-- KeyVault organization vaults.
-- Secrets never reach the server in clear: each vault document is AES-256-GCM encrypted on the client with a random
-- vault key, and that key is stored once per member, sealed to the member's X25519 public key. Who may read or save a
-- vault is enforced here with row level security, not in the app.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- tables
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  public_key text not null,          -- base64 X25519 public key
  private_key_enc text not null,     -- base64 salt||nonce||ciphertext, decryptable only with the account password
  created_at timestamptz not null default now()
);

create table public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

create table public.org_members (
  org_id uuid not null references public.orgs (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member')),
  added_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table public.vaults (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  name text not null,
  blob text not null default '',     -- encrypted vault document produced by the client
  rev text not null default '',      -- changes on every save; a save is rejected when it moved underneath you
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null
);

create table public.vault_members (
  vault_id uuid not null references public.vaults (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role text not null check (role in ('owner', 'write', 'read')),
  wrapped_key text not null,         -- the vault key sealed to this member's public key
  added_by uuid references auth.users (id) on delete set null,
  added_at timestamptz not null default now(),
  primary key (vault_id, user_id)
);

-- Sign-ups are limited to company email domains.
create table public.allowed_domains (domain text primary key);
insert into public.allowed_domains (domain) values ('bcmtrac.co.za');

-- A row the weekly keep-alive job reads so the free project is never paused for inactivity.
create table public.heartbeat (id int primary key default 1 check (id = 1), pinged_at timestamptz not null default now());
insert into public.heartbeat default values;

-- ---------------------------------------------------------------- helpers (run as definer: no RLS recursion)
create or replace function public.org_role(p_org uuid) returns text
language sql stable security definer set search_path = public as $$
  select role from public.org_members where org_id = p_org and user_id = auth.uid();
$$;

create or replace function public.vault_role(p_vault uuid) returns text
language sql stable security definer set search_path = public as $$
  select role from public.vault_members where vault_id = p_vault and user_id = auth.uid();
$$;

create or replace function public.shares_org_with_me(p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.org_members a join public.org_members b on a.org_id = b.org_id
                 where a.user_id = auth.uid() and b.user_id = p_user);
$$;

create or replace function public.restrict_signup_domain() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.allowed_domains where domain = lower(split_part(new.email, '@', 2))) then
    raise exception 'Sign-ups are limited to company email addresses';
  end if;
  return new;
end $$;
create trigger restrict_signup_domain before insert on auth.users
  for each row execute function public.restrict_signup_domain();

-- ---------------------------------------------------------------- row level security
alter table public.profiles enable row level security;
alter table public.orgs enable row level security;
alter table public.org_members enable row level security;
alter table public.vaults enable row level security;
alter table public.vault_members enable row level security;
alter table public.allowed_domains enable row level security;
alter table public.heartbeat enable row level security;

-- profiles: yours, plus the people who share an organization with you
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.shares_org_with_me(id));
create policy profiles_insert on public.profiles for insert to authenticated with check (id = auth.uid());
create policy profiles_update on public.profiles for update to authenticated using (id = auth.uid());

-- orgs: members see them; creation goes through create_org()
create policy orgs_select on public.orgs for select to authenticated using (public.org_role(id) is not null);
create policy orgs_update on public.orgs for update to authenticated using (public.org_role(id) = 'owner');
create policy orgs_delete on public.orgs for delete to authenticated using (public.org_role(id) = 'owner');

-- org members: members see the roster; owners and admins manage it; anyone may leave
create policy org_members_select on public.org_members for select to authenticated using (public.org_role(org_id) is not null);
create policy org_members_insert on public.org_members for insert to authenticated with check (public.org_role(org_id) in ('owner', 'admin'));
create policy org_members_update on public.org_members for update to authenticated using (public.org_role(org_id) in ('owner', 'admin'));
create policy org_members_delete on public.org_members for delete to authenticated
  using (public.org_role(org_id) in ('owner', 'admin') or user_id = auth.uid());

-- vaults: only people the vault was shared with see it; owner and write may save; creation goes through create_vault()
create policy vaults_select on public.vaults for select to authenticated using (public.vault_role(id) is not null);
create policy vaults_update on public.vaults for update to authenticated using (public.vault_role(id) in ('owner', 'write'));
create policy vaults_delete on public.vaults for delete to authenticated using (public.vault_role(id) = 'owner');

-- vault members: you see your own row; the vault owner sees and manages everyone's; anyone may leave
create policy vault_members_select on public.vault_members for select to authenticated
  using (user_id = auth.uid() or public.vault_role(vault_id) = 'owner');
create policy vault_members_insert on public.vault_members for insert to authenticated with check (public.vault_role(vault_id) = 'owner');
create policy vault_members_update on public.vault_members for update to authenticated using (public.vault_role(vault_id) = 'owner');
create policy vault_members_delete on public.vault_members for delete to authenticated
  using (public.vault_role(vault_id) = 'owner' or user_id = auth.uid());

-- the keep-alive job reads this with the anon key
create policy heartbeat_select on public.heartbeat for select to anon, authenticated using (true);

-- ---------------------------------------------------------------- RPC
-- Look up a colleague by exact email so a vault key can be sealed to their public key.
create or replace function public.find_profile(p_email text) returns table (id uuid, email text, public_key text)
language sql stable security definer set search_path = public as $$
  select id, email, public_key from public.profiles where lower(email) = lower(p_email);
$$;

create or replace function public.create_org(p_name text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  insert into public.orgs (name, created_by) values (p_name, auth.uid()) returning id into v_id;
  insert into public.org_members (org_id, user_id, role) values (v_id, auth.uid(), 'owner');
  return v_id;
end $$;

create or replace function public.create_vault(p_org uuid, p_name text, p_blob text, p_rev text, p_wrapped_key text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if coalesce(public.org_role(p_org), '') not in ('owner', 'admin') then
    raise exception 'Only organization owners and admins can create vaults';
  end if;
  insert into public.vaults (org_id, name, blob, rev, updated_by) values (p_org, p_name, p_blob, p_rev, auth.uid()) returning id into v_id;
  insert into public.vault_members (vault_id, user_id, role, wrapped_key, added_by) values (v_id, auth.uid(), 'owner', p_wrapped_key, auth.uid());
  return v_id;
end $$;

-- Atomic conditional save: true when nobody saved since p_expected_rev, false when the caller must merge and retry.
create or replace function public.save_vault(p_vault uuid, p_expected_rev text, p_blob text, p_rev text) returns boolean
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if coalesce(public.vault_role(p_vault), '') not in ('owner', 'write') then raise exception 'read-only'; end if;
  update public.vaults set blob = p_blob, rev = p_rev, updated_at = now(), updated_by = auth.uid()
   where id = p_vault and rev = p_expected_rev;
  get diagnostics n = row_count;
  return n = 1;
end $$;

revoke execute on function public.find_profile(text), public.create_org(text),
  public.create_vault(uuid, text, text, text, text), public.save_vault(uuid, text, text, text) from public, anon;
grant execute on function public.find_profile(text), public.create_org(text),
  public.create_vault(uuid, text, text, text, text), public.save_vault(uuid, text, text, text) to authenticated;
