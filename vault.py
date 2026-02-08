"""
SecureVault - Password Manager
==============================
A local password vault that stores encrypted credentials.
Uses AES-256-GCM encryption derived from a master password via Argon2id.

Architecture:
- Master password → Argon2id KDF → 256-bit encryption key
- Each entry encrypted individually with AES-256-GCM + unique nonce
- Vault file stored in user's local app data directory
- Passwords auto-generated with cryptographically secure randomness
"""

import os
import sys
import json
import base64
import string
import secrets
import hashlib
import getpass
import shutil
from pathlib import Path
from datetime import datetime, timezone

# --- Crypto imports ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import argon2
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


# ============================================================
# CONFIGURATION
# ============================================================
APP_NAME = "SecureVault"
VAULT_FILENAME = "vault.enc"
SALT_LENGTH = 32
NONCE_LENGTH = 12  # 96-bit nonce for AES-GCM
KEY_LENGTH = 32    # 256-bit key
MASTER_HASH_ITERATIONS = 100_000

# Argon2id parameters (OWASP recommended minimums)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4

# Password generation defaults
DEFAULT_PASSWORD_LENGTH = 20
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


# ============================================================
# VAULT FILE LOCATION
# ============================================================
def get_vault_dir() -> Path:
    """Get the vault storage directory in local user app data."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    
    vault_dir = base / APP_NAME
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir


def get_vault_path() -> Path:
    return get_vault_dir() / VAULT_FILENAME


# ============================================================
# KEY DERIVATION
# ============================================================
def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from the master password.
    Uses Argon2id if available (preferred), falls back to Scrypt.
    """
    password_bytes = master_password.encode("utf-8")

    if HAS_ARGON2:
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,  # Argon2id
        )
        return key
    elif HAS_CRYPTOGRAPHY:
        # Fallback: Scrypt (still very strong)
        kdf = Scrypt(
            salt=salt,
            length=KEY_LENGTH,
            n=2**17,       # CPU/memory cost
            r=8,
            p=1,
            backend=default_backend(),
        )
        return kdf.derive(password_bytes)
    else:
        # Last resort: PBKDF2 via hashlib (always available)
        return hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            iterations=MASTER_HASH_ITERATIONS,
            dklen=KEY_LENGTH,
        )


# ============================================================
# ENCRYPTION / DECRYPTION (AES-256-GCM)
# ============================================================
def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM.
    Returns: nonce (12 bytes) + ciphertext+tag
    """
    if HAS_CRYPTOGRAPHY:
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    else:
        # Fallback: XOR + HMAC (not production-grade, but functional demo)
        # In real deployment, cryptography package MUST be installed.
        raise RuntimeError(
            "The 'cryptography' package is required for secure encryption.\n"
            "Install it with: pip install cryptography"
        )


def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM data.
    Input: nonce (12 bytes) + ciphertext+tag
    """
    if HAS_CRYPTOGRAPHY:
        nonce = encrypted[:NONCE_LENGTH]
        ciphertext = encrypted[NONCE_LENGTH:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    else:
        raise RuntimeError("The 'cryptography' package is required.")


# ============================================================
# MASTER PASSWORD VERIFICATION
# ============================================================
def create_master_verification(master_password: str, salt: bytes) -> str:
    """Create a verification hash so we can check the master password on login."""
    verification_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt + b"verification",
        iterations=MASTER_HASH_ITERATIONS,
    )
    return base64.b64encode(verification_key).decode("ascii")


def verify_master_password(master_password: str, salt: bytes, stored_hash: str) -> bool:
    """Check if the provided master password is correct."""
    candidate = create_master_verification(master_password, salt)
    # Constant-time comparison
    return secrets.compare_digest(candidate, stored_hash)


# ============================================================
# PASSWORD GENERATOR
# ============================================================
def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.
    Guarantees at least one character from each selected category.
    """
    length = max(MIN_PASSWORD_LENGTH, min(length, MAX_PASSWORD_LENGTH))

    # Build character pools
    pools = []
    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace("O", "").replace("I", "")
        pools.append(chars)
    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace("l", "").replace("o", "")
        pools.append(chars)
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace("0", "").replace("1", "")
        pools.append(chars)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{}|;:,.<>?")

    if not pools:
        pools.append(string.ascii_letters + string.digits)

    # Ensure at least one from each pool
    password_chars = [secrets.choice(pool) for pool in pools]

    # Fill remaining length from combined pool
    all_chars = "".join(pools)
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))

    # Secure shuffle
    secure_shuffle(password_chars)
    return "".join(password_chars)


def secure_shuffle(lst: list) -> None:
    """Fisher-Yates shuffle using cryptographic randomness."""
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        lst[i], lst[j] = lst[j], lst[i]


# ============================================================
# VAULT DATA STRUCTURE
# ============================================================
class Vault:
    """
    Manages the encrypted password vault.
    
    File format (JSON before encryption):
    {
        "version": 1,
        "salt": "<base64>",
        "master_verify": "<base64 hash>",
        "entries": {
            "<uuid>": {
                "app_name": "...",
                "username": "...",
                "password_enc": "<base64 encrypted>",
                "url": "...",
                "notes": "...",
                "created": "ISO8601",
                "modified": "ISO8601"
            }
        }
    }
    """

    def __init__(self):
        self.vault_path = get_vault_path()
        self.salt: bytes = b""
        self.master_key: bytes = b""
        self.master_verify: str = ""
        self.entries: dict = {}
        self.is_unlocked: bool = False

    def exists(self) -> bool:
        return self.vault_path.exists()

    def create_new(self, master_password: str) -> None:
        """Initialize a brand new vault with the given master password."""
        self.salt = os.urandom(SALT_LENGTH)
        self.master_key = derive_key(master_password, self.salt)
        self.master_verify = create_master_verification(master_password, self.salt)
        self.entries = {}
        self.is_unlocked = True
        self._save()
        print(f"\n  Vault created at: {self.vault_path}")

    def unlock(self, master_password: str) -> bool:
        """Unlock an existing vault with the master password."""
        raw = self.vault_path.read_bytes()
        
        # The outer envelope is JSON with salt + master_verify + encrypted payload
        envelope = json.loads(raw)
        
        self.salt = base64.b64decode(envelope["salt"])
        self.master_verify = envelope["master_verify"]

        if not verify_master_password(master_password, self.salt, self.master_verify):
            return False

        self.master_key = derive_key(master_password, self.salt)

        # Decrypt the entries payload
        encrypted_entries = base64.b64decode(envelope["entries_enc"])
        decrypted = decrypt_data(encrypted_entries, self.master_key)
        self.entries = json.loads(decrypted.decode("utf-8"))
        self.is_unlocked = True
        return True

    def _save(self) -> None:
        """Encrypt and save the vault to disk."""
        if not self.is_unlocked:
            raise RuntimeError("Vault is locked.")

        entries_json = json.dumps(self.entries).encode("utf-8")
        encrypted_entries = encrypt_data(entries_json, self.master_key)

        envelope = {
            "version": 1,
            "app": APP_NAME,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "master_verify": self.master_verify,
            "entries_enc": base64.b64encode(encrypted_entries).decode("ascii"),
        }

        # Atomic write: write to temp then rename
        tmp_path = self.vault_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(envelope, indent=2))
        shutil.move(str(tmp_path), str(self.vault_path))

    def add_entry(
        self,
        app_name: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
    ) -> str:
        """Add a new password entry. Returns the entry ID."""
        entry_id = secrets.token_hex(8)
        now = datetime.now(timezone.utc).isoformat()

        # Encrypt the password individually within the entry
        pw_encrypted = encrypt_data(password.encode("utf-8"), self.master_key)

        self.entries[entry_id] = {
            "app_name": app_name,
            "username": username,
            "password_enc": base64.b64encode(pw_encrypted).decode("ascii"),
            "url": url,
            "notes": notes,
            "created": now,
            "modified": now,
        }
        self._save()
        return entry_id

    def get_password(self, entry_id: str) -> str:
        """Decrypt and return a password for a given entry."""
        entry = self.entries[entry_id]
        encrypted = base64.b64decode(entry["password_enc"])
        return decrypt_data(encrypted, self.master_key).decode("utf-8")

    def list_entries(self) -> list:
        """Return a list of all entries (without decrypted passwords)."""
        result = []
        for eid, entry in self.entries.items():
            result.append({
                "id": eid,
                "app_name": entry["app_name"],
                "username": entry["username"],
                "url": entry.get("url", ""),
                "created": entry["created"],
                "modified": entry["modified"],
            })
        return sorted(result, key=lambda x: x["app_name"].lower())

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry by ID."""
        if entry_id in self.entries:
            del self.entries[entry_id]
            self._save()
            return True
        return False

    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """Update fields of an existing entry."""
        if entry_id not in self.entries:
            return False

        entry = self.entries[entry_id]

        if "password" in kwargs:
            pw_encrypted = encrypt_data(kwargs["password"].encode("utf-8"), self.master_key)
            entry["password_enc"] = base64.b64encode(pw_encrypted).decode("ascii")

        for field in ("app_name", "username", "url", "notes"):
            if field in kwargs:
                entry[field] = kwargs[field]

        entry["modified"] = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Re-encrypt the entire vault with a new master password."""
        if not verify_master_password(old_password, self.salt, self.master_verify):
            return False

        # Decrypt all passwords with old key
        decrypted_passwords = {}
        for eid, entry in self.entries.items():
            encrypted = base64.b64decode(entry["password_enc"])
            decrypted_passwords[eid] = decrypt_data(encrypted, self.master_key).decode("utf-8")

        # Generate new salt and key
        self.salt = os.urandom(SALT_LENGTH)
        self.master_key = derive_key(new_password, self.salt)
        self.master_verify = create_master_verification(new_password, self.salt)

        # Re-encrypt all passwords with new key
        for eid, pw in decrypted_passwords.items():
            pw_encrypted = encrypt_data(pw.encode("utf-8"), self.master_key)
            self.entries[eid]["password_enc"] = base64.b64encode(pw_encrypted).decode("ascii")

        self._save()
        return True

    def export_entries_plaintext(self) -> str:
        """Export all entries as plaintext JSON (for user backup). Handle with care."""
        exported = []
        for eid, entry in self.entries.items():
            encrypted = base64.b64decode(entry["password_enc"])
            pw = decrypt_data(encrypted, self.master_key).decode("utf-8")
            exported.append({
                "app_name": entry["app_name"],
                "username": entry["username"],
                "password": pw,
                "url": entry.get("url", ""),
                "notes": entry.get("notes", ""),
            })
        return json.dumps(exported, indent=2)


# ============================================================
# CLI INTERFACE
# ============================================================
def clear_screen():
    os.system("cls" if sys.platform == "win32" else "clear")


def print_banner():
    print("""
╔══════════════════════════════════════════╗
║           🔐  SecureVault  🔐            ║
║        Local Password Manager            ║
╚══════════════════════════════════════════╝
    """)


def get_master_password_input(prompt: str = "Master Password: ") -> str:
    """Get password input (hidden)."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def password_strength_check(password: str) -> tuple[str, int]:
    """Basic password strength indicator."""
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if len(password) >= 16: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1

    if score <= 2: return ("WEAK", score)
    elif score <= 4: return ("MODERATE", score)
    elif score <= 5: return ("STRONG", score)
    else: return ("VERY STRONG", score)


def setup_new_vault(vault: Vault) -> bool:
    """First-time vault setup flow."""
    print("  No vault found. Let's create one!\n")
    print("  Choose a strong master password.")
    print("  This is the ONLY password you need to remember.\n")

    while True:
        pw1 = get_master_password_input("  Create Master Password: ")
        if len(pw1) < 8:
            print("  ⚠  Password must be at least 8 characters.\n")
            continue

        strength, score = password_strength_check(pw1)
        print(f"  Strength: {strength} ({score}/7)")

        pw2 = get_master_password_input("  Confirm Master Password: ")
        if pw1 != pw2:
            print("  ⚠  Passwords don't match. Try again.\n")
            continue

        vault.create_new(pw1)
        print("  ✅ Vault created successfully!\n")
        return True


def login_vault(vault: Vault) -> bool:
    """Login flow for existing vault."""
    print("  Vault found. Please unlock it.\n")
    attempts = 0
    max_attempts = 5

    while attempts < max_attempts:
        pw = get_master_password_input("  Master Password: ")
        try:
            if vault.unlock(pw):
                print("  ✅ Vault unlocked!\n")
                return True
        except Exception as e:
            print(f"  ❌ Error: {e}\n")
            return False

        attempts += 1
        remaining = max_attempts - attempts
        if remaining > 0:
            print(f"  ❌ Wrong password. {remaining} attempts remaining.\n")
        else:
            print("  ❌ Too many failed attempts. Exiting.\n")
            return False

    return False


def menu_add_password(vault: Vault):
    """Add a new password entry."""
    print("\n  ── Add New Password ──\n")
    app_name = input("  Application/Website name: ").strip()
    if not app_name:
        print("  Cancelled.")
        return

    username = input("  Username/Email: ").strip()
    url = input("  URL (optional): ").strip()
    notes = input("  Notes (optional): ").strip()

    print("\n  Password options:")
    print("  [1] Auto-generate (recommended)")
    print("  [2] Enter manually")
    choice = input("  Choice (1/2): ").strip()

    if choice == "2":
        password = get_master_password_input("  Password: ")
        if not password:
            print("  Cancelled.")
            return
    else:
        # Auto-generate
        try:
            length = input(f"  Password length [{DEFAULT_PASSWORD_LENGTH}]: ").strip()
            length = int(length) if length else DEFAULT_PASSWORD_LENGTH
        except ValueError:
            length = DEFAULT_PASSWORD_LENGTH

        include_symbols = input("  Include symbols? (Y/n): ").strip().lower() != "n"
        password = generate_password(length=length, use_symbols=include_symbols)
        print(f"\n  Generated: {password}")

    entry_id = vault.add_entry(app_name, username, password, url, notes)
    print(f"\n  ✅ Saved! Entry ID: {entry_id}")


def menu_list_passwords(vault: Vault):
    """List all stored entries."""
    entries = vault.list_entries()
    if not entries:
        print("\n  No passwords stored yet.\n")
        return

    print(f"\n  ── Your Vault ({len(entries)} entries) ──\n")
    print(f"  {'#':<4} {'Application':<25} {'Username':<30} {'ID':<18}")
    print(f"  {'─'*4} {'─'*25} {'─'*30} {'─'*18}")

    for i, entry in enumerate(entries, 1):
        print(f"  {i:<4} {entry['app_name']:<25} {entry['username']:<30} {entry['id']:<18}")

    print()


def menu_get_password(vault: Vault):
    """Retrieve and display a password."""
    entries = vault.list_entries()
    if not entries:
        print("\n  No passwords stored.\n")
        return

    menu_list_passwords(vault)
    choice = input("  Enter # or ID to reveal password: ").strip()

    entry_id = None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            entry_id = entries[idx]["id"]
    except ValueError:
        entry_id = choice

    if entry_id and entry_id in {e["id"] for e in entries}:
        password = vault.get_password(entry_id)
        entry = next(e for e in entries if e["id"] == entry_id)
        print(f"\n  App:      {entry['app_name']}")
        print(f"  User:     {entry['username']}")
        print(f"  Password: {password}")
        print(f"  URL:      {entry.get('url', 'N/A')}")

        # Copy to clipboard if pyperclip available
        try:
            import pyperclip
            pyperclip.copy(password)
            print("  📋 Password copied to clipboard!")
        except ImportError:
            pass

        print()
    else:
        print("  ❌ Entry not found.\n")


def menu_delete_password(vault: Vault):
    """Delete a password entry."""
    entries = vault.list_entries()
    if not entries:
        print("\n  No passwords stored.\n")
        return

    menu_list_passwords(vault)
    choice = input("  Enter # or ID to delete: ").strip()

    entry_id = None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            entry_id = entries[idx]["id"]
    except ValueError:
        entry_id = choice

    if entry_id:
        confirm = input(f"  Are you sure you want to delete '{entry_id}'? (yes/no): ").strip().lower()
        if confirm == "yes":
            if vault.delete_entry(entry_id):
                print("  ✅ Deleted.\n")
            else:
                print("  ❌ Entry not found.\n")
    else:
        print("  Cancelled.\n")


def menu_generate_password(vault: Vault):
    """Just generate a password without saving."""
    print("\n  ── Password Generator ──\n")
    try:
        length = input(f"  Length [{DEFAULT_PASSWORD_LENGTH}]: ").strip()
        length = int(length) if length else DEFAULT_PASSWORD_LENGTH
    except ValueError:
        length = DEFAULT_PASSWORD_LENGTH

    include_symbols = input("  Include symbols? (Y/n): ").strip().lower() != "n"
    exclude_ambiguous = input("  Exclude ambiguous chars (0/O/l/1)? (y/N): ").strip().lower() == "y"

    password = generate_password(
        length=length,
        use_symbols=include_symbols,
        exclude_ambiguous=exclude_ambiguous,
    )
    strength, score = password_strength_check(password)

    print(f"\n  Generated: {password}")
    print(f"  Strength:  {strength} ({score}/7)")
    print(f"  Length:     {len(password)} chars\n")

    save = input("  Save to vault? (y/N): ").strip().lower()
    if save == "y":
        app_name = input("  Application name: ").strip()
        username = input("  Username: ").strip()
        if app_name:
            vault.add_entry(app_name, username, password)
            print("  ✅ Saved!\n")


def menu_change_master(vault: Vault):
    """Change the master password."""
    print("\n  ── Change Master Password ──\n")
    old_pw = get_master_password_input("  Current Master Password: ")
    new_pw = get_master_password_input("  New Master Password: ")
    confirm = get_master_password_input("  Confirm New Password: ")

    if new_pw != confirm:
        print("  ❌ Passwords don't match.\n")
        return

    if len(new_pw) < 8:
        print("  ❌ Password must be at least 8 characters.\n")
        return

    if vault.change_master_password(old_pw, new_pw):
        print("  ✅ Master password changed!\n")
    else:
        print("  ❌ Current password is incorrect.\n")


def main():
    """Main application entry point."""
    # Check dependencies
    if not HAS_CRYPTOGRAPHY:
        print("\n  ⚠  WARNING: 'cryptography' package not found.")
        print("  Install it: pip install cryptography")
        print("  The vault requires this for AES-256-GCM encryption.\n")
        sys.exit(1)

    clear_screen()
    print_banner()

    kdf_name = "Argon2id" if HAS_ARGON2 else "Scrypt"
    print(f"  Encryption: AES-256-GCM | KDF: {kdf_name}")
    print(f"  Vault location: {get_vault_path()}\n")

    vault = Vault()

    # Setup or login
    if not vault.exists():
        if not setup_new_vault(vault):
            return
    else:
        if not login_vault(vault):
            return

    # Main menu loop
    while True:
        print("  ┌─────────────────────────────┐")
        print("  │       VAULT MENU             │")
        print("  ├─────────────────────────────┤")
        print("  │  [1] Add new password        │")
        print("  │  [2] List all entries         │")
        print("  │  [3] Get/reveal password      │")
        print("  │  [4] Delete entry             │")
        print("  │  [5] Generate password        │")
        print("  │  [6] Change master password   │")
        print("  │  [7] Lock & Exit              │")
        print("  └─────────────────────────────┘")

        choice = input("\n  Choice: ").strip()

        if choice == "1":
            menu_add_password(vault)
        elif choice == "2":
            menu_list_passwords(vault)
        elif choice == "3":
            menu_get_password(vault)
        elif choice == "4":
            menu_delete_password(vault)
        elif choice == "5":
            menu_generate_password(vault)
        elif choice == "6":
            menu_change_master(vault)
        elif choice == "7":
            # Zero out key from memory (best effort in Python)
            vault.master_key = b"\x00" * KEY_LENGTH
            vault.is_unlocked = False
            print("\n  🔒 Vault locked. Goodbye!\n")
            break
        else:
            print("  Invalid choice.\n")


if __name__ == "__main__":
    main()
