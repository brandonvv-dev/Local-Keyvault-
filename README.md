# 🔐 SecureVault — Local Password Manager

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run directly
python vault.py

# 3. Or build as .exe (Windows)
build.bat
# Output: dist/SecureVault.exe
```

---

## Architecture & Security Design

### Encryption Stackter Password

### Why This Is Strong

| Layer                                | What It Does                                                  | Why It Matters                                                                                          |
| ------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **Argon2id**                   | Derives encryption key from password                          | Resists brute-force, GPU attacks, and side-channel attacks. Winner of the Password Hashing Competition. |
| **256-bit random salt**        | Unique per vault creation                                     | Prevents rainbow table and precomputation attacks.                                                      |
| **AES-256-GCM**                | Encrypts all vault data                                       | Military-grade authenticated encryption. Detects any tampering.                                         |
| **Unique nonce per operation** | 96-bit random nonce each time                                 | Ensures identical passwords produce different ciphertext.                                               |
| **Double encryption**          | Vault encrypted + each password encrypted individually inside | Even if vault structure is somehow exposed, passwords remain individually encrypted.                    |
| **Constant-time comparison**   | Master password verification                                  | Prevents timing side-channel attacks.                                                                   |
| **Atomic file writes**         | Write to temp → rename                                       | Prevents vault corruption from crashes or power loss.                                                   |

### Vault File Format

Stored at:

- **Windows**: `%LOCALAPPDATA%\SecureVault\vault.enc`
- **macOS**: `~/Library/Application Support/SecureVault/vault.enc`
- **Linux**: `~/.local/share/SecureVault/vault.enc`

```json
{
  "version": 1,
  "salt": "<base64 encoded 256-bit salt>",
  "master_verify": "<base64 PBKDF2 hash for login verification>",
  "entries_enc": "<base64 AES-256-GCM encrypted JSON blob>"
}
```

Inside the decrypted entries blob, each password is **individually encrypted again** with AES-256-GCM + a unique nonce.

### Password Generator

- Uses `secrets` module (cryptographically secure OS randomness)
- Guarantees at least one character from each selected category
- Fisher-Yates shuffle with secure randomness
- Configurable length (12–128), symbol inclusion, ambiguous char exclusion

---

## Features

- **Create vault** with a master password
- **Auto-generate** strong passwords (configurable)
- **Store** passwords linked to app/website name, username, URL, notes
- **Retrieve** passwords on demand
- **Delete** entries
- **Change master password** (re-encrypts everything)
- **Clipboard copy** (if pyperclip installed)
- **Cross-platform** (Windows, macOS, Linux)
- **Single .exe** build via PyInstaller

---

## Building the .exe

```bash
pip install pyinstaller
pyinstaller --onefile --name SecureVault --console vault.py
```

The resulting `dist/SecureVault.exe` is fully standalone — no Python installation needed on the target machine.

---

## Security Notes

1. **The master password is never stored** — only a verification hash derived with a separate salt.
2. **Key material is zeroed** on vault lock (best-effort in Python's managed memory).
3. **No network access** — everything is 100% local.
4. **Fallback KDFs**: If Argon2 is unavailable, falls back to Scrypt → PBKDF2-SHA256.
5. **The `cryptography` package is mandatory** — it provides the NIST-validated AES-GCM implementation.
