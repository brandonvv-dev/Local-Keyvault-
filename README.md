# SecureVault Keychain

A beautiful, secure, 100% local password manager with two-factor authentication.

**No internet connection required. Your passwords never leave your device.**

---

## Features

- **Apple-style GUI** - Clean, minimal, professional dark interface
- **Two-Factor Authentication** - Local TOTP 2FA (works with Google Authenticator, Authy, etc.)
- **Military-grade encryption** - AES-256-GCM with Argon2id key derivation
- **Cross-platform** - Windows, Linux, and macOS
- **Shareable** - Build as a single executable file to share with friends
- **Password generator** - Cryptographically secure random passwords
- **Clipboard integration** - One-click copy passwords
- **Zero network access** - 100% offline, no telemetry, no cloud

---

## Quick Start

### Option 1: Run directly with Python

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python keychain.py
```

### Option 2: Build as executable (shareable)

**Windows:**
```batch
build.bat
# Output: dist\SecureVault.exe
```

**Linux/macOS:**
```bash
chmod +x build.sh
./build.sh
# Output: dist/SecureVault (Linux) or dist/SecureVault.app (macOS)
```

---

## Screenshots

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│                        SecureVault                             │
│                   Unlock your vault                            │
│                                                                │
│   ┌──────────────────────────────────────────────────────┐    │
│   │  Master Password                                      │    │
│   │  ••••••••••••••••                          [Show]    │    │
│   └──────────────────────────────────────────────────────┘    │
│                                                                │
│   ┌──────────────────────────────────────────────────────┐    │
│   │  Authentication Code                                  │    │
│   │  ______                                               │    │
│   └──────────────────────────────────────────────────────┘    │
│                                                                │
│              ┌────────────────────────┐                       │
│              │        Unlock          │                       │
│              └────────────────────────┘                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Encryption Stack

```
Master Password
       │
       ▼
┌─────────────────────┐
│  Argon2id KDF        │  ← Memory-hard, GPU/ASIC resistant
│  Time: 3 iterations  │
│  Memory: 64 MB       │
│  Parallelism: 4      │
│  + 256-bit salt      │
└─────────┬───────────┘
          │
          ▼
   256-bit Master Key
          │
          ▼
┌─────────────────────┐
│  AES-256-GCM         │  ← Authenticated encryption
│  Unique 96-bit nonce │
│  per encryption op   │
└─────────────────────┘
```

### Two-Factor Authentication

- **TOTP (Time-based One-Time Password)** - RFC 6238 compliant
- **100% Local** - No internet required, codes generated on your device
- **Compatible with** - Google Authenticator, Authy, Microsoft Authenticator, 1Password, etc.
- **QR Code Setup** - Easy setup by scanning QR code during vault creation

### Security Features

| Layer | Protection |
|-------|-----------|
| **Argon2id** | Resists brute-force, GPU attacks, side-channel attacks |
| **256-bit salt** | Prevents rainbow table and precomputation attacks |
| **AES-256-GCM** | Military-grade authenticated encryption, detects tampering |
| **Unique nonces** | Same password = different ciphertext each time |
| **Double encryption** | Vault encrypted + each password encrypted individually |
| **TOTP 2FA** | Even with master password, attacker needs authenticator |
| **Constant-time compare** | Prevents timing side-channel attacks |
| **Atomic writes** | No vault corruption from crashes |
| **Memory zeroing** | Keys cleared from memory on lock |

---

## Vault Storage Location

Your encrypted vault is stored locally at:

| Platform | Location |
|----------|----------|
| Windows | `%LOCALAPPDATA%\SecureVault\vault.enc` |
| macOS | `~/Library/Application Support/SecureVault/vault.enc` |
| Linux | `~/.local/share/SecureVault/vault.enc` |

---

## Building for Distribution

### Windows (.exe)

```batch
build.bat
```

Creates `dist\SecureVault.exe` - a single file you can share.

### Linux

```bash
./build.sh
```

Creates `dist/SecureVault` - a single executable file.

### macOS (.app)

```bash
./build.sh
```

Creates `dist/SecureVault.app` - a macOS application bundle.

---

## First-Time Setup

1. **Launch the app**
2. **Create a master password** (minimum 8 characters, strong recommended)
3. **Enable 2FA** (highly recommended)
4. **Scan QR code** with your authenticator app
5. **Enter verification code** to confirm setup
6. **Done!** Start adding passwords

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography` | AES-256-GCM encryption |
| `argon2-cffi` | Argon2id key derivation |
| `customtkinter` | Modern Apple-style GUI |
| `pillow` | Image handling for QR codes |
| `pyotp` | TOTP 2FA generation |
| `qrcode` | QR code generation for 2FA setup |
| `pyperclip` | Clipboard support |
| `pyinstaller` | Build standalone executables |

---

## Platform Requirements

- **Python 3.10+** (for development/building only)
- **No Python needed** to run the built executable

### Linux Additional Requirements

Install tkinter if not present:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

---

## Security Notes

1. **Master password is never stored** - only a verification hash
2. **TOTP secret is encrypted** - stored with AES-256-GCM in the vault
3. **No network access** - the app makes zero network connections
4. **No telemetry** - nothing is tracked or sent anywhere
5. **Open source** - you can audit every line of code
6. **Memory protection** - keys zeroed on vault lock

---

## FAQ

**Q: What if I lose my master password?**
A: There is no recovery. Your vault is encrypted with your password. Keep a secure backup of your password.

**Q: What if I lose my 2FA device?**
A: During setup, save the secret key shown below the QR code. You can use it to restore access on a new device.

**Q: Is this really secure?**
A: Yes. We use the same encryption standards as banks and governments (AES-256-GCM, Argon2id). The code is open for audit.

**Q: Can I use this without 2FA?**
A: Yes, but we strongly recommend enabling 2FA for maximum security.

**Q: Does this send my passwords anywhere?**
A: No. Zero network connections. Everything is 100% local on your device.

---

## License

MIT License - Use freely, modify, share.
# Local-Keyvault-
