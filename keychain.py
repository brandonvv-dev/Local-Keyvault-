"""
SecureVault - System Architect Credential Manager
==================================================
Secure local credential manager for system architects and DevOps engineers.
Designed for servers, databases, API keys, cloud accounts, and network devices.

Features:
- AES-256-GCM encryption with Argon2id KDF
- Local TOTP 2FA (no internet required)
- System tray with global hotkey (Shift+V+P chord)
- Server/environment focused organization
- Quick access for terminal and remote sessions
- Secure PDF export for team credential sharing

Performance optimizations:
- Lazy loading of heavy modules (PDF)
- Cached vault paths and computations
- Efficient UI batch updates
"""

import os
import sys
import json
import base64
import secrets
import hashlib
import shutil
import time
import threading
import queue
import tempfile
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple

# Core GUI imports
import customtkinter as ctk
from PIL import Image, ImageDraw
import pyperclip
import pystray
from pystray import MenuItem as TrayItem
import keyboard
import pyautogui
import qrcode

# Crypto imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

try:
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import pyotp

# PDF modules loaded lazily on first use for faster startup
HAS_PDF = None  # None = not checked yet, True/False after check
_pdf_modules = {}

def _load_pdf_modules():
    """Lazy load PDF modules only when needed."""
    global HAS_PDF, _pdf_modules
    if HAS_PDF is not None:
        return HAS_PDF
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from PyPDF2 import PdfReader, PdfWriter
        _pdf_modules = {
            'letter': letter, 'getSampleStyleSheet': getSampleStyleSheet,
            'ParagraphStyle': ParagraphStyle, 'inch': inch, 'HexColor': HexColor,
            'SimpleDocTemplate': SimpleDocTemplate, 'Paragraph': Paragraph,
            'Spacer': Spacer, 'Table': Table, 'TableStyle': TableStyle,
            'TA_CENTER': TA_CENTER, 'TA_LEFT': TA_LEFT,
            'PdfReader': PdfReader, 'PdfWriter': PdfWriter
        }
        HAS_PDF = True
    except ImportError:
        HAS_PDF = False
    return HAS_PDF

# ============================================================
# CONFIGURATION
# ============================================================
APP_NAME = "SecureVault"
APP_VERSION = "3.1.0"  # Performance optimized
VAULT_FILENAME = "vault.enc"
STATS_FILENAME = "stats.enc"
SALT_LENGTH = 32
NONCE_LENGTH = 12
KEY_LENGTH = 32
MASTER_HASH_ITERATIONS = 100_000
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
DEFAULT_PASSWORD_LENGTH = 24
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Hotkey chord: Shift+V then P (no key suppression to avoid interference)
HOTKEY_CHORD = ["shift+v", "p"]
CHORD_TIMEOUT = 1.0  # seconds to complete the chord

# System Architecture credential types (no entertainment/personal categories)
CREDENTIAL_TYPES = [
    "Server (SSH/RDP)",
    "Database Server",
    "Cloud Console (AWS/GCP/Azure)",
    "API Key / Token",
    "Service Account",
    "Network Device (Router/Switch/Firewall)",
    "Container Registry / K8s",
    "SSL Certificate / Key",
    "Web Admin Panel",
    "Git Repository",
    "CI/CD Pipeline",
    "Monitoring / Logging",
    "DNS / Domain Registrar",
    "Email Server (SMTP/IMAP)",
    "VPN / Remote Access",
    "Other Infrastructure",
]

ENVIRONMENTS = ["Production", "Staging", "Development", "QA", "DR", "Local", "Shared"]

PROTOCOLS = ["SSH", "RDP", "HTTPS", "HTTP", "MySQL", "PostgreSQL", "MongoDB", "Redis",
             "MSSQL", "FTP/SFTP", "API", "Console", "LDAP", "SMTP", "Docker", "K8s API", "Other"]

# Dark terminal theme
COLORS = {
    "bg_primary": "#0D1117",
    "bg_secondary": "#161B22",
    "bg_tertiary": "#21262D",
    "bg_popup": "#1C2128",
    "accent": "#58A6FF",
    "accent_hover": "#79B8FF",
    "success": "#3FB950",
    "warning": "#D29922",
    "danger": "#F85149",
    "text_primary": "#E6EDF3",
    "text_secondary": "#8B949E",
    "text_tertiary": "#6E7681",
    "border": "#30363D",
    "prod": "#F85149",
    "staging": "#D29922",
    "dev": "#3FB950",
}

# ============================================================
# PATHS (cached for performance)
# ============================================================
@lru_cache(maxsize=1)
def get_vault_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    vault_dir = base / APP_NAME
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir

@lru_cache(maxsize=1)
def get_vault_path() -> Path:
    return get_vault_dir() / VAULT_FILENAME

@lru_cache(maxsize=1)
def get_stats_path() -> Path:
    return get_vault_dir() / STATS_FILENAME

# ============================================================
# CRYPTO
# ============================================================
def derive_key(master_password: str, salt: bytes) -> bytes:
    pw = master_password.encode("utf-8")
    if HAS_ARGON2:
        return hash_secret_raw(secret=pw, salt=salt, time_cost=ARGON2_TIME_COST,
                               memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM,
                               hash_len=KEY_LENGTH, type=Type.ID)
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=2**17, r=8, p=1, backend=default_backend())
    return kdf.derive(pw)

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LENGTH)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(encrypted[:NONCE_LENGTH], encrypted[NONCE_LENGTH:], None)

def create_master_verification(master_password: str, salt: bytes) -> str:
    key = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt + b"verify", MASTER_HASH_ITERATIONS)
    return base64.b64encode(key).decode("ascii")

def verify_master_password(master_password: str, salt: bytes, stored: str) -> bool:
    return secrets.compare_digest(create_master_verification(master_password, salt), stored)

# ============================================================
# PASSWORD GENERATOR
# ============================================================
def generate_password(length: int = DEFAULT_PASSWORD_LENGTH, use_upper: bool = True,
                      use_lower: bool = True, use_digits: bool = True, use_symbols: bool = True) -> str:
    length = max(MIN_PASSWORD_LENGTH, min(length, MAX_PASSWORD_LENGTH))
    pools = []
    if use_upper: pools.append("ABCDEFGHJKLMNPQRSTUVWXYZ")
    if use_lower: pools.append("abcdefghjkmnpqrstuvwxyz")
    if use_digits: pools.append("23456789")
    if use_symbols: pools.append("!@#$%^&*-_=+")
    if not pools: pools.append("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789")
    chars = [secrets.choice(p) for p in pools]
    all_chars = "".join(pools)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)

def password_strength(pw: str) -> tuple:
    score = sum([len(pw) >= 8, len(pw) >= 12, len(pw) >= 16, len(pw) >= 24,
                 any(c.isupper() for c in pw), any(c.islower() for c in pw),
                 any(c.isdigit() for c in pw), any(c in "!@#$%^&*-_=+" for c in pw)]) * 12
    if score <= 30: return ("Weak", score, COLORS["danger"])
    if score <= 60: return ("Fair", score, COLORS["warning"])
    if score <= 80: return ("Strong", score, COLORS["accent"])
    return ("Excellent", score, COLORS["success"])

# ============================================================
# PDF EXPORT (Password Protected - Lazy Loaded)
# ============================================================
def export_credentials_to_pdf(entries: List[dict], vault, pdf_password: str, output_path: str,
                               export_title: str = "Infrastructure Credentials") -> bool:
    """
    Export selected credentials to a password-protected PDF.
    For sharing with junior developers securely.
    """
    if not _load_pdf_modules():
        raise RuntimeError("PDF export requires 'reportlab' and 'PyPDF2' packages.\n"
                          "Install with: pip install reportlab PyPDF2")

    # Get lazy-loaded modules
    letter = _pdf_modules['letter']
    inch = _pdf_modules['inch']
    getSampleStyleSheet = _pdf_modules['getSampleStyleSheet']
    ParagraphStyle = _pdf_modules['ParagraphStyle']
    HexColor = _pdf_modules['HexColor']
    SimpleDocTemplate = _pdf_modules['SimpleDocTemplate']
    Paragraph = _pdf_modules['Paragraph']
    Spacer = _pdf_modules['Spacer']
    Table = _pdf_modules['Table']
    TableStyle = _pdf_modules['TableStyle']
    TA_CENTER = _pdf_modules['TA_CENTER']
    PdfReader = _pdf_modules['PdfReader']
    PdfWriter = _pdf_modules['PdfWriter']

    # Create temporary unencrypted PDF first
    temp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    temp_pdf.close()

    try:
        # Create the PDF document
        doc = SimpleDocTemplate(temp_pdf.name, pagesize=letter,
                               topMargin=0.75*inch, bottomMargin=0.75*inch,
                               leftMargin=0.75*inch, rightMargin=0.75*inch)

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=20,
            textColor=HexColor('#1a1a2e'),
            alignment=TA_CENTER
        )

        warning_style = ParagraphStyle(
            'Warning',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#dc3545'),
            alignment=TA_CENTER,
            spaceAfter=20
        )

        section_style = ParagraphStyle(
            'Section',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#2d3748'),
            spaceBefore=15,
            spaceAfter=10
        )

        story = []

        # Title
        story.append(Paragraph(export_title, title_style))

        # Security warning
        story.append(Paragraph(
            "CONFIDENTIAL - Handle with care. Delete after use.",
            warning_style
        ))

        # Export metadata
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        meta_data = [
            ['Generated:', now],
            ['Total Credentials:', str(len(entries))],
            ['Classification:', 'INTERNAL USE ONLY']
        ]
        meta_table = Table(meta_data, colWidths=[1.5*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))

        # Separator line
        story.append(Paragraph("_" * 80, styles['Normal']))
        story.append(Spacer(1, 10))

        # Each credential
        for i, entry in enumerate(entries, 1):
            # Get the password
            pw = vault.get_password(entry["id"], track=False) if entry.get("id") else ""

            # Credential header
            env = entry.get("environment", "")
            env_label = f" [{env}]" if env else ""
            story.append(Paragraph(
                f"{i}. {entry['name']}{env_label}",
                section_style
            ))

            # Build credential table
            cred_data = []

            if entry.get("type"):
                cred_data.append(['Type:', entry["type"]])

            host_info = entry.get("host", "")
            if entry.get("port"):
                host_info += f":{entry['port']}"
            if host_info:
                cred_data.append(['Host:', host_info])

            if entry.get("protocol"):
                cred_data.append(['Protocol:', entry["protocol"]])

            if entry.get("username"):
                cred_data.append(['Username:', entry["username"]])

            if pw:
                cred_data.append(['Password:', pw])

            if entry.get("tags"):
                cred_data.append(['Tags:', entry["tags"]])

            if entry.get("notes"):
                # Truncate long notes
                notes = entry["notes"][:200] + "..." if len(entry.get("notes", "")) > 200 else entry.get("notes", "")
                cred_data.append(['Notes:', notes])

            if cred_data:
                cred_table = Table(cred_data, colWidths=[1.2*inch, 5.3*inch])
                cred_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica'),
                    ('FONTNAME', (1, 0), (1, -1), 'Courier'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
                    ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#1a1a2e')),
                    ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
                    ('BOX', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
                ]))
                story.append(cred_table)

            story.append(Spacer(1, 15))

        # Footer
        story.append(Spacer(1, 20))
        story.append(Paragraph("_" * 80, styles['Normal']))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=HexColor('#999999'),
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            f"Generated by SecureVault v{APP_VERSION} | This document is password protected",
            footer_style
        ))

        # Build the PDF
        doc.build(story)

        # Now encrypt with password
        reader = PdfReader(temp_pdf.name)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # Encrypt with AES-256
        writer.encrypt(pdf_password, pdf_password, algorithm="AES-256")

        # Write encrypted PDF
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)

        return True

    finally:
        # Clean up temp file
        try:
            os.unlink(temp_pdf.name)
        except:
            pass

# ============================================================
# USAGE STATS (optimized with __slots__)
# ============================================================
class UsageStats:
    __slots__ = ('stats', 'key', '_dirty', '_save_timer')

    def __init__(self):
        self.stats: Dict[str, dict] = {}
        self.key: bytes = b""
        self._dirty = False
        self._save_timer = None

    def set_key(self, key: bytes):
        self.key = key
        self._load()

    def _load(self):
        path = get_stats_path()
        if path.exists() and self.key:
            try:
                self.stats = json.loads(decrypt_data(path.read_bytes(), self.key).decode("utf-8"))
            except: self.stats = {}

    def _save(self):
        if self.key:
            get_stats_path().write_bytes(encrypt_data(json.dumps(self.stats).encode("utf-8"), self.key))
        self._dirty = False

    def _deferred_save(self):
        """Batch saves to reduce disk I/O."""
        if self._dirty:
            self._save()

    def record(self, eid: str):
        if eid not in self.stats: self.stats[eid] = {"count": 0, "last": ""}
        self.stats[eid]["count"] += 1
        self.stats[eid]["last"] = datetime.now(timezone.utc).isoformat()
        self._dirty = True
        # Immediate save for data safety
        self._save()

    def top(self, n: int = 8) -> List[str]:
        # Optimized sorting - avoid lambda overhead
        items = [(k, v["count"]) for k, v in self.stats.items()]
        items.sort(key=lambda x: x[1], reverse=True)
        return [k for k, _ in items[:n]]

    def count(self, eid: str) -> int:
        entry = self.stats.get(eid)
        return entry["count"] if entry else 0

# ============================================================
# VAULT (optimized with caching)
# ============================================================
class Vault:
    __slots__ = ('path', 'salt', 'key', 'verify_hash', 'totp_secret', 'totp_enabled',
                 'entries', 'unlocked', 'stats', '_list_cache', '_list_cache_valid')

    def __init__(self):
        self.path = get_vault_path()
        self.salt = b""
        self.key = b""
        self.verify_hash = ""
        self.totp_secret = ""
        self.totp_enabled = False
        self.entries = {}
        self.unlocked = False
        self.stats = UsageStats()
        self._list_cache = []
        self._list_cache_valid = False

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, password: str, enable_2fa: bool = True) -> str:
        self.salt = os.urandom(SALT_LENGTH)
        self.key = derive_key(password, self.salt)
        self.verify_hash = create_master_verification(password, self.salt)
        self.entries = {}
        self.unlocked = True
        self.stats.set_key(self.key)
        self.totp_secret = pyotp.random_base32() if enable_2fa else ""
        self.totp_enabled = enable_2fa
        self._save()
        return self.totp_secret

    def unlock(self, password: str) -> bool:
        try:
            data = json.loads(self.path.read_bytes())
            self.salt = base64.b64decode(data["salt"])
            self.verify_hash = data["master_verify"]
            if not verify_master_password(password, self.salt, self.verify_hash):
                return False
            self.key = derive_key(password, self.salt)
            self.entries = json.loads(decrypt_data(base64.b64decode(data["entries_enc"]), self.key).decode("utf-8"))
            if data.get("totp_enc"):
                self.totp_secret = decrypt_data(base64.b64decode(data["totp_enc"]), self.key).decode("utf-8")
                self.totp_enabled = True
            else:
                self.totp_enabled = data.get("totp_enabled", False)
            self.unlocked = True
            self._invalidate_cache()
            self.stats.set_key(self.key)
            return True
        except: return False

    def verify_totp(self, code: str) -> bool:
        if not self.totp_enabled: return True
        return pyotp.TOTP(self.totp_secret).verify(code, valid_window=1)

    def totp_uri(self) -> str:
        return pyotp.TOTP(self.totp_secret).provisioning_uri("SysAdmin", APP_NAME) if self.totp_secret else ""

    def has_totp(self) -> bool:
        if not self.path.exists(): return False
        try:
            data = json.loads(self.path.read_bytes())
            return bool(data.get("totp_enc") or data.get("totp_enabled"))
        except: return False

    def _save(self):
        enc = encrypt_data(json.dumps(self.entries).encode("utf-8"), self.key)
        data = {"version": 3, "app": APP_NAME, "salt": base64.b64encode(self.salt).decode(),
                "master_verify": self.verify_hash, "entries_enc": base64.b64encode(enc).decode(),
                "totp_enabled": self.totp_enabled}
        if self.totp_secret:
            data["totp_enc"] = base64.b64encode(encrypt_data(self.totp_secret.encode("utf-8"), self.key)).decode()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        shutil.move(str(tmp), str(self.path))

    def add(self, name: str, ctype: str, host: str = "", port: str = "", user: str = "",
            password: str = "", env: str = "", proto: str = "", tags: str = "", notes: str = "") -> str:
        eid = secrets.token_hex(8)
        now = datetime.now(timezone.utc).isoformat()
        self.entries[eid] = {"name": name, "type": ctype, "host": host, "port": port, "username": user,
                             "password_enc": base64.b64encode(encrypt_data(password.encode("utf-8"), self.key)).decode(),
                             "environment": env, "protocol": proto, "tags": tags, "notes": notes,
                             "created": now, "modified": now}
        self._invalidate_cache()
        self._save()
        return eid

    def get_password(self, eid: str, track: bool = True) -> str:
        if track: self.stats.record(eid)
        return decrypt_data(base64.b64decode(self.entries[eid]["password_enc"]), self.key).decode("utf-8")

    def _invalidate_cache(self):
        self._list_cache_valid = False

    def list_all(self) -> list:
        if self._list_cache_valid:
            return self._list_cache
        fields = ["name", "type", "host", "port", "username", "environment", "protocol", "tags", "notes", "created", "modified"]
        result = []
        for k, v in self.entries.items():
            entry = {"id": k, "use_count": self.stats.count(k)}
            for f in fields:
                entry[f] = v.get(f, "")
            result.append(entry)
        result.sort(key=lambda x: x["name"].lower())
        self._list_cache = result
        self._list_cache_valid = True
        return result

    def top_used(self, n: int = 8) -> list:
        return [{"id": k, **{f: self.entries[k].get(f, "") for f in ["name", "type", "host", "port", "username", "environment", "protocol"]},
                 "use_count": self.stats.count(k)} for k in self.stats.top(n) if k in self.entries]

    def by_env(self, env: str) -> list:
        return [e for e in self.list_all() if e["environment"] == env]

    def delete(self, eid: str):
        if eid in self.entries:
            del self.entries[eid]
            self._invalidate_cache()
            self._save()

    def update(self, eid: str, **kw):
        if eid not in self.entries: return
        e = self.entries[eid]
        if "password" in kw:
            e["password_enc"] = base64.b64encode(encrypt_data(kw.pop("password").encode("utf-8"), self.key)).decode()
        for f in ["name", "type", "host", "port", "username", "environment", "protocol", "tags", "notes"]:
            if f in kw: e[f] = kw[f]
        e["modified"] = datetime.now(timezone.utc).isoformat()
        self._invalidate_cache()
        self._save()

    def lock(self):
        self.key = b"\x00" * KEY_LENGTH
        self.entries = {}
        self.unlocked = False

# ============================================================
# STARTUP
# ============================================================
def add_startup():
    if sys.platform != "win32": return
    try:
        import winreg
        path = f'"{sys.executable}" --minimized' if getattr(sys, 'frozen', False) else f'pythonw "{os.path.abspath(__file__)}" --minimized'
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, path)
        winreg.CloseKey(key)
    except: pass

def remove_startup():
    if sys.platform != "win32": return
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
    except: pass

def in_startup() -> bool:
    if sys.platform != "win32": return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except: return False

# ============================================================
# HOTKEY CHORD HANDLER (Shift+V+P without interference)
# ============================================================
class ChordHotkeyHandler:
    """
    Handles Shift+V+P chord hotkey without interfering with normal typing.
    Uses a state machine approach instead of key suppression.
    """
    def __init__(self, callback: Callable):
        self.callback = callback
        self.chord_state = 0  # 0=waiting, 1=shift+v pressed, 2=chord complete
        self.last_chord_time = 0
        self.active = False
        self._lock = threading.Lock()

    def start(self):
        """Start listening for the chord hotkey."""
        if self.active:
            return
        self.active = True
        # Register handlers WITHOUT suppression to avoid interference
        keyboard.on_press(self._on_key_press, suppress=False)
        keyboard.on_release(self._on_key_release, suppress=False)

    def stop(self):
        """Stop listening."""
        self.active = False
        try:
            keyboard.unhook_all()
        except:
            pass

    def _on_key_press(self, event):
        """Handle key press events for chord detection."""
        if not self.active:
            return

        current_time = time.time()

        with self._lock:
            # Check for timeout - reset if too long since last chord key
            if self.chord_state > 0 and (current_time - self.last_chord_time) > CHORD_TIMEOUT:
                self.chord_state = 0

            key_name = event.name.lower() if event.name else ""

            # State 0: Waiting for Shift+V
            if self.chord_state == 0:
                if key_name == 'v' and keyboard.is_pressed('shift'):
                    self.chord_state = 1
                    self.last_chord_time = current_time

            # State 1: Shift+V was pressed, waiting for P
            elif self.chord_state == 1:
                if key_name == 'p':
                    self.chord_state = 0  # Reset state
                    # Trigger callback in separate thread to not block
                    threading.Thread(target=self.callback, daemon=True).start()
                elif key_name not in ('shift', 'v', 'p'):
                    # Wrong key pressed, reset
                    self.chord_state = 0

    def _on_key_release(self, event):
        """Handle key release - reset chord if shift released early."""
        if not self.active:
            return
        key_name = event.name.lower() if event.name else ""
        # If shift is released before completing chord, reset
        if key_name == 'shift' and self.chord_state == 1:
            with self._lock:
                self.chord_state = 0

# ============================================================
# QUICK ACCESS POPUP
# ============================================================
class QuickPopup(ctk.CTkToplevel):
    def __init__(self, vault: Vault, on_close: Callable):
        super().__init__()
        self.vault = vault
        self.on_close = on_close
        self.sel = 0
        self.items = []

        self.title("Quick Access")
        self.geometry("520x420")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.update_idletasks()
        self.geometry(f"520x420+{(self.winfo_screenwidth()-520)//2}+{(self.winfo_screenheight()-420)//2-80}")
        self.configure(fg_color=COLORS["bg_popup"])

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent", height=40)
        hdr.pack(fill="x", padx=14, pady=(14, 6))
        ctk.CTkLabel(hdr, text="Quick Access", font=ctk.CTkFont(size=15, weight="bold"), text_color=COLORS["text_primary"]).pack(side="left")
        ctk.CTkLabel(hdr, text="Shift+V, P", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"],
                    fg_color=COLORS["bg_tertiary"], corner_radius=4, width=70, height=22).pack(side="right")

        # Search
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh())
        self.search = ctk.CTkEntry(self, textvariable=self.search_var, height=38, corner_radius=6,
                                   border_width=1, border_color=COLORS["accent"], fg_color=COLORS["bg_tertiary"],
                                   text_color=COLORS["text_primary"], placeholder_text="Search... (Enter=copy, Shift+Enter=type)",
                                   font=ctk.CTkFont(size=13))
        self.search.pack(fill="x", padx=14, pady=(0, 10))
        self.search.focus_set()

        # Filters
        flt = ctk.CTkFrame(self, fg_color="transparent")
        flt.pack(fill="x", padx=14, pady=(0, 8))
        self.filter = "recent"
        for txt, val in [("Recent", "recent"), ("Prod", "Production"), ("Staging", "Staging"), ("Dev", "Development"), ("All", "all")]:
            b = ctk.CTkButton(flt, text=txt, width=60, height=26, corner_radius=5,
                             fg_color=COLORS["accent"] if val == "recent" else COLORS["bg_tertiary"],
                             hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=10),
                             command=lambda v=val: self._set_filter(v))
            b.pack(side="left", padx=(0, 4))
            setattr(self, f"fb_{val}", b)

        # List
        self.lst = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.lst.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Bindings
        self.bind("<Escape>", lambda _: self._close())
        self.bind("<Return>", lambda _: self._copy())
        self.bind("<Shift-Return>", lambda _: self._type())
        self.bind("<Up>", lambda _: self._move(-1))
        self.bind("<Down>", lambda _: self._move(1))
        self.search.bind("<Up>", lambda _: self._move(-1))
        self.search.bind("<Down>", lambda _: self._move(1))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()

    def _set_filter(self, f: str):
        self.filter = f
        for txt, val in [("Recent", "recent"), ("Prod", "Production"), ("Staging", "Staging"), ("Dev", "Development"), ("All", "all")]:
            getattr(self, f"fb_{val}").configure(fg_color=COLORS["accent"] if val == f else COLORS["bg_tertiary"])
        self.sel = 0
        self._refresh()

    def _refresh(self):
        for w in self.lst.winfo_children(): w.destroy()
        q = self.search_var.get().lower()
        if self.filter == "recent" and not q:
            self.items = self.vault.top_used(10)
        elif self.filter == "all" or q:
            self.items = self.vault.list_all()
        else:
            self.items = self.vault.by_env(self.filter)
        if q:
            self.items = [e for e in self.items if q in e["name"].lower() or q in e.get("host", "").lower() or
                         q in e.get("username", "").lower() or q in e.get("tags", "").lower()]
        if not self.items:
            ctk.CTkLabel(self.lst, text="No credentials found", font=ctk.CTkFont(size=12), text_color=COLORS["text_tertiary"]).pack(pady=25)
            return
        for i, e in enumerate(self.items):
            self._card(e, i)

    def _card(self, e: dict, i: int):
        sel = i == self.sel
        fr = ctk.CTkFrame(self.lst, fg_color=COLORS["accent"] if sel else COLORS["bg_secondary"], corner_radius=6, height=54)
        fr.pack(fill="x", pady=2)
        fr.pack_propagate(False)
        fr.bind("<Button-1>", lambda _, idx=i: self._sel_copy(idx))

        env = e.get("environment", "")
        ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["border"]
        ctk.CTkFrame(fr, width=4, fg_color=ec, corner_radius=0).pack(side="left", fill="y")

        cnt = ctk.CTkFrame(fr, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=10, pady=6)
        cnt.bind("<Button-1>", lambda _, idx=i: self._sel_copy(idx))

        ctk.CTkLabel(cnt, text=e["name"], font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        info = " @ ".join(filter(None, [e.get("username"), (e.get("host", "") + (f":{e['port']}" if e.get("port") else ""))]))
        ctk.CTkLabel(cnt, text=info or e.get("type", ""), font=ctk.CTkFont(size=10, family="Consolas"),
                    text_color=COLORS["text_primary"] if sel else COLORS["text_secondary"], anchor="w").pack(fill="x")

        btns = ctk.CTkFrame(fr, fg_color="transparent")
        btns.pack(side="right", padx=6)
        ctk.CTkButton(btns, text="Copy", width=42, height=24, corner_radius=4, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=10), command=lambda idx=i: self._sel_copy(idx)).pack(side="left", padx=2)
        ctk.CTkButton(btns, text="Type", width=42, height=24, corner_radius=4, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=10), command=lambda idx=i: self._sel_type(idx)).pack(side="left", padx=2)

    def _move(self, d: int):
        if self.items:
            self.sel = max(0, min(len(self.items) - 1, self.sel + d))
            self._refresh()

    def _sel_copy(self, i: int):
        self.sel = i
        self._copy()

    def _sel_type(self, i: int):
        self.sel = i
        self._type()

    def _copy(self):
        if self.items:
            pyperclip.copy(self.vault.get_password(self.items[self.sel]["id"]))
            self.title("Copied!")
            self.after(350, self._close)

    def _type(self):
        if self.items:
            pw = self.vault.get_password(self.items[self.sel]["id"])
            self._close()
            time.sleep(0.25)
            pyautogui.typewrite(pw, interval=0.02)

    def _close(self):
        self.on_close()
        self.destroy()

# ============================================================
# WIDGETS
# ============================================================
class Entry(ctk.CTkEntry):
    def __init__(self, master, placeholder="", **kw):
        super().__init__(master, height=38, corner_radius=6, border_width=1, border_color=COLORS["border"],
                        fg_color=COLORS["bg_tertiary"], text_color=COLORS["text_primary"],
                        placeholder_text=placeholder, placeholder_text_color=COLORS["text_tertiary"],
                        font=ctk.CTkFont(size=12), **kw)

class Btn(ctk.CTkButton):
    def __init__(self, master, text="", primary=True, danger=False, **kw):
        c = COLORS["danger"] if danger else COLORS["accent"] if primary else COLORS["bg_tertiary"]
        h = "#FF6961" if danger else COLORS["accent_hover"] if primary else COLORS["border"]
        super().__init__(master, text=text, height=38, corner_radius=6, fg_color=c, hover_color=h,
                        text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), **kw)

class PwEntry(ctk.CTkFrame):
    def __init__(self, master, placeholder="Password / Secret", **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.show = False
        self.e = Entry(self, placeholder=placeholder, show="*")
        self.e.pack(side="left", fill="x", expand=True)
        self.b = ctk.CTkButton(self, text="Show", width=50, height=38, corner_radius=6, fg_color=COLORS["bg_tertiary"],
                              hover_color=COLORS["border"], font=ctk.CTkFont(size=10), command=self._toggle)
        self.b.pack(side="right", padx=(5, 0))

    def _toggle(self):
        self.show = not self.show
        self.e.configure(show="" if self.show else "*")
        self.b.configure(text="Hide" if self.show else "Show")

    def get(self): return self.e.get()
    def delete(self, a, b): self.e.delete(a, b)
    def insert(self, i, t): self.e.insert(i, t)

class Card(ctk.CTkFrame):
    def __init__(self, master, data: dict, on_click: Callable, on_copy: Callable, selectable: bool = False,
                 selected: bool = False, on_select: Callable = None, **kw):
        super().__init__(master, fg_color=COLORS["bg_secondary"], corner_radius=8, height=80, **kw)
        self.data = data
        self.selectable = selectable
        self.selected = selected
        self.on_select = on_select

        self.bind("<Button-1>", lambda _: on_click(data))

        env = data.get("environment", "")
        ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["border"]
        ctk.CTkFrame(self, width=4, fg_color=ec, corner_radius=0).pack(side="left", fill="y")

        # Selection checkbox for export
        if selectable:
            self.chk_var = ctk.BooleanVar(value=selected)
            chk = ctk.CTkCheckBox(self, text="", variable=self.chk_var, width=24,
                                  fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                  command=lambda: on_select(data["id"], self.chk_var.get()) if on_select else None)
            chk.pack(side="left", padx=(8, 0))

        cnt = ctk.CTkFrame(self, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=12, pady=10)
        cnt.bind("<Button-1>", lambda _: on_click(data))

        top = ctk.CTkFrame(cnt, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top, text=data["name"], font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(side="left")
        ctk.CTkLabel(top, text=data.get("type", ""), font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"],
                    fg_color=COLORS["bg_tertiary"], corner_radius=3, width=90, height=18).pack(side="right")

        info = " @ ".join(filter(None, [data.get("username"), (data.get("host", "") + (f":{data['port']}" if data.get("port") else ""))]))
        if info:
            ctk.CTkLabel(cnt, text=info, font=ctk.CTkFont(size=11, family="Consolas"), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(2, 0))

        bot = ctk.CTkFrame(cnt, fg_color="transparent")
        bot.pack(fill="x", pady=(6, 0))
        if env:
            ctk.CTkLabel(bot, text=env, font=ctk.CTkFont(size=10, weight="bold"), text_color=ec, anchor="w").pack(side="left")
        ctk.CTkButton(bot, text="Copy Password", width=100, height=26, corner_radius=5, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=10), command=lambda: on_copy(data)).pack(side="right")

# ============================================================
# EXPORT DIALOG
# ============================================================
class ExportDialog(ctk.CTkToplevel):
    def __init__(self, master, vault: Vault, selected_ids: Set[str]):
        super().__init__(master)
        self.vault = vault
        self.selected_ids = selected_ids
        self.result = None

        self.title("Export Credentials to PDF")
        self.geometry("450x350")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self.configure(fg_color=COLORS["bg_primary"])

        # Center on parent
        self.update_idletasks()
        x = master.winfo_x() + (master.winfo_width() - 450) // 2
        y = master.winfo_y() + (master.winfo_height() - 350) // 2
        self.geometry(f"450x350+{x}+{y}")

        # Content
        ctk.CTkLabel(self, text="Export for Team Member", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(pady=(20, 5))
        ctk.CTkLabel(self, text=f"Exporting {len(selected_ids)} credential(s) to password-protected PDF",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        form = ctk.CTkFrame(self, fg_color="transparent")
        form.pack(fill="x", padx=30)

        # Export title
        ctk.CTkLabel(form, text="Document Title", font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.title_entry = Entry(form, placeholder="e.g., Dev Server Credentials for John")
        self.title_entry.pack(fill="x", pady=(0, 12))
        self.title_entry.insert(0, f"Infrastructure Credentials - {datetime.now().strftime('%Y-%m-%d')}")

        # PDF Password
        ctk.CTkLabel(form, text="PDF Password (share this with recipient separately)",
                    font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.pw_entry = PwEntry(form, placeholder="Strong password for the PDF")
        self.pw_entry.pack(fill="x", pady=(0, 8))

        # Generate password button
        ctk.CTkButton(form, text="Generate Strong Password", height=28, corner_radius=5,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     font=ctk.CTkFont(size=10), command=self._gen_password).pack(anchor="w", pady=(0, 12))

        # Confirm password
        ctk.CTkLabel(form, text="Confirm Password", font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.pw_confirm = PwEntry(form, placeholder="Confirm password")
        self.pw_confirm.pack(fill="x", pady=(0, 15))

        # Error label
        self.err_label = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=10), text_color=COLORS["danger"])
        self.err_label.pack(fill="x", pady=(0, 10))

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30, pady=(0, 20))

        Btn(btn_frame, text="Cancel", primary=False, width=100, command=self.destroy).pack(side="left")
        Btn(btn_frame, text="Export PDF", width=150, command=self._do_export).pack(side="right")

    def _gen_password(self):
        pw = generate_password(16, True, True, True, True)
        self.pw_entry.delete(0, "end")
        self.pw_entry.insert(0, pw)
        self.pw_confirm.delete(0, "end")
        self.pw_confirm.insert(0, pw)
        # Show the password temporarily
        self.pw_entry.show = True
        self.pw_entry.e.configure(show="")
        self.pw_entry.b.configure(text="Hide")
        pyperclip.copy(pw)
        self.err_label.configure(text="Password generated and copied to clipboard!", text_color=COLORS["success"])

    def _do_export(self):
        title = self.title_entry.get().strip()
        password = self.pw_entry.get()
        confirm = self.pw_confirm.get()

        if not title:
            self.err_label.configure(text="Please enter a document title", text_color=COLORS["danger"])
            return
        if not password:
            self.err_label.configure(text="Please enter a password for the PDF", text_color=COLORS["danger"])
            return
        if len(password) < 8:
            self.err_label.configure(text="Password must be at least 8 characters", text_color=COLORS["danger"])
            return
        if password != confirm:
            self.err_label.configure(text="Passwords do not match", text_color=COLORS["danger"])
            return

        if not HAS_PDF:
            self.err_label.configure(text="PDF export requires reportlab and PyPDF2 packages", text_color=COLORS["danger"])
            return

        # Get selected entries
        entries = [e for e in self.vault.list_all() if e["id"] in self.selected_ids]

        # Ask for save location
        from tkinter import filedialog
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
        default_name = f"{safe_title}.pdf"

        filepath = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=default_name,
            title="Save Encrypted PDF"
        )

        if not filepath:
            return

        try:
            export_credentials_to_pdf(entries, self.vault, password, filepath, title)
            self.result = filepath
            self.destroy()
        except Exception as e:
            self.err_label.configure(text=f"Export failed: {str(e)}", text_color=COLORS["danger"])

# ============================================================
# APP
# ============================================================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} - System Architect Credentials")
        self.geometry("980x680")
        self.minsize(880, 620)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=COLORS["bg_primary"])

        self.vault = Vault()
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_list())
        self.tray = None
        self.popup = None
        self.queue = queue.Queue()
        self.hotkey_handler = None
        self.start_min = False
        self.export_mode = False
        self.selected_for_export: Set[str] = set()

        self._check_queue()
        self._show_login() if self.vault.exists() else self._show_setup()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _check_queue(self):
        try:
            while True:
                if self.queue.get_nowait() == "popup": self._open_popup()
        except queue.Empty: pass
        self.after(100, self._check_queue)

    def _setup_tray(self):
        if self.tray: return
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([16, 28, 48, 56], radius=4, fill="#58A6FF")
        d.arc([20, 12, 44, 36], 0, 180, fill="#58A6FF", width=6)

        menu = pystray.Menu(
            TrayItem("Open", self._tray_open, default=True),
            TrayItem("Quick Access", self._tray_popup),
            pystray.Menu.SEPARATOR,
            TrayItem("Start with Windows", self._toggle_startup, checked=lambda _: in_startup()),
            pystray.Menu.SEPARATOR,
            TrayItem("Lock", self._tray_lock),
            TrayItem("Quit", self._tray_quit))
        self.tray = pystray.Icon(APP_NAME, img, f"{APP_NAME}\nShift+V, P", menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

    def _setup_hotkey(self):
        """Setup the Shift+V+P chord hotkey without key suppression."""
        if self.hotkey_handler:
            return
        try:
            self.hotkey_handler = ChordHotkeyHandler(
                lambda: self.queue.put("popup") if self.vault.unlocked else None
            )
            self.hotkey_handler.start()
        except Exception as e:
            print(f"Hotkey setup failed: {e}")

    def _open_popup(self):
        if not self.vault.unlocked: return
        if self.popup and self.popup.winfo_exists():
            self.popup.focus_set()
            return
        self.popup = QuickPopup(self.vault, lambda: setattr(self, "popup", None))

    def _tray_open(self, *_): self.after(0, lambda: (self.deiconify(), self.lift(), self.focus_force()))
    def _tray_popup(self, *_): self.queue.put("popup")
    def _toggle_startup(self, *_): remove_startup() if in_startup() else add_startup()
    def _tray_lock(self, *_): self.after(0, self._lock)
    def _tray_quit(self, *_):
        if self.tray: self.tray.stop()
        if self.hotkey_handler: self.hotkey_handler.stop()
        self.quit()

    def _on_close(self):
        if self.vault.unlocked and self.tray: self.withdraw()
        else: self._tray_quit()

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    # ===== SETUP =====
    def _show_setup(self):
        self._clear()
        c = ctk.CTkFrame(self, fg_color="transparent")
        c.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(c, text="SecureVault", font=ctk.CTkFont(size=32, weight="bold"), text_color=COLORS["text_primary"]).pack(pady=(0, 4))
        ctk.CTkLabel(c, text="System Architect Credential Manager", font=ctk.CTkFont(size=12), text_color=COLORS["text_secondary"]).pack(pady=(0, 32))

        f = ctk.CTkFrame(c, fg_color="transparent", width=360)
        f.pack()

        ctk.CTkLabel(f, text="Master Password", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.s_pw = PwEntry(f)
        self.s_pw.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(f, text="Confirm Password", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.s_conf = PwEntry(f)
        self.s_conf.pack(fill="x", pady=(0, 14))

        self.s_2fa = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f, text="Enable 2FA", variable=self.s_2fa, font=ctk.CTkFont(size=11),
                       text_color=COLORS["text_secondary"], fg_color=COLORS["accent"]).pack(fill="x", pady=(0, 16))

        self.s_err = ctk.CTkLabel(f, text="", font=ctk.CTkFont(size=11), text_color=COLORS["danger"])
        self.s_err.pack(fill="x", pady=(0, 6))

        Btn(f, text="Create Vault", width=360, command=self._do_setup).pack(fill="x")
        self.bind("<Return>", lambda _: self._do_setup())

    def _do_setup(self):
        pw, conf = self.s_pw.get(), self.s_conf.get()
        if len(pw) < 8: self.s_err.configure(text="Min 8 characters"); return
        if pw != conf: self.s_err.configure(text="Passwords don't match"); return
        secret = self.vault.create(pw, self.s_2fa.get())
        if self.s_2fa.get(): self._show_2fa(secret)
        else: self._finish_login()

    def _show_2fa(self, secret: str):
        self._clear()
        c = ctk.CTkFrame(self, fg_color="transparent")
        c.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(c, text="Two-Factor Setup", font=ctk.CTkFont(size=22, weight="bold"), text_color=COLORS["text_primary"]).pack(pady=(0, 6))
        ctk.CTkLabel(c, text="Scan with authenticator app", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        qr = qrcode.QRCode(version=1, box_size=5, border=2)
        qr.add_data(self.vault.totp_uri())
        qr.make(fit=True)
        img = qr.make_image(fill_color="white", back_color=COLORS["bg_primary"])
        buf = BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        ctk.CTkLabel(c, image=ctk.CTkImage(Image.open(buf), size=(160, 160)), text="").pack(pady=(0, 12))

        sf = ctk.CTkFrame(c, fg_color=COLORS["bg_secondary"], corner_radius=6)
        sf.pack(pady=(0, 18))
        ctk.CTkLabel(sf, text=secret, font=ctk.CTkFont(size=10, family="Consolas"), text_color=COLORS["text_secondary"]).pack(padx=12, pady=6)

        ctk.CTkLabel(c, text="Enter code to verify:", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 4))
        self.v_code = Entry(c, width=120)
        self.v_code.pack(pady=(0, 4))

        self.v_err = ctk.CTkLabel(c, text="", font=ctk.CTkFont(size=11), text_color=COLORS["danger"])
        self.v_err.pack(pady=(0, 10))

        Btn(c, text="Verify", width=160, command=self._verify_2fa).pack()
        self.bind("<Return>", lambda _: self._verify_2fa())

    def _verify_2fa(self):
        if self.vault.verify_totp(self.v_code.get().strip()): self._finish_login()
        else: self.v_err.configure(text="Invalid code")

    # ===== LOGIN =====
    def _show_login(self):
        self._clear()
        c = ctk.CTkFrame(self, fg_color="transparent")
        c.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(c, text="SecureVault", font=ctk.CTkFont(size=32, weight="bold"), text_color=COLORS["text_primary"]).pack(pady=(0, 4))
        ctk.CTkLabel(c, text="Unlock your vault", font=ctk.CTkFont(size=12), text_color=COLORS["text_secondary"]).pack(pady=(0, 32))

        f = ctk.CTkFrame(c, fg_color="transparent", width=360)
        f.pack()

        ctk.CTkLabel(f, text="Master Password", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.l_pw = PwEntry(f)
        self.l_pw.pack(fill="x", pady=(0, 10))

        self.need_2fa = self.vault.has_totp()
        if self.need_2fa:
            ctk.CTkLabel(f, text="2FA Code", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
            self.l_code = Entry(f)
            self.l_code.pack(fill="x", pady=(0, 10))

        self.l_err = ctk.CTkLabel(f, text="", font=ctk.CTkFont(size=11), text_color=COLORS["danger"])
        self.l_err.pack(fill="x", pady=(0, 6))

        Btn(f, text="Unlock", width=360, command=self._do_login).pack(fill="x")
        self.bind("<Return>", lambda _: self._do_login())

    def _do_login(self):
        if not self.vault.unlock(self.l_pw.get()): self.l_err.configure(text="Wrong password"); return
        if self.need_2fa and not self.vault.verify_totp(self.l_code.get().strip()):
            self.vault.lock()
            self.l_err.configure(text="Invalid 2FA code")
            return
        self._finish_login()

    def _finish_login(self):
        self._setup_tray()
        self._setup_hotkey()
        self._show_main()
        if self.start_min: self.after(100, self.withdraw)

    # ===== MAIN =====
    def _show_main(self):
        self._clear()
        self.unbind("<Return>")

        # Sidebar
        sb = ctk.CTkFrame(self, width=220, fg_color=COLORS["bg_secondary"], corner_radius=0)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        hdr = ctk.CTkFrame(sb, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=14)
        ctk.CTkLabel(hdr, text="SecureVault", font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["text_primary"]).pack(anchor="w")
        ctk.CTkLabel(hdr, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(anchor="w")

        hk = ctk.CTkFrame(sb, fg_color=COLORS["bg_tertiary"], corner_radius=5)
        hk.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(hk, text="Shift+V, P anywhere", font=ctk.CTkFont(size=9), text_color=COLORS["accent"]).pack(pady=5)

        nav = ctk.CTkFrame(sb, fg_color="transparent")
        nav.pack(fill="x", padx=8, pady=4)
        for txt, cmd in [("All Credentials", self._view_all), ("Recent", self._view_recent),
                         ("By Environment", self._view_env), ("Export to PDF", self._view_export),
                         ("Generate Password", self._view_gen), ("Settings", self._view_settings)]:
            ctk.CTkButton(nav, text=txt, height=32, corner_radius=6, fg_color="transparent", hover_color=COLORS["bg_tertiary"],
                         text_color=COLORS["text_primary"], anchor="w", font=ctk.CTkFont(size=12), command=cmd).pack(fill="x", pady=1)

        ctk.CTkFrame(sb, fg_color="transparent").pack(fill="both", expand=True)

        bot = ctk.CTkFrame(sb, fg_color="transparent")
        bot.pack(fill="x", padx=8, pady=14)
        ctk.CTkButton(bot, text="Minimize to Tray", height=32, corner_radius=6, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=11), command=self.withdraw).pack(fill="x", pady=(0, 5))
        ctk.CTkButton(bot, text="Lock", height=32, corner_radius=6, fg_color=COLORS["danger"],
                     hover_color="#FF6961", font=ctk.CTkFont(size=11), command=self._lock).pack(fill="x")

        self.content = ctk.CTkFrame(self, fg_color=COLORS["bg_primary"], corner_radius=0)
        self.content.pack(side="right", fill="both", expand=True)
        self._view_all()

    def _lock(self):
        self.vault.lock()
        self._show_login()

    # ===== VIEWS =====
    def _view_all(self):
        self.export_mode = False
        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkLabel(hdr, text="All Credentials", font=ctk.CTkFont(size=20, weight="bold"), text_color=COLORS["text_primary"]).pack(side="left")
        Btn(hdr, text="+ Add", width=100, command=self._view_add).pack(side="right")

        flt = ctk.CTkFrame(self.content, fg_color="transparent")
        flt.pack(fill="x", padx=20, pady=(0, 12))
        self.search = Entry(flt, placeholder="Search...", textvariable=self.search_var, width=340)
        self.search.pack(side="left")
        self.env_flt = ctk.CTkComboBox(flt, values=["All"] + ENVIRONMENTS, width=120, height=38, corner_radius=6,
                                       border_width=1, border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11), command=lambda _: self._refresh_list())
        self.env_flt.set("All")
        self.env_flt.pack(side="left", padx=(8, 0))

        self.lst = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        self.lst.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._refresh_list()

    def _refresh_list(self):
        if not hasattr(self, "lst"): return
        for w in self.lst.winfo_children(): w.destroy()
        items = self.vault.list_all()
        q = self.search_var.get().lower()
        env = self.env_flt.get() if hasattr(self, "env_flt") else "All"
        if q:
            items = [e for e in items if q in e["name"].lower() or q in e.get("host", "").lower() or
                    q in e.get("username", "").lower() or q in e.get("tags", "").lower()]
        if env != "All":
            items = [e for e in items if e.get("environment") == env]
        if not items:
            ctk.CTkLabel(self.lst, text="No credentials", font=ctk.CTkFont(size=12), text_color=COLORS["text_tertiary"]).pack(pady=30)
            return
        for e in items:
            if self.export_mode:
                Card(self.lst, e, self._view_detail, self._quick_copy,
                     selectable=True, selected=e["id"] in self.selected_for_export,
                     on_select=self._toggle_export_selection).pack(fill="x", pady=2)
            else:
                Card(self.lst, e, self._view_detail, self._quick_copy).pack(fill="x", pady=2)

    def _toggle_export_selection(self, eid: str, selected: bool):
        if selected:
            self.selected_for_export.add(eid)
        else:
            self.selected_for_export.discard(eid)
        # Update export button text
        if hasattr(self, 'export_btn'):
            self.export_btn.configure(text=f"Export {len(self.selected_for_export)} Selected")

    def _quick_copy(self, e: dict):
        pyperclip.copy(self.vault.get_password(e["id"]))

    def _view_recent(self):
        self.export_mode = False
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="Recently Used", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 14))
        lst = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        lst.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        items = self.vault.top_used(12)
        if not items:
            ctk.CTkLabel(lst, text="No usage data yet", font=ctk.CTkFont(size=12), text_color=COLORS["text_tertiary"]).pack(pady=30)
            return
        for e in items:
            Card(lst, e, self._view_detail, self._quick_copy).pack(fill="x", pady=2)

    def _view_env(self):
        self.export_mode = False
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="By Environment", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 14))
        lst = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        lst.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        for env in ENVIRONMENTS:
            items = self.vault.by_env(env)
            if not items: continue
            ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["text_secondary"]
            ctk.CTkLabel(lst, text=f"{env} ({len(items)})", font=ctk.CTkFont(size=13, weight="bold"), text_color=ec).pack(anchor="w", pady=(12, 6))
            for e in items:
                Card(lst, e, self._view_detail, self._quick_copy).pack(fill="x", pady=2)

    def _view_export(self):
        """Export view - select credentials to export to PDF for junior devs."""
        self.export_mode = True
        self.selected_for_export.clear()

        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkLabel(hdr, text="Export to PDF", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(side="left")

        self.export_btn = Btn(hdr, text="Export 0 Selected", width=150, command=self._do_export)
        self.export_btn.pack(side="right")
        Btn(hdr, text="Cancel", primary=False, width=80, command=self._view_all).pack(side="right", padx=(0, 10))

        # Instructions
        ctk.CTkLabel(self.content, text="Select credentials to export as password-protected PDF for team members",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(0, 12))

        # Filter
        flt = ctk.CTkFrame(self.content, fg_color="transparent")
        flt.pack(fill="x", padx=20, pady=(0, 12))
        self.search = Entry(flt, placeholder="Search...", textvariable=self.search_var, width=340)
        self.search.pack(side="left")
        self.env_flt = ctk.CTkComboBox(flt, values=["All"] + ENVIRONMENTS, width=120, height=38, corner_radius=6,
                                       border_width=1, border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11), command=lambda _: self._refresh_list())
        self.env_flt.set("All")
        self.env_flt.pack(side="left", padx=(8, 0))

        # Select all button
        Btn(flt, text="Select All", primary=False, width=80, command=self._select_all_for_export).pack(side="right")

        self.lst = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        self.lst.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._refresh_list()

    def _select_all_for_export(self):
        items = self.vault.list_all()
        q = self.search_var.get().lower()
        env = self.env_flt.get() if hasattr(self, "env_flt") else "All"
        if q:
            items = [e for e in items if q in e["name"].lower() or q in e.get("host", "").lower()]
        if env != "All":
            items = [e for e in items if e.get("environment") == env]
        self.selected_for_export = {e["id"] for e in items}
        self._refresh_list()
        if hasattr(self, 'export_btn'):
            self.export_btn.configure(text=f"Export {len(self.selected_for_export)} Selected")

    def _do_export(self):
        if not self.selected_for_export:
            return
        if not _load_pdf_modules():
            # Show error dialog
            dialog = ctk.CTkToplevel(self)
            dialog.title("Missing Dependencies")
            dialog.geometry("400x150")
            dialog.transient(self)
            dialog.grab_set()
            dialog.configure(fg_color=COLORS["bg_primary"])
            ctk.CTkLabel(dialog, text="PDF Export requires additional packages.\n\nPlease run:\npip install reportlab PyPDF2",
                        font=ctk.CTkFont(size=12), text_color=COLORS["text_primary"]).pack(pady=30)
            Btn(dialog, text="OK", width=80, command=dialog.destroy).pack()
            return

        dialog = ExportDialog(self, self.vault, self.selected_for_export)
        self.wait_window(dialog)
        if dialog.result:
            # Show success message
            success_dialog = ctk.CTkToplevel(self)
            success_dialog.title("Export Complete")
            success_dialog.geometry("400x180")
            success_dialog.transient(self)
            success_dialog.grab_set()
            success_dialog.configure(fg_color=COLORS["bg_primary"])

            ctk.CTkLabel(success_dialog, text="PDF Exported Successfully!",
                        font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["success"]).pack(pady=(20, 10))
            ctk.CTkLabel(success_dialog, text=f"Saved to:\n{dialog.result}",
                        font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 10))
            ctk.CTkLabel(success_dialog, text="Share the PDF password with the recipient securely!",
                        font=ctk.CTkFont(size=10), text_color=COLORS["warning"]).pack(pady=(0, 15))
            Btn(success_dialog, text="OK", width=80, command=success_dialog.destroy).pack()

    def _view_detail(self, e: dict):
        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkButton(hdr, text="< Back", width=60, height=28, corner_radius=5, fg_color="transparent",
                     hover_color=COLORS["bg_tertiary"], text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=11), command=self._view_all).pack(side="left")
        Btn(hdr, text="Delete", danger=True, width=70, command=lambda: (self.vault.delete(e["id"]), self._view_all())).pack(side="right")
        Btn(hdr, text="Edit", primary=False, width=60, command=lambda: self._view_edit(e)).pack(side="right", padx=6)

        cnt = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        ctk.CTkLabel(cnt, text=e["name"], font=ctk.CTkFont(size=22, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x", pady=(0, 16))

        pw = self.vault.get_password(e["id"])
        fields = [("Type", e.get("type")), ("Host", e.get("host")), ("Port", e.get("port")),
                  ("Username", e.get("username"), True), ("Password", pw, True, True),
                  ("Environment", e.get("environment")), ("Protocol", e.get("protocol")),
                  ("Tags", e.get("tags")), ("Notes", e.get("notes"))]
        for item in fields:
            val = item[1]
            if not val: continue
            copy = len(item) > 2 and item[2]
            hide = len(item) > 3 and item[3]
            self._field(cnt, item[0], val, copy, hide)

        if e.get("use_count"):
            ctk.CTkLabel(cnt, text=f"Used {e['use_count']} times", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(anchor="w", pady=(14, 0))

    def _field(self, parent, label: str, val: str, copy: bool = False, hide: bool = False):
        fr = ctk.CTkFrame(parent, fg_color="transparent")
        fr.pack(fill="x", pady=5)
        ctk.CTkLabel(fr, text=label, font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"], anchor="w").pack(fill="x")
        row = ctk.CTkFrame(fr, fg_color="transparent")
        row.pack(fill="x")

        disp = "*" * 14 if hide else val
        var = ctk.StringVar(value=disp)
        ctk.CTkLabel(row, textvariable=var, font=ctk.CTkFont(size=13, family="Consolas" if hide or label in ["Host", "Port"] else None),
                    text_color=COLORS["text_primary"], anchor="w").pack(side="left")

        if hide:
            show = [False]
            def toggle():
                show[0] = not show[0]
                var.set(val if show[0] else "*" * 14)
                tb.configure(text="Hide" if show[0] else "Show")
            tb = ctk.CTkButton(row, text="Show", width=44, height=24, corner_radius=4, fg_color=COLORS["bg_tertiary"],
                              hover_color=COLORS["border"], font=ctk.CTkFont(size=9), command=toggle)
            tb.pack(side="left", padx=5)

        if copy:
            def do_copy():
                pyperclip.copy(val)
                cb.configure(text="Copied!")
                self.after(1000, lambda: cb.configure(text="Copy"))
            cb = ctk.CTkButton(row, text="Copy", width=44, height=24, corner_radius=4, fg_color=COLORS["accent"],
                              hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=9), command=do_copy)
            cb.pack(side="left", padx=2)

    # ===== ADD =====
    def _view_add(self):
        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkButton(hdr, text="< Cancel", width=70, height=28, corner_radius=5, fg_color="transparent",
                     hover_color=COLORS["bg_tertiary"], text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=11), command=self._view_all).pack(side="left")
        ctk.CTkLabel(hdr, text="Add Credential", font=ctk.CTkFont(size=18, weight="bold"), text_color=COLORS["text_primary"]).pack(side="left", padx=14)

        frm = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        frm.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self._input(frm, "Name / Label", "a_name", "Production DB, AWS Root, etc.")

        ctk.CTkLabel(frm, text="Type", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        self.a_type = ctk.CTkComboBox(frm, values=CREDENTIAL_TYPES, height=38, corner_radius=6, border_width=1,
                                      border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                      dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.a_type.pack(fill="x")
        self.a_type.set(CREDENTIAL_TYPES[0])

        row = ctk.CTkFrame(frm, fg_color="transparent")
        row.pack(fill="x", pady=(10, 0))
        hf = ctk.CTkFrame(row, fg_color="transparent")
        hf.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(hf, text="Host / IP", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.a_host = Entry(hf, placeholder="192.168.1.1 or hostname")
        self.a_host.pack(fill="x")
        pf = ctk.CTkFrame(row, fg_color="transparent", width=90)
        pf.pack(side="right", padx=(8, 0))
        pf.pack_propagate(False)
        ctk.CTkLabel(pf, text="Port", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.a_port = Entry(pf, placeholder="22")
        self.a_port.pack(fill="x")

        self._input(frm, "Username / Access Key", "a_user", "root, admin, AKIA...")

        ctk.CTkLabel(frm, text="Password / Secret", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        prow = ctk.CTkFrame(frm, fg_color="transparent")
        prow.pack(fill="x")
        self.a_pw = PwEntry(prow)
        self.a_pw.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(prow, text="Generate", width=75, height=38, corner_radius=6, fg_color=COLORS["accent"],
                     hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=10),
                     command=lambda: (self.a_pw.delete(0, "end"), self.a_pw.insert(0, generate_password()))).pack(side="right", padx=(5, 0))

        row2 = ctk.CTkFrame(frm, fg_color="transparent")
        row2.pack(fill="x", pady=(10, 0))
        ef = ctk.CTkFrame(row2, fg_color="transparent")
        ef.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(ef, text="Environment", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.a_env = ctk.CTkComboBox(ef, values=ENVIRONMENTS, height=38, corner_radius=6, border_width=1,
                                     border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                     dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.a_env.pack(fill="x")
        self.a_env.set("Development")
        prf = ctk.CTkFrame(row2, fg_color="transparent")
        prf.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(prf, text="Protocol", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.a_proto = ctk.CTkComboBox(prf, values=PROTOCOLS, height=38, corner_radius=6, border_width=1,
                                       border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.a_proto.pack(fill="x")
        self.a_proto.set("SSH")

        self._input(frm, "Tags (comma separated)", "a_tags", "linux, mysql, us-east, team-backend")

        ctk.CTkLabel(frm, text="Notes", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        self.a_notes = ctk.CTkTextbox(frm, height=60, corner_radius=6, border_width=1, border_color=COLORS["border"],
                                      fg_color=COLORS["bg_tertiary"], text_color=COLORS["text_primary"], font=ctk.CTkFont(size=11))
        self.a_notes.pack(fill="x")

        self.a_err = ctk.CTkLabel(frm, text="", font=ctk.CTkFont(size=10), text_color=COLORS["danger"])
        self.a_err.pack(fill="x", pady=(10, 0))

        Btn(frm, text="Save", command=self._do_add).pack(fill="x", pady=(10, 20))

    def _input(self, parent, label: str, attr: str, placeholder: str):
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        e = Entry(parent, placeholder=placeholder)
        e.pack(fill="x")
        setattr(self, attr, e)

    def _do_add(self):
        name = self.a_name.get().strip()
        pw = self.a_pw.get()
        if not name: self.a_err.configure(text="Name required"); return
        if not pw: self.a_err.configure(text="Password required"); return
        self.vault.add(name, self.a_type.get(), self.a_host.get().strip(), self.a_port.get().strip(),
                      self.a_user.get().strip(), pw, self.a_env.get(), self.a_proto.get(),
                      self.a_tags.get().strip(), self.a_notes.get("1.0", "end").strip())
        self._view_all()

    # ===== EDIT =====
    def _view_edit(self, e: dict):
        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkButton(hdr, text="< Cancel", width=70, height=28, corner_radius=5, fg_color="transparent",
                     hover_color=COLORS["bg_tertiary"], text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=11), command=lambda: self._view_detail(e)).pack(side="left")
        ctk.CTkLabel(hdr, text="Edit Credential", font=ctk.CTkFont(size=18, weight="bold"), text_color=COLORS["text_primary"]).pack(side="left", padx=14)

        frm = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        frm.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        pw = self.vault.get_password(e["id"], track=False)

        self._edit_input(frm, "Name", "e_name", e["name"])

        ctk.CTkLabel(frm, text="Type", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        self.e_type = ctk.CTkComboBox(frm, values=CREDENTIAL_TYPES, height=38, corner_radius=6, border_width=1,
                                      border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                      dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.e_type.pack(fill="x")
        self.e_type.set(e.get("type", CREDENTIAL_TYPES[0]))

        row = ctk.CTkFrame(frm, fg_color="transparent")
        row.pack(fill="x", pady=(10, 0))
        hf = ctk.CTkFrame(row, fg_color="transparent")
        hf.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(hf, text="Host / IP", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.e_host = Entry(hf)
        self.e_host.pack(fill="x")
        self.e_host.insert(0, e.get("host", ""))
        pf = ctk.CTkFrame(row, fg_color="transparent", width=90)
        pf.pack(side="right", padx=(8, 0))
        pf.pack_propagate(False)
        ctk.CTkLabel(pf, text="Port", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.e_port = Entry(pf)
        self.e_port.pack(fill="x")
        self.e_port.insert(0, e.get("port", ""))

        self._edit_input(frm, "Username", "e_user", e.get("username", ""))

        ctk.CTkLabel(frm, text="Password", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        prow = ctk.CTkFrame(frm, fg_color="transparent")
        prow.pack(fill="x")
        self.e_pw = PwEntry(prow)
        self.e_pw.pack(side="left", fill="x", expand=True)
        self.e_pw.insert(0, pw)
        ctk.CTkButton(prow, text="Generate", width=75, height=38, corner_radius=6, fg_color=COLORS["accent"],
                     hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=10),
                     command=lambda: (self.e_pw.delete(0, "end"), self.e_pw.insert(0, generate_password()))).pack(side="right", padx=(5, 0))

        row2 = ctk.CTkFrame(frm, fg_color="transparent")
        row2.pack(fill="x", pady=(10, 0))
        ef = ctk.CTkFrame(row2, fg_color="transparent")
        ef.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(ef, text="Environment", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.e_env = ctk.CTkComboBox(ef, values=ENVIRONMENTS, height=38, corner_radius=6, border_width=1,
                                     border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                     dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.e_env.pack(fill="x")
        self.e_env.set(e.get("environment", ENVIRONMENTS[0]))
        prf = ctk.CTkFrame(row2, fg_color="transparent")
        prf.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(prf, text="Protocol", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 3))
        self.e_proto = ctk.CTkComboBox(prf, values=PROTOCOLS, height=38, corner_radius=6, border_width=1,
                                       border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.e_proto.pack(fill="x")
        self.e_proto.set(e.get("protocol", PROTOCOLS[0]))

        self._edit_input(frm, "Tags", "e_tags", e.get("tags", ""))

        ctk.CTkLabel(frm, text="Notes", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        self.e_notes = ctk.CTkTextbox(frm, height=60, corner_radius=6, border_width=1, border_color=COLORS["border"],
                                      fg_color=COLORS["bg_tertiary"], text_color=COLORS["text_primary"], font=ctk.CTkFont(size=11))
        self.e_notes.pack(fill="x")
        if e.get("notes"): self.e_notes.insert("1.0", e["notes"])

        self.e_err = ctk.CTkLabel(frm, text="", font=ctk.CTkFont(size=10), text_color=COLORS["danger"])
        self.e_err.pack(fill="x", pady=(10, 0))

        self.edit_id = e["id"]
        Btn(frm, text="Save Changes", command=self._do_edit).pack(fill="x", pady=(10, 20))

    def _edit_input(self, parent, label: str, attr: str, val: str):
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(10, 3))
        e = Entry(parent)
        e.pack(fill="x")
        e.insert(0, val)
        setattr(self, attr, e)

    def _do_edit(self):
        name = self.e_name.get().strip()
        pw = self.e_pw.get()
        if not name: self.e_err.configure(text="Name required"); return
        if not pw: self.e_err.configure(text="Password required"); return
        self.vault.update(self.edit_id, name=name, type=self.e_type.get(), host=self.e_host.get().strip(),
                         port=self.e_port.get().strip(), username=self.e_user.get().strip(), password=pw,
                         environment=self.e_env.get(), protocol=self.e_proto.get(),
                         tags=self.e_tags.get().strip(), notes=self.e_notes.get("1.0", "end").strip())
        e = next((x for x in self.vault.list_all() if x["id"] == self.edit_id), None)
        if e: self._view_detail(e)
        else: self._view_all()

    # ===== GENERATOR =====
    def _view_gen(self):
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="Password Generator", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 14))

        cnt = ctk.CTkFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.gen_var = ctk.StringVar(value=generate_password())
        pf = ctk.CTkFrame(cnt, fg_color=COLORS["bg_secondary"], corner_radius=8)
        pf.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(pf, textvariable=self.gen_var, font=ctk.CTkFont(size=16, family="Consolas"), text_color=COLORS["text_primary"]).pack(pady=14, padx=14)

        self.str_lbl = ctk.CTkLabel(cnt, text="", font=ctk.CTkFont(size=12), text_color=COLORS["success"])
        self.str_lbl.pack(pady=(0, 16))
        self._upd_str()

        br = ctk.CTkFrame(cnt, fg_color="transparent")
        br.pack(fill="x", pady=(0, 20))
        Btn(br, text="Regenerate", command=self._regen).pack(side="left", padx=(0, 6))
        Btn(br, text="Copy", primary=False, command=lambda: pyperclip.copy(self.gen_var.get())).pack(side="left")

        ctk.CTkLabel(cnt, text="Options", font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x", pady=(12, 8))

        lr = ctk.CTkFrame(cnt, fg_color="transparent")
        lr.pack(fill="x", pady=4)
        ctk.CTkLabel(lr, text="Length:", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(side="left")
        self.len_lbl = ctk.CTkLabel(lr, text="24", font=ctk.CTkFont(size=11, weight="bold"), text_color=COLORS["text_primary"], width=28)
        self.len_lbl.pack(side="right")
        self.len_sl = ctk.CTkSlider(lr, from_=12, to=64, number_of_steps=52, command=self._on_len,
                                    fg_color=COLORS["bg_tertiary"], progress_color=COLORS["accent"],
                                    button_color=COLORS["accent"], button_hover_color=COLORS["accent_hover"])
        self.len_sl.set(24)
        self.len_sl.pack(side="right", fill="x", expand=True, padx=8)

        self.g_up = ctk.BooleanVar(value=True)
        self.g_lo = ctk.BooleanVar(value=True)
        self.g_num = ctk.BooleanVar(value=True)
        self.g_sym = ctk.BooleanVar(value=True)
        for txt, v in [("Uppercase", self.g_up), ("Lowercase", self.g_lo), ("Numbers", self.g_num), ("Symbols", self.g_sym)]:
            ctk.CTkCheckBox(cnt, text=txt, variable=v, font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"],
                           fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"], command=self._regen).pack(fill="x", pady=2)

    def _on_len(self, v):
        self.len_lbl.configure(text=str(int(v)))
        self._regen()

    def _regen(self):
        self.gen_var.set(generate_password(int(self.len_sl.get()), self.g_up.get(), self.g_lo.get(), self.g_num.get(), self.g_sym.get()))
        self._upd_str()

    def _upd_str(self):
        l, s, c = password_strength(self.gen_var.get())
        self.str_lbl.configure(text=f"Strength: {l} ({s}%)", text_color=c)

    # ===== SETTINGS =====
    def _view_settings(self):
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="Settings", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 14))

        cnt = ctk.CTkFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self._setting(cnt, "Start with Windows", "Launch minimized at login", in_startup(), self._tog_startup)
        self._info(cnt, "Global Hotkey", "Shift+V, P (chord - press Shift+V then P)")
        self._info(cnt, "Vault Location", str(get_vault_path()))
        self._info(cnt, "2FA", "Enabled" if self.vault.totp_enabled else "Disabled")
        self._info(cnt, "Encryption", f"AES-256-GCM + {'Argon2id' if HAS_ARGON2 else 'Scrypt'}")
        self._info(cnt, "PDF Export", "Available" if _load_pdf_modules() else "Install: pip install reportlab PyPDF2")

        ctk.CTkLabel(cnt, text=f"SecureVault v{APP_VERSION}", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(pady=(14, 0))

    def _setting(self, parent, title: str, desc: str, val: bool, cmd: Callable):
        fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=8)
        fr.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(fr, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=12)
        ctk.CTkLabel(inner, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        ctk.CTkLabel(inner, text=desc, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x")
        v = ctk.BooleanVar(value=val)
        ctk.CTkSwitch(inner, text="", variable=v, command=cmd, fg_color=COLORS["bg_tertiary"],
                     progress_color=COLORS["accent"], button_color=COLORS["text_primary"]).place(relx=1.0, rely=0.5, anchor="e")
        setattr(self, f"set_{title.lower().replace(' ', '_')}", v)

    def _info(self, parent, title: str, val: str):
        fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=8)
        fr.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(fr, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=12)
        ctk.CTkLabel(inner, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        ctk.CTkLabel(inner, text=val, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(2, 0))

    def _tog_startup(self):
        v = getattr(self, "set_start_with_windows", None)
        if v and v.get(): add_startup()
        else: remove_startup()

# ============================================================
# MAIN
# ============================================================
def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--minimized", "-m", action="store_true")
    args = p.parse_args()

    # Optimize pyautogui for faster typing
    pyautogui.FAILSAFE = False
    pyautogui.PAUSE = 0.005  # Reduced pause for faster response

    # Pre-warm the vault path cache
    get_vault_dir()

    app = App()
    app.start_min = args.minimized
    app.mainloop()

if __name__ == "__main__":
    main()
