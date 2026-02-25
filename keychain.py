"""
SecureVault - System Architect Credential Manager
==================================================
Secure local credential manager for system architects and DevOps engineers.
Designed for servers, databases, API keys, cloud accounts, and network devices.

Features:
- AES-256-GCM encryption with Argon2id KDF
- Local TOTP 2FA (no internet required)
- System tray with configurable global hotkey
- Server/environment focused organization
- Quick access for terminal and remote sessions
- Secure PDF export for team credential sharing
- Favorites/pinned credentials
- SSH key storage
- Password expiry reminders (90 days)
- Clipboard auto-clear (configurable)
- Dark/Light theme
- Sorting options
- Breach detection (local common passwords check)

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
import math
import shutil
import time
import threading
import queue
import tempfile
import urllib.request
import urllib.error
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
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
APP_VERSION = "7.0.0"  # UX polish: hover effects, keyboard shortcuts, copy feedback, confirmations
VAULT_FILENAME = "vault.enc"
STATS_FILENAME = "stats.enc"
SETTINGS_FILENAME = "settings.json"
SALT_LENGTH = 32
NONCE_LENGTH = 12
KEY_LENGTH = 32
MASTER_HASH_ITERATIONS = 100_000
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
DEFAULT_PASSWORD_LENGTH = 24
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 128

# Default hotkey chord: Shift+V then P (configurable in settings)
DEFAULT_HOTKEY_FIRST = "shift+v"
DEFAULT_HOTKEY_SECOND = "p"
CHORD_TIMEOUT = 1.0  # seconds to complete the chord

# Password expiry (days)
PASSWORD_EXPIRY_DAYS = 90
PASSWORD_WARNING_DAYS = 14  # Warn this many days before expiry

# Clipboard auto-clear default (seconds) - 5 minutes
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 300

# Top common passwords for local breach detection (top 1000 most common)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "696969", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "pussy", "superman", "1qaz2wsx", "7777777", "fuckyou", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder",
    "taylor", "matrix", "william", "corvette", "hello", "martin", "heather", "secret",
    "fucker", "merlin", "diamond", "1234qwer", "gfhjkm", "hammer", "silver", "222222",
    "88888888", "anthony", "justin", "test", "bailey", "q1w2e3r4t5", "patrick", "internet",
    "scooter", "orange", "11111", "golfer", "cookie", "richard", "samantha", "bigdog",
    "guitar", "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy", "maverick",
    "phoenix", "camaro", "sexy", "peanut", "morgan", "welcome", "falcon", "cowboy",
    "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph", "mercedes", "dakota",
    "arsenal", "eagles", "melissa", "boomer", "booboo", "spider", "nascar", "monster",
    "tigers", "yellow", "xxxxxx", "123123123", "gateway", "marina", "diablo", "bulldog",
    "qwer1234", "compaq", "purple", "hardcore", "banana", "junior", "hannah", "123654",
    "porsche", "lakers", "iceman", "money", "cowboys", "987654", "london", "tennis",
    "999999", "ncc1701", "coffee", "scooby", "0000", "miller", "boston", "q1w2e3r4",
    "fuckoff", "brandon", "yamaha", "chester", "mother", "forever", "johnny", "edward",
    "333333", "oliver", "redsox", "player", "nikita", "knight", "fender", "barney",
    "midnight", "please", "brandy", "chicago", "badboy", "iwantu", "slayer", "rangers",
    "charles", "angel", "flower", "bigdaddy", "rabbit", "wizard", "bigdick", "jasper",
    "enter", "rachel", "chris", "steven", "winner", "adidas", "victoria", "natasha",
    "1q2w3e4r", "jasmine", "winter", "prince", "panties", "marine", "ghbdtn", "fishing",
    "cocacola", "casper", "james", "232323", "raiders", "888888", "marlboro", "gandalf",
    "asdfasdf", "crystal", "87654321", "12344321", "sexsex", "golden", "blowme", "bigtits",
    "8675309", "panther", "lauren", "angela", "bitch", "spanky", "thx1138", "angels",
    "madison", "winston", "shannon", "mike", "toyota", "blowjob", "jordan23", "canada",
    "sophie", "Password", "apples", "dick", "tiger", "razz", "123abc", "pokemon", "qazxsw",
    "55555", "qwaszx", "muffin", "johnson", "murphy", "cooper", "jonathan", "liverpoo",
    "david", "danielle", "159357", "jackie", "1990", "123456a", "789456", "turtle", "horny",
    "abcd1234", "scorpion", "qazwsxedc", "101010", "butter", "carlos", "Password1",
    "admin", "password1", "password123", "admin123", "root", "toor", "administrator",
    "letmein123", "welcome1", "welcome123", "changeme", "passw0rd", "p@ssw0rd", "P@ssw0rd",
}

# DevOps credential types with icons and default fields
# Format: (display_name, icon, default_protocol, suggested_port)
CREDENTIAL_CATEGORIES = {
    # Servers
    "Windows Server": {"icon": "🪟", "proto": "RDP", "port": "3389", "fields": ["host", "port", "username", "password"]},
    "Linux Server": {"icon": "🐧", "proto": "SSH", "port": "22", "fields": ["host", "port", "username", "password"]},
    "IIS Server": {"icon": "🌐", "proto": "HTTPS", "port": "443", "fields": ["host", "port", "username", "password"]},
    # Databases
    "SQL Server": {"icon": "🗃️", "proto": "MSSQL", "port": "1433", "fields": ["host", "port", "username", "password", "database"]},
    "Database - MySQL": {"icon": "🗄️", "proto": "MySQL", "port": "3306", "fields": ["host", "port", "username", "password", "database"]},
    "Database - PostgreSQL": {"icon": "🐘", "proto": "PostgreSQL", "port": "5432", "fields": ["host", "port", "username", "password", "database"]},
    "Database - MongoDB": {"icon": "🍃", "proto": "MongoDB", "port": "27017", "fields": ["host", "port", "username", "password", "database"]},
    "Database - Redis": {"icon": "⚡", "proto": "Redis", "port": "6379", "fields": ["host", "port", "password"]},
    # Accounts
    "Domain Account": {"icon": "🏢", "proto": "LDAP", "port": "389", "fields": ["host", "username", "password"]},
    "User Account": {"icon": "👤", "proto": "HTTPS", "port": "", "fields": ["username", "password", "email", "role"]},
    "Service Account": {"icon": "🤖", "proto": "API", "port": "", "fields": ["username", "password", "service_name"]},
    "Root / Admin": {"icon": "👑", "proto": "SSH", "port": "22", "fields": ["host", "port", "username", "password"]},
    # .NET / Config
    ".NET Application": {"icon": "🟣", "proto": "HTTPS", "port": "", "fields": ["host", "username", "password"]},
    "AppSettings": {"icon": "⚙️", "proto": "Other", "port": "", "fields": ["username", "password"]},
    "Web.config": {"icon": "📄", "proto": "Other", "port": "", "fields": ["host", "username", "password"]},
    "Environment Variable": {"icon": "📋", "proto": "Other", "port": "", "fields": ["username", "password"]},
    # Secrets
    "Application Secret": {"icon": "🔏", "proto": "API", "port": "", "fields": ["username", "password"]},
    "GitHub Secret": {"icon": "🐙", "proto": "HTTPS", "port": "", "fields": ["username", "password"]},
    "API Key": {"icon": "🔑", "proto": "API", "port": "", "fields": ["api_key", "api_secret", "endpoint"]},
    "SSL Certificate": {"icon": "📜", "proto": "HTTPS", "port": "", "fields": ["domain", "private_key", "certificate", "expiry"]},
    # Cloud & CI/CD
    "AWS Console": {"icon": "☁️", "proto": "Console", "port": "", "fields": ["username", "password", "account_id", "mfa_secret"]},
    "Azure Portal": {"icon": "🔷", "proto": "Console", "port": "", "fields": ["username", "password", "tenant_id"]},
    "GCP Console": {"icon": "🔶", "proto": "Console", "port": "", "fields": ["username", "password", "project_id"]},
    "Git Repository": {"icon": "📦", "proto": "HTTPS", "port": "", "fields": ["host", "username", "password", "repo_url"]},
    "CI/CD - Jenkins": {"icon": "🔧", "proto": "HTTPS", "port": "8080", "fields": ["host", "port", "username", "password", "api_token"]},
    "CI/CD - GitLab": {"icon": "🦊", "proto": "HTTPS", "port": "", "fields": ["host", "username", "password", "access_token"]},
    "CI/CD - GitHub": {"icon": "🐙", "proto": "HTTPS", "port": "", "fields": ["username", "password", "access_token"]},
    # Web & Email
    "Web Server - Nginx": {"icon": "🌐", "proto": "HTTPS", "port": "443", "fields": ["host", "port", "username", "password", "config_path"]},
    "Web Server - Apache": {"icon": "🪶", "proto": "HTTPS", "port": "443", "fields": ["host", "port", "username", "password", "config_path"]},
    "SMTP / Email": {"icon": "📧", "proto": "SMTP", "port": "587", "fields": ["host", "port", "username", "password", "from_email"]},
    "FTP / SFTP": {"icon": "📁", "proto": "FTP/SFTP", "port": "22", "fields": ["host", "port", "username", "password", "root_path"]},
    # Network
    "VPN / Tunnel": {"icon": "🔒", "proto": "VPN", "port": "", "fields": ["host", "port", "username", "password", "vpn_type"]},
    "Network - Router": {"icon": "📡", "proto": "SSH", "port": "22", "fields": ["host", "port", "username", "password", "enable_password"]},
    "Network - Switch": {"icon": "🔀", "proto": "SSH", "port": "22", "fields": ["host", "port", "username", "password", "enable_password"]},
    "Network - Firewall": {"icon": "🛡️", "proto": "HTTPS", "port": "443", "fields": ["host", "port", "username", "password"]},
    "DNS Provider": {"icon": "🌍", "proto": "API", "port": "", "fields": ["api_key", "api_secret", "zone"]},
    # Other
    "Normal Password": {"icon": "🔐", "proto": "Other", "port": "", "fields": ["username", "password"]},
    "Other": {"icon": "🔐", "proto": "Other", "port": "", "fields": ["host", "port", "username", "password"]},
}

CREDENTIAL_TYPES = list(CREDENTIAL_CATEGORIES.keys())

def get_category_icon(ctype: str) -> str:
    """Get icon for credential type."""
    return CREDENTIAL_CATEGORIES.get(ctype, {}).get("icon", "🔐")

def get_category_defaults(ctype: str) -> dict:
    """Get default values for a credential type."""
    return CREDENTIAL_CATEGORIES.get(ctype, {"proto": "Other", "port": "", "fields": []})

ENVIRONMENTS = ["Production", "Staging", "Development", "QA", "DR", "Local", "Shared"]

PROTOCOLS = ["SSH", "RDP", "HTTPS", "HTTP", "MySQL", "PostgreSQL", "MongoDB", "Redis",
             "MSSQL", "FTP/SFTP", "API", "Console", "LDAP", "SMTP", "Docker", "K8s API", "VPN", "Other"]

# Dark theme (default)
COLORS_DARK = {
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
    "danger_hover": "#FF6961",
    "warning_text": "#FFFFFF",
}

# Light theme
COLORS_LIGHT = {
    "bg_primary": "#FFFFFF",
    "bg_secondary": "#F6F8FA",
    "bg_tertiary": "#EAEEF2",
    "bg_popup": "#FFFFFF",
    "accent": "#0969DA",
    "accent_hover": "#0550AE",
    "success": "#1A7F37",
    "warning": "#9A6700",
    "danger": "#CF222E",
    "text_primary": "#1F2328",
    "text_secondary": "#656D76",
    "text_tertiary": "#8C959F",
    "border": "#D0D7DE",
    "prod": "#CF222E",
    "staging": "#9A6700",
    "dev": "#1A7F37",
    "danger_hover": "#E5534B",
    "warning_text": "#FFFFFF",
}

# Active colors (set by theme)
COLORS = COLORS_DARK.copy()

def set_theme(dark: bool = True):
    """Switch between dark and light theme."""
    global COLORS
    COLORS.clear()
    COLORS.update(COLORS_DARK if dark else COLORS_LIGHT)

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

def get_settings_path() -> Path:
    return get_vault_dir() / SETTINGS_FILENAME

# ============================================================
# SETTINGS MANAGER
# ============================================================
class Settings:
    """Persistent user settings (unencrypted, non-sensitive)."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self):
        self.data = {
            "theme": "dark",
            "hotkey_first": DEFAULT_HOTKEY_FIRST,
            "hotkey_second": DEFAULT_HOTKEY_SECOND,
            "clipboard_clear_seconds": DEFAULT_CLIPBOARD_CLEAR_SECONDS,
            "sort_by": "name",  # name, date, usage, environment
            "sort_ascending": True,
        }
        path = get_settings_path()
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text()))
            except:
                pass
        # Apply theme on load
        set_theme(self.data["theme"] == "dark")

    def save(self):
        get_settings_path().write_text(json.dumps(self.data, indent=2))

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value):
        self.data[key] = value
        self.save()
        if key == "theme":
            set_theme(value == "dark")

def get_settings() -> Settings:
    return Settings()

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
    if use_symbols:
        symbols = "!@#$%^&*-_=+"
        try:
            if get_settings().get("exclude_dollar", False):
                symbols = symbols.replace("$", "")
        except Exception:
            pass
        pools.append(symbols)
    if not pools: pools.append("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789")
    chars = [secrets.choice(p) for p in pools]
    all_chars = "".join(pools)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)

def check_password_breach(pw: str) -> Tuple[bool, str]:
    """
    Check if password is in common passwords list (local check).
    Returns (is_breached, message)
    """
    if not pw:
        return False, ""

    # Check against local common passwords
    if pw.lower() in COMMON_PASSWORDS or pw in COMMON_PASSWORDS:
        return True, "Common password - easily guessable!"

    # Check for simple patterns
    if pw.isdigit() and len(set(pw)) <= 2:
        return True, "Simple number pattern"
    if pw.lower() == pw.lower()[0] * len(pw):
        return True, "Repeated character"

    return False, "Not in common breach list"

def check_password_hibp(pw: str) -> Tuple[bool, int, str]:
    """
    Check password against Have I Been Pwned using k-anonymity.
    Only sends first 5 chars of SHA-1 hash (privacy-safe).
    Returns (is_breached, count, message)
    """
    try:
        sha1 = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={'User-Agent': 'SecureVault-PasswordManager'})

        with urllib.request.urlopen(req, timeout=5) as response:
            hashes = response.read().decode('utf-8')

        for line in hashes.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return True, int(count), f"Found in {int(count):,} breaches!"

        return False, 0, "Not found in breaches"
    except Exception as e:
        return False, -1, f"Check failed: {str(e)[:30]}"

def password_strength(pw: str) -> Tuple[str, int, str, str]:
    """
    Entropy-based password strength scoring.
    Returns (label, score_percent, color, details)
    """
    if not pw:
        return ("None", 0, COLORS["danger"], "Enter a password")

    length = len(pw)

    # Check for common/breached passwords first (instant fail)
    is_common, common_msg = check_password_breach(pw)
    if is_common:
        return ("Breached", 5, COLORS["danger"], common_msg)

    # Determine character pool size from what is actually present
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in pw)

    pool_size = 0
    if has_upper: pool_size += 26
    if has_lower: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32

    # Fallback: if somehow no category matched, assume lowercase
    if pool_size == 0:
        pool_size = 26

    # Calculate entropy bits: length * log2(pool_size)
    entropy_bits = length * math.log2(pool_size)

    # Map entropy to 0-100 score using 128 bits as the 100% reference
    score = min(100, int(entropy_bits * 100 / 128))

    # Build suggestions for missing character types
    suggestions = []
    if not (has_upper and has_lower):
        suggestions.append("Add mixed case")
    if not has_digit:
        suggestions.append("Add numbers")
    if not has_symbol:
        suggestions.append("Add symbols")

    # Determine label and color based on entropy thresholds
    bits_int = int(entropy_bits)

    if entropy_bits < 36:
        detail = "Extremely weak"
        if suggestions:
            detail = ", ".join(suggestions) + f" ({bits_int}-bit entropy)"
        return ("Critical", score, COLORS["danger"], detail)
    elif entropy_bits < 60:
        detail = ", ".join(suggestions) if suggestions else "Needs improvement"
        detail += f" ({bits_int}-bit entropy)"
        return ("Weak", score, COLORS["danger"], detail)
    elif entropy_bits < 80:
        detail = ", ".join(suggestions) if suggestions else "Moderate security"
        detail += f" ({bits_int}-bit entropy)"
        return ("Fair", score, COLORS["warning"], detail)
    elif entropy_bits < 100:
        return ("Strong", score, COLORS["accent"], f"Good security \u00b7 {bits_int}-bit entropy")
    else:
        return ("Excellent", score, COLORS["success"], f"{bits_int}-bit entropy")

def get_password_age_days(modified_date: str) -> int:
    """Get password age in days from modified date string."""
    try:
        if not modified_date:
            return 0
        modified = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - modified).days
    except:
        return 0

def is_password_expiring(modified_date: str) -> Tuple[bool, int, str]:
    """
    Check if password is expiring soon or expired.
    Returns (is_expiring, days_until_expiry, message)
    """
    age_days = get_password_age_days(modified_date)
    days_until_expiry = PASSWORD_EXPIRY_DAYS - age_days

    if days_until_expiry <= 0:
        return True, days_until_expiry, f"Expired {abs(days_until_expiry)} days ago!"
    elif days_until_expiry <= PASSWORD_WARNING_DAYS:
        return True, days_until_expiry, f"Expires in {days_until_expiry} days"
    else:
        return False, days_until_expiry, f"{age_days} days old"

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

        # Encrypt with password (use AES-256 if supported, fallback to default)
        try:
            writer.encrypt(pdf_password, pdf_password, algorithm="AES-256")
        except TypeError:
            # Older PyPDF2 versions don't support algorithm parameter
            writer.encrypt(pdf_password, pdf_password)

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
# PDF IMPORT (Password Protected - Lazy Loaded)
# ============================================================
def import_credentials_from_pdf(pdf_path: str, pdf_password: str) -> List[dict]:
    """
    Import credentials from a password-protected PDF previously exported by SecureVault.
    Parses the known export format and returns a list of credential dicts.

    Returns list of dicts with keys:
        name, type, host, port, username, password, environment, protocol, tags, notes
    """
    if not _load_pdf_modules():
        raise RuntimeError("PDF import requires 'PyPDF2' package.\n"
                          "Install with: pip install PyPDF2")

    PdfReader = _pdf_modules['PdfReader']

    import re

    reader = PdfReader(pdf_path)

    # Decrypt the PDF
    if reader.is_encrypted:
        result = reader.decrypt(pdf_password)
        # PyPDF2 returns 0 for failed decrypt, 1 or 2 for success
        if result == 0:
            raise ValueError("Incorrect PDF password")

    # Extract text from all pages, concatenated
    full_text = ""
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            full_text += page_text + "\n"

    if not full_text.strip():
        raise ValueError("Could not extract text from PDF. The file may be empty or corrupt.")

    credentials = []

    # Split into credential blocks using the numbered header pattern:
    # "1. CredentialName [Environment]" or "1. CredentialName"
    # The pattern accounts for PyPDF2 text extraction quirks
    entry_pattern = re.compile(
        r'(\d+)\.\s+(.+?)(?:\s*\[([^\]]*)\])?\s*\n',
        re.MULTILINE
    )

    matches = list(entry_pattern.finditer(full_text))

    if not matches:
        raise ValueError("No credentials found in PDF. The file may not be a SecureVault export.")

    for idx, match in enumerate(matches):
        # Determine the text block for this credential
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(full_text)
        block = full_text[start:end]

        cred_name = match.group(2).strip()
        cred_env = match.group(3).strip() if match.group(3) else ""

        cred = {
            "name": cred_name,
            "type": "",
            "host": "",
            "port": "",
            "username": "",
            "password": "",
            "environment": cred_env,
            "protocol": "",
            "tags": "",
            "notes": "",
        }

        # Parse label:value pairs from the block
        # The PDF export uses "Label:" followed by value, one per line
        # PyPDF2 may merge lines or add extra whitespace, so be flexible
        field_map = {
            "type": "type",
            "host": "host",
            "protocol": "protocol",
            "username": "username",
            "password": "password",
            "tags": "tags",
            "notes": "notes",
        }

        # Try line-by-line extraction first (most reliable)
        lines = block.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Match "Label: value" or "Label:value"
            label_match = re.match(r'^(Type|Host|Protocol|Username|Password|Tags|Notes)\s*:\s*(.*)', line, re.IGNORECASE)
            if label_match:
                label_key = label_match.group(1).lower()
                value = label_match.group(2).strip()

                if label_key == "host" and value:
                    # Split host:port if present
                    # Handle IPv6 addresses in brackets [::1]:port
                    if value.startswith("["):
                        bracket_end = value.find("]")
                        if bracket_end != -1 and bracket_end + 1 < len(value) and value[bracket_end + 1] == ":":
                            cred["host"] = value[:bracket_end + 1]
                            cred["port"] = value[bracket_end + 2:]
                        else:
                            cred["host"] = value
                    elif ":" in value:
                        # Could be host:port - but only split on last colon
                        # to handle cases like "hostname:8080"
                        parts = value.rsplit(":", 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            cred["host"] = parts[0]
                            cred["port"] = parts[1]
                        else:
                            cred["host"] = value
                    else:
                        cred["host"] = value
                elif label_key in field_map:
                    mapped_key = field_map[label_key]
                    cred[mapped_key] = value

        # Strip trailing "..." from notes (export truncates to 200 chars)
        if cred["notes"].endswith("..."):
            cred["notes"] = cred["notes"][:-3].rstrip()

        credentials.append(cred)

    return credentials

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
                 'entries', 'unlocked', 'stats', '_list_cache', '_list_cache_valid', 'favorites')

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
        self.favorites: Set[str] = set()

    def exists(self) -> bool:
        return self.path.exists()

    def toggle_favorite(self, eid: str) -> bool:
        """Toggle favorite status. Returns new status."""
        if eid in self.favorites:
            self.favorites.discard(eid)
            result = False
        else:
            self.favorites.add(eid)
            result = True
        self._save()
        return result

    def is_favorite(self, eid: str) -> bool:
        return eid in self.favorites

    def get_favorites(self) -> list:
        """Get all favorite credentials."""
        return [e for e in self.list_all() if e["id"] in self.favorites]

    def get_expiring_passwords(self) -> list:
        """Get credentials with expiring/expired passwords."""
        result = []
        for e in self.list_all():
            is_exp, days, msg = is_password_expiring(e.get("modified", ""))
            if is_exp:
                e["expiry_days"] = days
                e["expiry_msg"] = msg
                result.append(e)
        return sorted(result, key=lambda x: x["expiry_days"])

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

    def unlock(self, password: str) -> Tuple[bool, str]:
        """Unlock vault. Returns (success, error_message)."""
        try:
            if not self.path.exists():
                return False, "Vault file not found"
            data = json.loads(self.path.read_bytes())
            self.salt = base64.b64decode(data["salt"])
            self.verify_hash = data["master_verify"]
            if not verify_master_password(password, self.salt, self.verify_hash):
                return False, "Wrong password"
            self.key = derive_key(password, self.salt)
            self.entries = json.loads(decrypt_data(base64.b64decode(data["entries_enc"]), self.key).decode("utf-8"))
            if data.get("totp_enc"):
                self.totp_secret = decrypt_data(base64.b64decode(data["totp_enc"]), self.key).decode("utf-8")
                self.totp_enabled = True
            else:
                self.totp_enabled = data.get("totp_enabled", False)
            # Load favorites
            self.favorites = set(data.get("favorites", []))
            self.unlocked = True
            self._invalidate_cache()
            self.stats.set_key(self.key)
            return True, ""
        except json.JSONDecodeError:
            return False, "Vault file corrupted"
        except KeyError as e:
            return False, f"Invalid vault format: missing {e}"
        except Exception as e:
            return False, f"Unlock failed: {str(e)[:50]}"

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
        data = {"version": 4, "app": APP_NAME, "salt": base64.b64encode(self.salt).decode(),
                "master_verify": self.verify_hash, "entries_enc": base64.b64encode(enc).decode(),
                "totp_enabled": self.totp_enabled, "favorites": list(self.favorites)}
        if self.totp_secret:
            data["totp_enc"] = base64.b64encode(encrypt_data(self.totp_secret.encode("utf-8"), self.key)).decode()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        shutil.move(str(tmp), str(self.path))

    def add(self, name: str, ctype: str, host: str = "", port: str = "", user: str = "",
            password: str = "", env: str = "", proto: str = "", tags: str = "", notes: str = "",
            ssh_key: str = "") -> str:
        eid = secrets.token_hex(8)
        now = datetime.now(timezone.utc).isoformat()
        entry = {"name": name, "type": ctype, "host": host, "port": port, "username": user,
                 "password_enc": base64.b64encode(encrypt_data(password.encode("utf-8"), self.key)).decode(),
                 "environment": env, "protocol": proto, "tags": tags, "notes": notes,
                 "created": now, "modified": now}
        if ssh_key:
            entry["ssh_key_enc"] = base64.b64encode(encrypt_data(ssh_key.encode("utf-8"), self.key)).decode()
        self.entries[eid] = entry
        self._invalidate_cache()
        self._save()
        return eid

    def get_ssh_key(self, eid: str) -> str:
        """Get decrypted SSH key for an entry."""
        entry = self.entries.get(eid, {})
        if "ssh_key_enc" in entry:
            return decrypt_data(base64.b64decode(entry["ssh_key_enc"]), self.key).decode("utf-8")
        return ""

    def get_password(self, eid: str, track: bool = True) -> str:
        if track: self.stats.record(eid)
        return decrypt_data(base64.b64decode(self.entries[eid]["password_enc"]), self.key).decode("utf-8")

    def _invalidate_cache(self):
        self._list_cache_valid = False

    def list_all(self, sort_by: str = None, ascending: bool = True) -> list:
        if self._list_cache_valid and sort_by is None:
            return self._list_cache
        fields = ["name", "type", "host", "port", "username", "environment", "protocol", "tags", "notes", "created", "modified"]
        result = []
        for k, v in self.entries.items():
            entry = {"id": k, "use_count": self.stats.count(k)}
            for f in fields:
                entry[f] = v.get(f, "")
            entry["is_favorite"] = k in self.favorites
            entry["has_ssh_key"] = "ssh_key_enc" in v
            # Check expiry
            is_exp, days, msg = is_password_expiring(v.get("modified", ""))
            entry["is_expiring"] = is_exp
            entry["expiry_days"] = days
            entry["expiry_msg"] = msg
            result.append(entry)

        # Sort based on settings or parameter
        sort_key = sort_by or get_settings().get("sort_by", "name")
        if sort_key == "name":
            result.sort(key=lambda x: (not x["is_favorite"], x["name"].lower()), reverse=not ascending)
        elif sort_key == "date":
            result.sort(key=lambda x: (not x["is_favorite"], x["modified"]), reverse=not ascending)
        elif sort_key == "usage":
            result.sort(key=lambda x: (not x["is_favorite"], -x["use_count"]), reverse=not ascending)
        elif sort_key == "environment":
            result.sort(key=lambda x: (not x["is_favorite"], x["environment"], x["name"].lower()), reverse=not ascending)
        else:
            result.sort(key=lambda x: (not x["is_favorite"], x["name"].lower()))

        if sort_by is None:
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
        if "ssh_key" in kw:
            ssh_key = kw.pop("ssh_key")
            if ssh_key:
                e["ssh_key_enc"] = base64.b64encode(encrypt_data(ssh_key.encode("utf-8"), self.key)).decode()
            elif "ssh_key_enc" in e:
                del e["ssh_key_enc"]
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
    Handles configurable chord hotkey without interfering with normal typing.
    Uses a state machine approach instead of key suppression.
    """
    def __init__(self, callback: Callable):
        self.callback = callback
        self.chord_state = 0  # 0=waiting, 1=first key pressed, 2=chord complete
        self.last_chord_time = 0
        self.active = False
        self._lock = threading.Lock()
        self._load_hotkey_config()

    def _load_hotkey_config(self):
        """Load hotkey configuration from settings."""
        settings = get_settings()
        self.hotkey_first = settings.get("hotkey_first", DEFAULT_HOTKEY_FIRST)
        self.hotkey_second = settings.get("hotkey_second", DEFAULT_HOTKEY_SECOND)
        # Parse first hotkey (e.g., "shift+v" -> modifier="shift", key="v")
        if "+" in self.hotkey_first:
            self.first_modifier, self.first_key = self.hotkey_first.rsplit("+", 1)
        else:
            self.first_modifier, self.first_key = None, self.hotkey_first

    def reload_config(self):
        """Reload hotkey configuration."""
        self._load_hotkey_config()

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

            # State 0: Waiting for first key combo (e.g., Shift+V)
            if self.chord_state == 0:
                if key_name == self.first_key:
                    if self.first_modifier is None or keyboard.is_pressed(self.first_modifier):
                        self.chord_state = 1
                        self.last_chord_time = current_time

            # State 1: First key was pressed, waiting for second key
            elif self.chord_state == 1:
                if key_name == self.hotkey_second:
                    self.chord_state = 0  # Reset state
                    # Trigger callback in separate thread to not block
                    threading.Thread(target=self.callback, daemon=True).start()
                elif key_name not in (self.first_modifier or '', self.first_key, self.hotkey_second):
                    # Wrong key pressed, reset
                    self.chord_state = 0

    def _on_key_release(self, event):
        """Handle key release - reset chord if modifier released early."""
        if not self.active:
            return
        key_name = event.name.lower() if event.name else ""
        # If modifier is released before completing chord, reset
        if self.first_modifier and key_name == self.first_modifier and self.chord_state == 1:
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
        hk_settings = get_settings()
        hk_first = hk_settings.get("hotkey_first", DEFAULT_HOTKEY_FIRST)
        hk_second = hk_settings.get("hotkey_second", DEFAULT_HOTKEY_SECOND)
        hk_display = f"{hk_first}, {hk_second}".upper()
        ctk.CTkLabel(hdr, text=hk_display, font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"],
                    fg_color=COLORS["bg_tertiary"], corner_radius=4, width=90, height=22).pack(side="right")

        # Search
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh())
        self.search = ctk.CTkEntry(self, textvariable=self.search_var, height=38, corner_radius=6,
                                   border_width=1, border_color=COLORS["accent"], fg_color=COLORS["bg_tertiary"],
                                   text_color=COLORS["text_primary"], placeholder_text="Search... (Enter=copy pw, Ctrl+Enter=auto-fill)",
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
        self.bind("<Control-Return>", lambda _: self._autofill())
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
        hover_color = COLORS["bg_tertiary"]
        default_color = COLORS["bg_secondary"]
        fr = ctk.CTkFrame(self.lst, fg_color=default_color, corner_radius=8, height=44)
        fr.pack(fill="x", pady=1)
        fr.pack_propagate(False)
        fr.bind("<Button-1>", lambda _, idx=i: self._sel_copy(idx))
        fr.bind("<Enter>", lambda _: fr.configure(fg_color=hover_color))
        fr.bind("<Leave>", lambda _: fr.configure(fg_color=default_color))

        env = e.get("environment", "")
        ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["border"]
        ctk.CTkFrame(fr, width=3, fg_color=ec, corner_radius=0).pack(side="left", fill="y")

        # Icon
        ctype = e.get("type", "Other")
        icon = get_category_icon(ctype)
        ctk.CTkLabel(fr, text=icon, font=ctk.CTkFont(size=16), width=28).pack(side="left", padx=(6, 0))

        # Buttons on right (packed right-to-left: Fill, Pw, User)
        ctk.CTkButton(fr, text="Fill", width=38, height=24, corner_radius=6,
                     fg_color=COLORS["accent"],
                     hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=8, weight="bold"),
                     command=lambda idx=i: self._sel_autofill(idx)).pack(side="right", padx=(2, 6))
        ctk.CTkButton(fr, text="Pw", width=38, height=24, corner_radius=6,
                     fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=8),
                     command=lambda idx=i: self._sel_copy(idx)).pack(side="right", padx=(2, 0))
        ctk.CTkButton(fr, text="User", width=42, height=24, corner_radius=6,
                     fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=8),
                     command=lambda idx=i: self._sel_copy_user(idx)).pack(side="right")

        # Content
        cnt = ctk.CTkFrame(fr, fg_color="transparent")
        cnt.pack(side="left", fill="both", expand=True, padx=4)
        cnt.bind("<Button-1>", lambda _, idx=i: self._sel_copy(idx))

        ctk.CTkLabel(cnt, text=e["name"], font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=COLORS["text_primary"], anchor="w").pack(fill="x", pady=(5, 0))
        info = e.get("username", "") or e.get("host", "") or ctype.split(" - ")[-1].split(" ")[0]
        ctk.CTkLabel(cnt, text=info[:30], font=ctk.CTkFont(size=8),
                    text_color=COLORS["text_tertiary"], anchor="w").pack(fill="x")

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

    def _sel_autofill(self, i: int):
        self.sel = i
        self._autofill()

    def _sel_copy_user(self, i: int):
        self.sel = i
        self._copy_username()

    def _copy(self):
        if self.items:
            ClipboardManager.copy(self.vault.get_password(self.items[self.sel]["id"]))
            self.title("Copied!")
            self.after(350, self._close)

    def _copy_username(self):
        if self.items:
            user = self.items[self.sel].get("username", "")
            if user:
                ClipboardManager.copy(user)
                self.title("Username Copied!")
            else:
                self.title("No username")
            self.after(350, self._close)

    def _type(self):
        if self.items:
            pw = self.vault.get_password(self.items[self.sel]["id"])
            self._close()
            time.sleep(0.25)
            self._safe_type(pw)

    def _autofill(self):
        """Auto-fill: types username, Tab, password into the focused window."""
        if self.items:
            e = self.items[self.sel]
            user = e.get("username", "")
            pw = self.vault.get_password(e["id"])
            self._close()
            time.sleep(0.3)
            if user:
                self._safe_type(user)
                pyautogui.press("tab")
                time.sleep(0.05)
            self._safe_type(pw)

    @staticmethod
    def _safe_type(text: str):
        """Type text using clipboard paste for full unicode support."""
        if not text:
            return
        # Pure ASCII: use typewrite for character-by-character reliability
        try:
            text.encode("ascii")
            pyautogui.typewrite(text, interval=0.02)
        except UnicodeEncodeError:
            # Non-ASCII: clipboard-based paste for unicode support
            prev = None
            try:
                prev = pyperclip.paste()
            except Exception:
                pass
            pyperclip.copy(text)
            time.sleep(0.02)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.05)
            # Restore previous clipboard content
            if prev is not None:
                try:
                    pyperclip.copy(prev)
                except Exception:
                    pass

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
        h = COLORS["danger_hover"] if danger else COLORS["accent_hover"] if primary else COLORS["border"]
        tc = "#FFFFFF" if primary or danger else COLORS["text_primary"]
        super().__init__(master, text=text, height=38, corner_radius=6, fg_color=c, hover_color=h,
                        text_color=tc, font=ctk.CTkFont(size=12, weight="bold"), **kw)

class PwEntry(ctk.CTkFrame):
    def __init__(self, master, placeholder="Password / Secret", **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.show = False
        self.e = Entry(self, placeholder=placeholder, show="*")
        self.e.pack(side="left", fill="x", expand=True)
        self.b = ctk.CTkButton(self, text="Show", width=50, height=38, corner_radius=6, fg_color=COLORS["bg_tertiary"],
                              hover_color=COLORS["border"], text_color=COLORS["text_primary"], font=ctk.CTkFont(size=10), command=self._toggle)
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
                 selected: bool = False, on_select: Callable = None, on_favorite: Callable = None,
                 show_expiry: bool = False, **kw):
        # Card with more info (62px height = 48 + 14)
        super().__init__(master, fg_color=COLORS["bg_secondary"], corner_radius=10, height=62, **kw)
        self.data = data
        self._on_click = lambda _=None: on_click(data)
        self._default_color = COLORS["bg_secondary"]
        self._hover_color = COLORS["bg_tertiary"]
        self.pack_propagate(False)
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", lambda _: self.configure(fg_color=self._hover_color))
        self.bind("<Leave>", lambda _: self.configure(fg_color=self._default_color))

        env = data.get("environment", "")
        ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["border"]

        # Expiry warning border
        bar = ctk.CTkFrame(self, width=4, fg_color=COLORS["warning"] if data.get("is_expiring") else ec, corner_radius=0)
        bar.pack(side="left", fill="y")
        bar.bind("<Button-1>", self._on_click)

        # Selection checkbox for export
        if selectable:
            self.chk_var = ctk.BooleanVar(value=selected)
            chk = ctk.CTkCheckBox(self, text="", variable=self.chk_var, width=22, corner_radius=4,
                                  fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                  command=lambda: on_select(data["id"], self.chk_var.get()) if on_select else None)
            chk.pack(side="left", padx=(8, 0))

        # Favorite star button
        if on_favorite:
            is_fav = data.get("is_favorite", False)
            ctk.CTkButton(self, text="★" if is_fav else "☆", width=28, height=28, corner_radius=6,
                         fg_color=COLORS["warning"] if is_fav else "transparent",
                         hover_color=COLORS["warning"], font=ctk.CTkFont(size=14),
                         text_color="#FFFFFF" if is_fav else COLORS["text_tertiary"],
                         command=lambda: on_favorite(data["id"])).pack(side="right", padx=(0, 4))

        # Copy password button on right
        def _copy_pw():
            on_copy(data)
            pw_btn.configure(text="Copied!")
            self.after(1000, lambda: pw_btn.configure(text="Copy PW"))
        pw_btn = ctk.CTkButton(self, text="Copy PW", width=60, height=32, corner_radius=8, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], text_color=COLORS["text_primary"], font=ctk.CTkFont(size=10),
                     command=_copy_pw)
        pw_btn.pack(side="right", padx=(0, 6), pady=10)

        # Copy username button on right
        if data.get("username"):
            def _copy_user():
                ClipboardManager.copy(data["username"])
                usr_btn.configure(text="Copied!")
                self.after(1000, lambda: usr_btn.configure(text="Copy User"))
            usr_btn = ctk.CTkButton(self, text="Copy User", width=68, height=32, corner_radius=8, fg_color=COLORS["bg_tertiary"],
                         hover_color=COLORS["border"], text_color=COLORS["text_primary"], font=ctk.CTkFont(size=10),
                         command=_copy_user)
            usr_btn.pack(side="right", padx=(0, 4), pady=10)

        # Icon on left
        ctype = data.get("type", "Other")
        icon = get_category_icon(ctype)
        icon_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_tertiary"], corner_radius=8, width=36, height=36)
        icon_frame.pack(side="left", padx=(8, 0), pady=13)
        icon_frame.pack_propagate(False)
        icon_lbl = ctk.CTkLabel(icon_frame, text=icon, font=ctk.CTkFont(size=16), text_color=COLORS["text_primary"])
        icon_lbl.place(relx=0.5, rely=0.5, anchor="center")
        icon_frame.bind("<Button-1>", self._on_click)
        icon_lbl.bind("<Button-1>", self._on_click)

        # Content with more info
        cnt = ctk.CTkFrame(self, fg_color="transparent")
        cnt.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        cnt.bind("<Button-1>", self._on_click)

        # Top row: Name + badges
        top_row = ctk.CTkFrame(cnt, fg_color="transparent")
        top_row.pack(fill="x")
        top_row.bind("<Button-1>", self._on_click)

        name_lbl = ctk.CTkLabel(top_row, text=data["name"], font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["text_primary"], anchor="w")
        name_lbl.pack(side="left")
        name_lbl.bind("<Button-1>", self._on_click)

        # SSH key indicator
        if data.get("has_ssh_key"):
            ssh_lbl = ctk.CTkLabel(top_row, text="🔑", font=ctk.CTkFont(size=10))
            ssh_lbl.pack(side="left", padx=(4, 0))
            ssh_lbl.bind("<Button-1>", self._on_click)

        # Environment badge
        if env:
            env_lbl = ctk.CTkLabel(top_row, text=env[:4], font=ctk.CTkFont(size=8, weight="bold"), text_color=ec,
                        fg_color=COLORS["bg_primary"], corner_radius=4, height=16)
            env_lbl.pack(side="left", padx=(8, 0))
            env_lbl.bind("<Button-1>", self._on_click)

        # Expiry badge
        if show_expiry and data.get("is_expiring"):
            exp_color = COLORS["danger"] if data.get("expiry_days", 0) <= 0 else COLORS["warning"]
            exp_lbl = ctk.CTkLabel(top_row, text=data.get("expiry_msg", ""), font=ctk.CTkFont(size=8, weight="bold"),
                        text_color=exp_color, fg_color=COLORS["bg_primary"], corner_radius=4, height=16)
            exp_lbl.pack(side="left", padx=(8, 0))
            exp_lbl.bind("<Button-1>", self._on_click)

        # Bottom row: type | user@host:port
        info_parts = []
        if ctype and ctype != "Other":
            info_parts.append(ctype.split(" - ")[-1].split(" ")[0])  # Short type name
        if data.get("username"):
            info_parts.append(data["username"])
        host_str = data.get("host", "")
        if data.get("port"):
            host_str += f":{data['port']}"
        if host_str:
            info_parts.append(host_str)

        info_line = " • ".join(info_parts) if info_parts else data.get("protocol", "")

        if info_line:
            info_lbl = ctk.CTkLabel(cnt, text=info_line[:50], font=ctk.CTkFont(size=10),
                        text_color=COLORS["text_secondary"], anchor="w")
            info_lbl.pack(fill="x", pady=(2, 0))
            info_lbl.bind("<Button-1>", self._on_click)

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
        self.geometry("500x550")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self.configure(fg_color=COLORS["bg_primary"])

        # Center on parent
        self.update_idletasks()
        x = master.winfo_x() + (master.winfo_width() - 500) // 2
        y = master.winfo_y() + (master.winfo_height() - 550) // 2
        self.geometry(f"500x550+{x}+{y}")

        # Content
        ctk.CTkLabel(self, text="Export for Team Member", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(pady=(25, 8))
        ctk.CTkLabel(self, text=f"Exporting {len(selected_ids)} credential(s) to password-protected PDF",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 25))

        form = ctk.CTkFrame(self, fg_color="transparent")
        form.pack(fill="x", padx=40)

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
        btn_frame.pack(fill="x", padx=40, pady=(20, 30))

        ctk.CTkButton(btn_frame, text="Cancel", width=140, height=40, corner_radius=10,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=self.destroy).pack(side="left")
        ctk.CTkButton(btn_frame, text="Export PDF", width=160, height=40, corner_radius=10,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=self._do_export).pack(side="right")

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
        ClipboardManager.copy(pw, auto_clear=False)  # Don't auto-clear generated passwords
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
# IMPORT DIALOG
# ============================================================
class ImportDialog(ctk.CTkToplevel):
    """Dialog for importing credentials from a SecureVault-exported PDF."""

    def __init__(self, master, vault: Vault):
        super().__init__(master)
        self.vault = vault
        self.result = None
        self.parsed_credentials: List[dict] = []
        self.check_vars: List[ctk.BooleanVar] = []

        self.title("Import Credentials from PDF")
        self.geometry("600x700")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self.configure(fg_color=COLORS["bg_primary"])

        # Center on parent
        self.update_idletasks()
        x = master.winfo_x() + (master.winfo_width() - 600) // 2
        y = master.winfo_y() + (master.winfo_height() - 700) // 2
        self.geometry(f"600x700+{x}+{y}")

        # Header
        ctk.CTkLabel(self, text="Import Credentials from PDF", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(pady=(25, 8))
        ctk.CTkLabel(self, text="Import credentials from a SecureVault-exported PDF",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        # Step 1: File selection + password
        self.step1_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.step1_frame.pack(fill="x", padx=30)

        ctk.CTkLabel(self.step1_frame, text="Step 1: Select PDF File",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", pady=(0, 8))

        # File selection row
        file_row = ctk.CTkFrame(self.step1_frame, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, 8))

        self.file_path_var = ctk.StringVar(value="No file selected")
        ctk.CTkLabel(file_row, textvariable=self.file_path_var, font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_secondary"], anchor="w", wraplength=400).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(file_row, text="Select PDF", width=100, height=32, corner_radius=6,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=11),
                     command=self._select_file).pack(side="right")

        # Password
        ctk.CTkLabel(self.step1_frame, text="PDF Password", font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(4, 3))
        self.pw_entry = PwEntry(self.step1_frame, placeholder="Password used to encrypt the PDF")
        self.pw_entry.pack(fill="x", pady=(0, 10))

        # Parse button
        ctk.CTkButton(self.step1_frame, text="Parse PDF", width=120, height=36, corner_radius=8,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=self._parse_pdf).pack(anchor="w", pady=(0, 8))

        # Error label
        self.err_label = ctk.CTkLabel(self.step1_frame, text="", font=ctk.CTkFont(size=10),
                                      text_color=COLORS["danger"])
        self.err_label.pack(fill="x", pady=(0, 8))

        # Separator
        ctk.CTkFrame(self, fg_color=COLORS["border"], height=1).pack(fill="x", padx=30, pady=(4, 12))

        # Step 2: Preview (hidden until parse)
        self.step2_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.step2_frame.pack(fill="both", expand=True, padx=30)

        self.step2_header = ctk.CTkFrame(self.step2_frame, fg_color="transparent")
        self.step2_header.pack(fill="x")

        self.step2_title = ctk.CTkLabel(self.step2_header, text="Step 2: Review Credentials",
                                        font=ctk.CTkFont(size=13, weight="bold"),
                                        text_color=COLORS["text_primary"])
        self.step2_title.pack(side="left")

        self.count_label = ctk.CTkLabel(self.step2_header, text="",
                                        font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"])
        self.count_label.pack(side="right")

        # Select All / Deselect All buttons
        self.sel_btn_frame = ctk.CTkFrame(self.step2_frame, fg_color="transparent")
        self.sel_btn_frame.pack(fill="x", pady=(6, 6))

        ctk.CTkButton(self.sel_btn_frame, text="Select All", width=80, height=26, corner_radius=5,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=10),
                     command=self._select_all).pack(side="left", padx=(0, 6))
        ctk.CTkButton(self.sel_btn_frame, text="Deselect All", width=80, height=26, corner_radius=5,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=10),
                     command=self._deselect_all).pack(side="left")

        # Scrollable list of credentials
        self.cred_list = ctk.CTkScrollableFrame(self.step2_frame, fg_color="transparent")
        self.cred_list.pack(fill="both", expand=True, pady=(4, 8))

        # Step 3: Import button row
        self.step3_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.step3_frame.pack(fill="x", padx=30, pady=(0, 20))

        self.import_btn = ctk.CTkButton(self.step3_frame, text="Import 0 Selected", width=180, height=40,
                                        corner_radius=10, fg_color=COLORS["accent"],
                                        hover_color=COLORS["accent_hover"], text_color=COLORS["text_primary"],
                                        font=ctk.CTkFont(size=13, weight="bold"),
                                        command=self._do_import, state="disabled")
        self.import_btn.pack(side="right")

        ctk.CTkButton(self.step3_frame, text="Cancel", width=100, height=40, corner_radius=10,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=self.destroy).pack(side="left")

        # Holds selected PDF path
        self._pdf_path: str = ""

    def _select_file(self):
        from tkinter import filedialog
        filepath = filedialog.askopenfilename(
            parent=self,
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            title="Select SecureVault PDF Export"
        )
        if filepath:
            self._pdf_path = filepath
            # Show just the filename, not full path for cleanliness
            display = filepath if len(filepath) <= 60 else "..." + filepath[-57:]
            self.file_path_var.set(display)
            self.err_label.configure(text="", text_color=COLORS["danger"])

    def _parse_pdf(self):
        if not self._pdf_path:
            self.err_label.configure(text="Please select a PDF file first", text_color=COLORS["danger"])
            return

        password = self.pw_entry.get()
        if not password:
            self.err_label.configure(text="Please enter the PDF password", text_color=COLORS["danger"])
            return

        try:
            self.parsed_credentials = import_credentials_from_pdf(self._pdf_path, password)
        except ValueError as e:
            self.err_label.configure(text=str(e), text_color=COLORS["danger"])
            return
        except Exception as e:
            self.err_label.configure(text=f"Parse failed: {str(e)[:80]}", text_color=COLORS["danger"])
            return

        if not self.parsed_credentials:
            self.err_label.configure(text="No credentials found in the PDF", text_color=COLORS["danger"])
            return

        self.err_label.configure(text=f"Successfully parsed {len(self.parsed_credentials)} credential(s)",
                                 text_color=COLORS["success"])
        self._populate_credential_list()

    def _populate_credential_list(self):
        # Clear existing items
        for w in self.cred_list.winfo_children():
            w.destroy()
        self.check_vars.clear()

        self.count_label.configure(text=f"{len(self.parsed_credentials)} found")

        for i, cred in enumerate(self.parsed_credentials):
            var = ctk.BooleanVar(value=True)
            self.check_vars.append(var)

            row = ctk.CTkFrame(self.cred_list, fg_color=COLORS["bg_secondary"], corner_radius=8, height=48)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            # Checkbox
            chk = ctk.CTkCheckBox(row, text="", variable=var, width=22, corner_radius=4,
                                  fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                  command=self._update_import_count)
            chk.pack(side="left", padx=(10, 6))

            # Environment color bar
            env = cred.get("environment", "")
            ec = (COLORS["prod"] if env == "Production" else
                  COLORS["staging"] if env == "Staging" else
                  COLORS["dev"] if env == "Development" else COLORS["border"])
            ctk.CTkFrame(row, width=3, fg_color=ec, corner_radius=0).pack(side="left", fill="y")

            # Credential info
            info_frame = ctk.CTkFrame(row, fg_color="transparent")
            info_frame.pack(side="left", fill="both", expand=True, padx=8, pady=6)

            name_text = cred.get("name", "Unknown")
            ctk.CTkLabel(info_frame, text=name_text, font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=COLORS["text_primary"], anchor="w").pack(fill="x")

            detail_parts = []
            if cred.get("type"):
                detail_parts.append(cred["type"])
            if cred.get("environment"):
                detail_parts.append(cred["environment"])
            if cred.get("username"):
                detail_parts.append(cred["username"])
            detail_text = " | ".join(detail_parts) if detail_parts else "No details"

            ctk.CTkLabel(info_frame, text=detail_text[:60], font=ctk.CTkFont(size=9),
                        text_color=COLORS["text_tertiary"], anchor="w").pack(fill="x")

        self._update_import_count()

    def _update_import_count(self):
        selected = sum(1 for v in self.check_vars if v.get())
        self.import_btn.configure(text=f"Import {selected} Selected",
                                  state="normal" if selected > 0 else "disabled")

    def _select_all(self):
        for v in self.check_vars:
            v.set(True)
        self._update_import_count()
        self._populate_credential_list()

    def _deselect_all(self):
        for v in self.check_vars:
            v.set(False)
        self._update_import_count()
        self._populate_credential_list()

    def _do_import(self):
        selected_count = 0
        errors = []

        for i, cred in enumerate(self.parsed_credentials):
            if i < len(self.check_vars) and self.check_vars[i].get():
                try:
                    self.vault.add(
                        name=cred.get("name", "Imported"),
                        ctype=cred.get("type", "Other"),
                        host=cred.get("host", ""),
                        port=cred.get("port", ""),
                        user=cred.get("username", ""),
                        password=cred.get("password", ""),
                        env=cred.get("environment", ""),
                        proto=cred.get("protocol", ""),
                        tags=cred.get("tags", ""),
                        notes=cred.get("notes", ""),
                    )
                    selected_count += 1
                except Exception as e:
                    errors.append(f"{cred.get('name', '?')}: {str(e)[:40]}")

        if errors:
            self.err_label.configure(
                text=f"Imported {selected_count}, failed {len(errors)}: {errors[0]}",
                text_color=COLORS["warning"])
        else:
            self.result = selected_count
            self.destroy()

# ============================================================
# APP
# ============================================================
class ClipboardManager:
    """Manages clipboard with auto-clear functionality."""
    _instance = None
    _timer = None
    _last_copied = None

    @classmethod
    def copy(cls, text: str, auto_clear: bool = True):
        """Copy text to clipboard with optional auto-clear."""
        pyperclip.copy(text)
        cls._last_copied = text

        if auto_clear:
            # Cancel any existing timer
            if cls._timer:
                cls._timer.cancel()

            # Get clear time from settings
            clear_seconds = get_settings().get("clipboard_clear_seconds", DEFAULT_CLIPBOARD_CLEAR_SECONDS)
            if clear_seconds > 0:
                cls._timer = threading.Timer(clear_seconds, cls._clear_if_unchanged)
                cls._timer.daemon = True
                cls._timer.start()

    @classmethod
    def _clear_if_unchanged(cls):
        """Clear clipboard only if it still contains our copied text."""
        try:
            current = pyperclip.paste()
            if current == cls._last_copied:
                pyperclip.copy("")
                cls._last_copied = None
        except:
            pass

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KeyVault")
        self.geometry("980x680")
        self.minsize(880, 620)

        # Apply theme from settings
        settings = get_settings()
        theme = settings.get("theme", "dark")
        ctk.set_appearance_mode(theme)
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
        self.delete_mode = False
        self.selected_for_delete: Set[str] = set()
        self.current_sort = settings.get("sort_by", "name")
        self.sort_ascending = settings.get("sort_ascending", True)

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
        d.rounded_rectangle([16, 28, 48, 56], radius=4, fill=COLORS["accent"])
        d.arc([20, 12, 44, 36], 0, 180, fill=COLORS["accent"], width=6)

        menu = pystray.Menu(
            TrayItem("Open", self._tray_open, default=True),
            TrayItem("Quick Access", self._tray_popup),
            pystray.Menu.SEPARATOR,
            TrayItem("Start with Windows", self._toggle_startup, checked=lambda _: in_startup()),
            pystray.Menu.SEPARATOR,
            TrayItem("Lock", self._tray_lock),
            TrayItem("Quit", self._tray_quit))
        tray_settings = get_settings()
        tray_hk_first = tray_settings.get("hotkey_first", DEFAULT_HOTKEY_FIRST)
        tray_hk_second = tray_settings.get("hotkey_second", DEFAULT_HOTKEY_SECOND)
        tray_hk_display = f"{tray_hk_first}, {tray_hk_second}".upper()
        self.tray = pystray.Icon(APP_NAME, img, f"{APP_NAME}\n{tray_hk_display}", menu)
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

    @staticmethod
    def _load_logo(alpha_factor: float = 1.0):
        logo_path = Path(__file__).parent / "logo.png"
        if not logo_path.exists():
            return None
        img = Image.open(logo_path).convert("RGBA")
        datas = img.getdata()
        new_data = []
        for item in datas:
            if item[0] > 240 and item[1] > 240 and item[2] > 240:
                new_data.append((0, 0, 0, 0))
            else:
                if alpha_factor < 1.0:
                    new_data.append((item[0], item[1], item[2], int(item[3] * alpha_factor)))
                else:
                    new_data.append(item)
        img.putdata(new_data)
        return img

    def _clear(self):
        self.unbind("<Control-n>")
        self.unbind("<Control-f>")
        self.unbind("<Escape>")
        for w in self.winfo_children(): w.destroy()

    # ===== SETUP =====
    def _show_setup(self):
        self._clear()
        c = ctk.CTkFrame(self, fg_color="transparent")
        c.place(relx=0.5, rely=0.5, anchor="center")

        setup_logo = self._load_logo()
        if setup_logo:
            self._setup_logo = ctk.CTkImage(setup_logo, size=(200, 175))
            ctk.CTkLabel(c, image=self._setup_logo, text="").pack(pady=(0, 4))
        else:
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
        img = qr.make_image(fill_color=COLORS["text_primary"], back_color=COLORS["bg_primary"])
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

        login_logo = self._load_logo()
        if login_logo:
            self._login_logo = ctk.CTkImage(login_logo, size=(200, 175))
            ctk.CTkLabel(c, image=self._login_logo, text="").pack(pady=(0, 4))
        else:
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

        # Reset option if user forgot password
        ctk.CTkButton(f, text="Forgot password? Reset vault", width=360, height=28,
                     fg_color="transparent", hover_color=COLORS["bg_tertiary"],
                     text_color=COLORS["text_tertiary"], font=ctk.CTkFont(size=10),
                     command=self._confirm_reset).pack(fill="x", pady=(12, 0))
        self.bind("<Return>", lambda _: self._do_login())

    def _confirm_reset(self):
        """Show confirmation dialog to reset vault."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Reset Vault")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=COLORS["bg_primary"])
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 400) // 2
        y = self.winfo_y() + (self.winfo_height() - 200) // 2
        dialog.geometry(f"400x200+{x}+{y}")

        ctk.CTkLabel(dialog, text="Reset Vault?", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["danger"]).pack(pady=(20, 10))
        ctk.CTkLabel(dialog, text="This will DELETE all saved credentials!\nThis action cannot be undone.",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30)
        Btn(btn_frame, text="Cancel", primary=False, width=120, command=dialog.destroy).pack(side="left")
        Btn(btn_frame, text="Delete & Reset", danger=True, width=120,
            command=lambda: self._do_reset(dialog)).pack(side="right")

    def _do_reset(self, dialog):
        """Delete vault and show setup screen."""
        dialog.destroy()
        try:
            vault_path = get_vault_path()
            stats_path = get_stats_path()
            if vault_path.exists():
                vault_path.unlink()
            if stats_path.exists():
                stats_path.unlink()
        except Exception as e:
            self.l_err.configure(text=f"Reset failed: {e}")
            return
        self.vault = Vault()
        self._show_setup()

    def _do_login(self):
        success, error = self.vault.unlock(self.l_pw.get())
        if not success:
            self.l_err.configure(text=error)
            return
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
        logo_img = self._load_logo()
        if logo_img:
            self._sidebar_logo = ctk.CTkImage(logo_img, size=(160, 140))
            ctk.CTkLabel(hdr, image=self._sidebar_logo, text="").pack(anchor="w", pady=(0, 4))
        else:
            ctk.CTkLabel(hdr, text="SecureVault", font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["text_primary"]).pack(anchor="w")
        ver_row = ctk.CTkFrame(hdr, fg_color="transparent")
        ver_row.pack(fill="x")
        ctk.CTkLabel(ver_row, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(side="left")
        sidebar_count = len(self.vault.list_all()) if self.vault.unlocked else 0
        ctk.CTkLabel(ver_row, text=f"{sidebar_count} credentials", font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(side="right")

        hk = ctk.CTkFrame(sb, fg_color=COLORS["bg_tertiary"], corner_radius=5)
        hk.pack(fill="x", padx=10, pady=(0, 10))
        hotkey_first = settings.get("hotkey_first", DEFAULT_HOTKEY_FIRST)
        hotkey_second = settings.get("hotkey_second", DEFAULT_HOTKEY_SECOND)
        hotkey_display = f"{hotkey_first}, {hotkey_second}".upper()
        self._hotkey_label = ctk.CTkLabel(hk, text=f"HOTKEY: {hotkey_display}", font=ctk.CTkFont(size=11, weight="bold"), text_color=COLORS["accent"])
        self._hotkey_label.pack(pady=5)

        nav = ctk.CTkFrame(sb, fg_color="transparent")
        nav.pack(fill="x", padx=8, pady=4)
        for txt, cmd in [("🔑  All Credentials", self._view_all), ("🕐  Recent", self._view_recent),
                         ("📂  By Environment", self._view_env), ("📤  Export to PDF", self._view_export),
                         ("📥  Import from PDF", self._view_import),
                         ("🎲  Generate Password", self._view_gen), ("⚙️  Settings", self._view_settings)]:
            ctk.CTkButton(nav, text=txt, height=32, corner_radius=6, fg_color="transparent", hover_color=COLORS["bg_tertiary"],
                         text_color=COLORS["text_primary"], anchor="w", font=ctk.CTkFont(size=12), command=cmd).pack(fill="x", pady=1)

        ctk.CTkFrame(sb, fg_color="transparent").pack(fill="both", expand=True)

        bot = ctk.CTkFrame(sb, fg_color="transparent")
        bot.pack(fill="x", padx=8, pady=14)
        ctk.CTkButton(bot, text="⬇️  Minimize to Tray", height=32, corner_radius=6, fg_color=COLORS["bg_tertiary"],
                     hover_color=COLORS["border"], font=ctk.CTkFont(size=11), anchor="w", command=self.withdraw).pack(fill="x", pady=(0, 5))
        ctk.CTkButton(bot, text="🔒  Lock", height=32, corner_radius=6, fg_color=COLORS["danger"],
                     hover_color=COLORS["danger_hover"], font=ctk.CTkFont(size=11), anchor="w", command=self._lock).pack(fill="x")

        self.content = ctk.CTkFrame(self, fg_color=COLORS["bg_primary"], corner_radius=0)
        self.content.pack(side="right", fill="both", expand=True)
        self._view_all()

        # Keyboard shortcuts
        self.bind("<Control-n>", lambda _: self._view_add())
        self.bind("<Control-f>", lambda _: self.search.focus_set() if hasattr(self, 'search') else None)
        self.bind("<Escape>", lambda _: self._view_all())

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
        total_count = len(self.vault.list_all())
        ctk.CTkLabel(hdr, text=f"({total_count})", font=ctk.CTkFont(size=13), text_color=COLORS["text_tertiary"]).pack(side="left", padx=(8, 0))

        # Right-side buttons: Delete | Add | Star (packed right-to-left so star first)
        if self.delete_mode:
            Btn(hdr, text="Cancel", primary=False, width=80, command=self._cancel_delete_mode).pack(side="right")
            self.delete_sel_btn = Btn(hdr, text="Delete Selected (0)", danger=True, width=160, command=self._do_batch_delete)
            self.delete_sel_btn.pack(side="right", padx=(0, 9))
            Btn(hdr, text="Select All", primary=False, width=90, command=self._select_all_for_delete).pack(side="right", padx=(0, 9))
        else:
            # Star button
            ctk.CTkButton(hdr, text="\u2605", width=38, height=38, corner_radius=6,
                         fg_color=COLORS["warning"] if hasattr(self, '_show_favorites_only') and self._show_favorites_only else COLORS["bg_tertiary"],
                         hover_color=COLORS["warning"], font=ctk.CTkFont(size=14),
                         command=self._toggle_favorites_filter).pack(side="right")
            # Add button
            Btn(hdr, text="+ Add", width=100, command=self._view_add).pack(side="right", padx=(0, 9))
            # Delete button
            Btn(hdr, text="Delete", danger=True, width=80, command=self._enter_delete_mode).pack(side="right", padx=(0, 9))

        # Show expiry warnings if any
        expiring = self.vault.get_expiring_passwords()
        if expiring:
            warn_frame = ctk.CTkFrame(self.content, fg_color=COLORS["warning"], corner_radius=8)
            warn_frame.pack(fill="x", padx=20, pady=(0, 10))
            warn_inner = ctk.CTkFrame(warn_frame, fg_color="transparent")
            warn_inner.pack(fill="x", padx=12, pady=8)
            ctk.CTkLabel(warn_inner, text=f"⚠️ {len(expiring)} password(s) expiring soon or expired",
                        font=ctk.CTkFont(size=11, weight="bold"), text_color=COLORS["warning_text"]).pack(side="left")
            ctk.CTkButton(warn_inner, text="View", width=60, height=24, corner_radius=6,
                         fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"], text_color=COLORS["text_primary"],
                         font=ctk.CTkFont(size=10), command=self._view_expiring).pack(side="right")

        flt = ctk.CTkFrame(self.content, fg_color="transparent")
        flt.pack(fill="x", padx=20, pady=(0, 12))
        self.search = Entry(flt, placeholder="Search...", textvariable=self.search_var, width=280)
        self.search.pack(side="left")
        self.env_flt = ctk.CTkComboBox(flt, values=["All"] + ENVIRONMENTS, width=110, height=38, corner_radius=6,
                                       border_width=1, border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11), command=lambda _: self._refresh_list())
        self.env_flt.set("All")
        self.env_flt.pack(side="left", padx=(8, 0))

        # Sort options
        self.sort_combo = ctk.CTkComboBox(flt, values=["Name", "Date Modified", "Usage", "Environment"], width=120, height=38,
                                          corner_radius=6, border_width=1, border_color=COLORS["border"],
                                          fg_color=COLORS["bg_tertiary"], dropdown_fg_color=COLORS["bg_secondary"],
                                          font=ctk.CTkFont(size=11), command=self._on_sort_change)
        sort_display = {"name": "Name", "date": "Date Modified", "usage": "Usage", "environment": "Environment"}
        self.sort_combo.set(sort_display.get(self.current_sort, "Name"))
        self.sort_combo.pack(side="left", padx=(8, 0))

        # Wrapper for list + watermark logo
        list_wrapper = ctk.CTkFrame(self.content, fg_color="transparent")
        list_wrapper.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        wm_img = self._load_logo(alpha_factor=0.07)
        if wm_img:
            self._home_watermark = ctk.CTkImage(wm_img, size=(300, 260))
            ctk.CTkLabel(list_wrapper, image=self._home_watermark, text="").place(relx=0.5, rely=0.5, anchor="center")

        self.lst = ctk.CTkScrollableFrame(list_wrapper, fg_color="transparent")
        self.lst.pack(fill="both", expand=True)
        self._refresh_list()

    def _on_sort_change(self, value):
        sort_map = {"Name": "name", "Date Modified": "date", "Usage": "usage", "Environment": "environment"}
        self.current_sort = sort_map.get(value, "name")
        get_settings().set("sort_by", self.current_sort)
        self.vault._invalidate_cache()
        self._refresh_list()

    def _toggle_favorites_filter(self):
        if not hasattr(self, '_show_favorites_only'):
            self._show_favorites_only = False
        self._show_favorites_only = not self._show_favorites_only
        self._view_all()

    def _view_expiring(self):
        """Show credentials with expiring passwords."""
        for w in self.content.winfo_children(): w.destroy()

        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkButton(hdr, text="< Back", width=70, height=28, corner_radius=5, fg_color="transparent",
                     hover_color=COLORS["bg_tertiary"], text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=11), command=self._view_all).pack(side="left")
        ctk.CTkLabel(hdr, text="Expiring Passwords", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(side="left", padx=14)

        ctk.CTkLabel(self.content, text="Passwords older than 90 days should be rotated for security.",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(0, 12))

        lst = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        lst.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        expiring = self.vault.get_expiring_passwords()
        for e in expiring:
            card = Card(lst, e, self._view_detail, self._quick_copy, show_expiry=True)
            card.pack(fill="x", pady=2)

    def _refresh_list(self):
        if not hasattr(self, "lst"): return
        for w in self.lst.winfo_children(): w.destroy()
        items = self.vault.list_all(sort_by=self.current_sort, ascending=self.sort_ascending)
        q = self.search_var.get().lower()
        env = self.env_flt.get() if hasattr(self, "env_flt") else "All"

        # Apply favorites filter
        if hasattr(self, '_show_favorites_only') and self._show_favorites_only:
            items = [e for e in items if e.get("is_favorite")]

        if q:
            items = [e for e in items if q in e["name"].lower() or q in e.get("host", "").lower() or
                    q in e.get("username", "").lower() or q in e.get("tags", "").lower()]
        if env != "All":
            items = [e for e in items if e.get("environment") == env]
        if not items:
            msg = "No favorites yet" if hasattr(self, '_show_favorites_only') and self._show_favorites_only else "No credentials"
            ctk.CTkLabel(self.lst, text=msg, font=ctk.CTkFont(size=12), text_color=COLORS["text_tertiary"]).pack(pady=30)
            return
        for e in items:
            if self.export_mode:
                Card(self.lst, e, self._view_detail, self._quick_copy,
                     selectable=True, selected=e["id"] in self.selected_for_export,
                     on_select=self._toggle_export_selection, on_favorite=self._toggle_favorite).pack(fill="x", pady=2)
            elif self.delete_mode:
                Card(self.lst, e, self._view_detail, self._quick_copy,
                     selectable=True, selected=e["id"] in self.selected_for_delete,
                     on_select=self._toggle_delete_selection).pack(fill="x", pady=2)
            else:
                Card(self.lst, e, self._view_detail, self._quick_copy, on_favorite=self._toggle_favorite).pack(fill="x", pady=2)

    def _toggle_favorite(self, eid: str):
        self.vault.toggle_favorite(eid)
        self._refresh_list()

    def _enter_delete_mode(self):
        self.delete_mode = True
        self.selected_for_delete.clear()
        self._view_all()

    def _cancel_delete_mode(self):
        self.delete_mode = False
        self.selected_for_delete.clear()
        self._view_all()

    def _toggle_delete_selection(self, eid: str, selected: bool):
        if selected:
            self.selected_for_delete.add(eid)
        else:
            self.selected_for_delete.discard(eid)
        if hasattr(self, 'delete_sel_btn'):
            self.delete_sel_btn.configure(text=f"Delete Selected ({len(self.selected_for_delete)})")

    def _select_all_for_delete(self):
        items = self.vault.list_all(sort_by=self.current_sort, ascending=self.sort_ascending)
        q = self.search_var.get().lower()
        env = self.env_flt.get() if hasattr(self, "env_flt") else "All"
        if hasattr(self, '_show_favorites_only') and self._show_favorites_only:
            items = [e for e in items if e.get("is_favorite")]
        if q:
            items = [e for e in items if q in e["name"].lower() or q in e.get("host", "").lower() or
                    q in e.get("username", "").lower() or q in e.get("tags", "").lower()]
        if env != "All":
            items = [e for e in items if e.get("environment") == env]
        self.selected_for_delete = {e["id"] for e in items}
        self._refresh_list()
        if hasattr(self, 'delete_sel_btn'):
            self.delete_sel_btn.configure(text=f"Delete Selected ({len(self.selected_for_delete)})")

    def _do_batch_delete(self):
        if not self.selected_for_delete:
            return
        count = len(self.selected_for_delete)
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirm Delete")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=COLORS["bg_primary"])
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 400) // 2
        y = self.winfo_y() + (self.winfo_height() - 200) // 2
        dialog.geometry(f"400x200+{x}+{y}")

        ctk.CTkLabel(dialog, text=f"Delete {count} Credential(s)?", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["danger"]).pack(pady=(20, 10))
        ctk.CTkLabel(dialog, text="This action cannot be undone.\nAll selected credentials will be permanently deleted.",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30)

        def confirm():
            dialog.destroy()
            for eid in list(self.selected_for_delete):
                self.vault.delete(eid)
            self.selected_for_delete.clear()
            self.delete_mode = False
            self._view_all()

        Btn(btn_frame, text="Cancel", primary=False, width=120, command=dialog.destroy).pack(side="left")
        Btn(btn_frame, text=f"Delete {count}", danger=True, width=120, command=confirm).pack(side="right")

    def _confirm_delete_single(self, e: dict):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirm Delete")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=COLORS["bg_primary"])
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 400) // 2
        y = self.winfo_y() + (self.winfo_height() - 200) // 2
        dialog.geometry(f"400x200+{x}+{y}")

        ctk.CTkLabel(dialog, text=f"Delete \"{e['name']}\"?", font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=COLORS["danger"]).pack(pady=(20, 10))
        ctk.CTkLabel(dialog, text="This action cannot be undone.\nThis credential will be permanently deleted.",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 20))

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30)

        def confirm():
            dialog.destroy()
            self.vault.delete(e["id"])
            self._view_all()

        Btn(btn_frame, text="Cancel", primary=False, width=120, command=dialog.destroy).pack(side="left")
        Btn(btn_frame, text="Delete", danger=True, width=120, command=confirm).pack(side="right")

    def _toggle_export_selection(self, eid: str, selected: bool):
        if selected:
            self.selected_for_export.add(eid)
        else:
            self.selected_for_export.discard(eid)
        # Update export button text
        if hasattr(self, 'export_btn'):
            self.export_btn.configure(text=f"Export {len(self.selected_for_export)} Selected")

    def _quick_copy(self, e: dict):
        ClipboardManager.copy(self.vault.get_password(e["id"]))

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

        hdr = ctk.CTkFrame(self.content, fg_color="transparent", height=50)
        hdr.pack(fill="x", padx=20, pady=(20, 14))
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="Export to PDF", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(side="left", pady=8)

        # Buttons frame on right side
        btn_row = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_row.pack(side="right", pady=4)

        self.export_btn = ctk.CTkButton(btn_row, text="Export 0 Selected", width=180, height=40, corner_radius=8,
                                        fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                        text_color=COLORS["text_primary"], font=ctk.CTkFont(size=13, weight="bold"),
                                        command=self._do_export)
        self.export_btn.pack(side="left", padx=(0, 10))
        Btn(btn_row, text="Cancel", primary=False, width=80, command=self._view_all).pack(side="left")

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

    def _view_import(self):
        """Import view - import credentials from a SecureVault-exported PDF."""
        for w in self.content.winfo_children(): w.destroy()

        ctk.CTkLabel(self.content, text="Import from PDF", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 8))
        ctk.CTkLabel(self.content, text="Import credentials from a password-protected SecureVault PDF export",
                    font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=20, pady=(0, 14))

        if not _load_pdf_modules():
            # Show error when PDF modules are not available
            err_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_secondary"], corner_radius=10)
            err_frame.pack(fill="x", padx=20, pady=10)
            ctk.CTkLabel(err_frame, text="PDF Import requires additional packages.\n\nPlease run:\npip install PyPDF2",
                        font=ctk.CTkFont(size=12), text_color=COLORS["text_primary"]).pack(pady=30, padx=20)
            return

        dialog = ImportDialog(self, self.vault)
        self.wait_window(dialog)

        if dialog.result:
            # Show success message
            count = dialog.result
            success_dialog = ctk.CTkToplevel(self)
            success_dialog.title("Import Complete")
            success_dialog.geometry("400x180")
            success_dialog.transient(self)
            success_dialog.grab_set()
            success_dialog.configure(fg_color=COLORS["bg_primary"])

            ctk.CTkLabel(success_dialog, text="Import Successful!",
                        font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["success"]).pack(pady=(20, 10))
            ctk.CTkLabel(success_dialog, text=f"Imported {count} credential(s) into your vault",
                        font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(pady=(0, 10))
            ctk.CTkLabel(success_dialog, text="Review imported credentials in All Credentials",
                        font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(pady=(0, 15))
            Btn(success_dialog, text="OK", width=80,
                command=lambda: (success_dialog.destroy(), self._view_all())).pack()
        else:
            # User cancelled or no import - go back to all credentials
            self._view_all()

    def _view_detail(self, e: dict):
        for w in self.content.winfo_children(): w.destroy()

        # Header with back button and actions
        hdr = ctk.CTkFrame(self.content, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkButton(hdr, text="< Back", width=70, height=32, corner_radius=8, fg_color="transparent",
                     hover_color=COLORS["bg_tertiary"], text_color=COLORS["text_secondary"],
                     font=ctk.CTkFont(size=12), command=self._view_all).pack(side="left")
        ctk.CTkButton(hdr, text="Delete", width=80, height=36, corner_radius=8,
                     fg_color=COLORS["danger"], hover_color=COLORS["danger_hover"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=lambda: self._confirm_delete_single(e)).pack(side="right")
        ctk.CTkButton(hdr, text="Edit", width=70, height=36, corner_radius=8,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=lambda: self._view_edit(e)).pack(side="right", padx=(0, 8))
        ctk.CTkButton(hdr, text="Auto-fill", width=80, height=36, corner_radius=8,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     text_color=COLORS["text_primary"], font=ctk.CTkFont(size=12, weight="bold"),
                     command=lambda: self._detail_autofill(e)).pack(side="right", padx=(0, 8))

        cnt = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        # Title with environment badge
        title_row = ctk.CTkFrame(cnt, fg_color="transparent")
        title_row.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(title_row, text=e["name"], font=ctk.CTkFont(size=24, weight="bold"),
                    text_color=COLORS["text_primary"], anchor="w").pack(side="left")
        env = e.get("environment", "")
        if env:
            ec = COLORS["prod"] if env == "Production" else COLORS["staging"] if env == "Staging" else COLORS["dev"] if env == "Development" else COLORS["text_tertiary"]
            ctk.CTkLabel(title_row, text=env, font=ctk.CTkFont(size=10, weight="bold"),
                        text_color=ec, fg_color=COLORS["bg_tertiary"], corner_radius=6,
                        width=70, height=22).pack(side="left", padx=(12, 0))

        # Show expiry warning if applicable
        is_exp, days, exp_msg = is_password_expiring(e.get("modified", ""))
        if is_exp:
            exp_frame = ctk.CTkFrame(cnt, fg_color=COLORS["warning"], corner_radius=8)
            exp_frame.pack(fill="x", pady=(0, 12))
            exp_color = COLORS["danger"] if days <= 0 else COLORS["warning"]
            ctk.CTkLabel(exp_frame, text=f"⚠️ Password {exp_msg} - consider rotating",
                        font=ctk.CTkFont(size=11, weight="bold"), text_color=COLORS["warning_text"]).pack(padx=12, pady=8)

        pw = self.vault.get_password(e["id"])
        fields = [("Type", e.get("type")), ("Host", e.get("host")), ("Port", e.get("port")),
                  ("Username", e.get("username"), True), ("Password", pw, True, True),
                  ("Protocol", e.get("protocol")), ("Tags", e.get("tags")), ("Notes", e.get("notes"))]
        for item in fields:
            val = item[1]
            if not val: continue
            copy = len(item) > 2 and item[2]
            hide = len(item) > 3 and item[3]
            self._field(cnt, item[0], val, copy, hide)

        # SSH Key section
        ssh_key = self.vault.get_ssh_key(e["id"])
        if ssh_key:
            self._field(cnt, "SSH Key", ssh_key, True, True)

        # Stats
        stats_frame = ctk.CTkFrame(cnt, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(16, 0))
        if e.get("use_count"):
            ctk.CTkLabel(stats_frame, text=f"Used {e['use_count']} times", font=ctk.CTkFont(size=11),
                        text_color=COLORS["text_tertiary"]).pack(side="left")
        age_days = get_password_age_days(e.get("modified", ""))
        ctk.CTkLabel(stats_frame, text=f"Password age: {age_days} days", font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_tertiary"]).pack(side="right")

    def _detail_autofill(self, e: dict):
        """Auto-fill from detail view: minimize window, type username+Tab+password."""
        user = e.get("username", "")
        pw = self.vault.get_password(e["id"])
        self.iconify()
        time.sleep(0.5)
        if user:
            QuickPopup._safe_type(user)
            pyautogui.press("tab")
            time.sleep(0.05)
        QuickPopup._safe_type(pw)

    def _field(self, parent, label: str, val: str, copy: bool = False, hide: bool = False):
        # Check if multiline (for SSH keys)
        is_multiline = "\n" in val or len(val) > 100

        if is_multiline:
            # Multiline field (expandable)
            fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=10)
            fr.pack(fill="x", pady=4)

            header = ctk.CTkFrame(fr, fg_color="transparent")
            header.pack(fill="x", padx=16, pady=(10, 0))
            ctk.CTkLabel(header, text=label, font=ctk.CTkFont(size=11), text_color=COLORS["text_tertiary"], anchor="w").pack(side="left")

            # Buttons
            if copy:
                def do_copy():
                    ClipboardManager.copy(val)
                    cb.configure(text="Copied!")
                    self.after(1000, lambda: cb.configure(text="Copy"))
                cb = ctk.CTkButton(header, text="Copy", width=60, height=28, corner_radius=6,
                                  fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                  font=ctk.CTkFont(size=10), command=do_copy)
                cb.pack(side="right", padx=(6, 0))

            if hide:
                show_var = [False]
                text_widget = ctk.CTkTextbox(fr, height=80, corner_radius=6, border_width=0,
                                             fg_color=COLORS["bg_tertiary"], text_color=COLORS["text_primary"],
                                             font=ctk.CTkFont(size=11, family="Consolas"), state="disabled")
                text_widget.pack(fill="x", padx=16, pady=(8, 10))

                def toggle():
                    show_var[0] = not show_var[0]
                    text_widget.configure(state="normal")
                    text_widget.delete("1.0", "end")
                    text_widget.insert("1.0", val if show_var[0] else "*" * 20 + "\n(hidden)")
                    text_widget.configure(state="disabled")
                    tb.configure(text="Hide" if show_var[0] else "Show")

                tb = ctk.CTkButton(header, text="Show", width=60, height=28, corner_radius=6,
                                  fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                                  font=ctk.CTkFont(size=10), command=toggle)
                tb.pack(side="right")
                toggle()  # Initialize hidden
            else:
                text_widget = ctk.CTkTextbox(fr, height=80, corner_radius=6, border_width=0,
                                             fg_color=COLORS["bg_tertiary"], text_color=COLORS["text_primary"],
                                             font=ctk.CTkFont(size=11, family="Consolas"), state="disabled")
                text_widget.pack(fill="x", padx=16, pady=(8, 10))
                text_widget.configure(state="normal")
                text_widget.insert("1.0", val)
                text_widget.configure(state="disabled")
        else:
            # Single line field
            fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=10, height=60)
            fr.pack(fill="x", pady=4)
            fr.pack_propagate(False)

            # Left side - label and value
            left = ctk.CTkFrame(fr, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=16, pady=10)

            ctk.CTkLabel(left, text=label, font=ctk.CTkFont(size=11), text_color=COLORS["text_tertiary"], anchor="w").pack(fill="x")

            disp = "*" * 16 if hide else (val[:50] + "..." if len(val) > 50 else val)
            var = ctk.StringVar(value=disp)
            ctk.CTkLabel(left, textvariable=var, font=ctk.CTkFont(size=14, family="Consolas" if hide or label in ["Host", "Port", "Username"] else None),
                        text_color=COLORS["text_primary"], anchor="w").pack(fill="x")

            # Right side - buttons
            right = ctk.CTkFrame(fr, fg_color="transparent")
            right.pack(side="right", padx=12, pady=10)

            if copy:
                def do_copy():
                    ClipboardManager.copy(val)
                    cb.configure(text="Copied!")
                    self.after(1000, lambda: cb.configure(text="Copy"))
                cb = ctk.CTkButton(right, text="Copy", width=60, height=32, corner_radius=8,
                                  fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                  font=ctk.CTkFont(size=11), command=do_copy)
                cb.pack(side="right", padx=(6, 0))

            if hide:
                show = [False]
                def toggle():
                    show[0] = not show[0]
                    var.set(val if show[0] else "*" * 16)
                    tb.configure(text="Hide" if show[0] else "Show")
                tb = ctk.CTkButton(right, text="Show", width=60, height=32, corner_radius=8,
                                  fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                                  font=ctk.CTkFont(size=11), command=toggle)
                tb.pack(side="right")

    def _on_type_selected(self, selected_type: str):
        defaults = get_category_defaults(selected_type)
        if hasattr(self, 'a_proto') and not self.a_proto.get().strip():
            self.a_proto.set(defaults.get("proto", ""))
        if hasattr(self, 'a_port') and not self.a_port.get().strip():
            self.a_port.delete(0, "end")
            self.a_port.insert(0, defaults.get("port", ""))

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

        ctk.CTkLabel(frm, text="Type", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(9, 2))
        self.a_type = ctk.CTkComboBox(frm, values=CREDENTIAL_TYPES, height=38, corner_radius=6, border_width=1,
                                      border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                      dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11),
                                      command=self._on_type_selected)
        self.a_type.pack(fill="x")
        self.a_type.set(CREDENTIAL_TYPES[0])

        # Host and Port row - labels first
        lbl_row = ctk.CTkFrame(frm, fg_color="transparent")
        lbl_row.pack(fill="x", pady=(9, 2))
        ctk.CTkLabel(lbl_row, text="Host / IP", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(lbl_row, text="Port", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w", width=90).pack(side="right", padx=(8, 0))

        # Host and Port row - inputs
        input_row = ctk.CTkFrame(frm, fg_color="transparent")
        input_row.pack(fill="x")
        self.a_host = Entry(input_row, placeholder="192.168.1.1 or hostname")
        self.a_host.pack(side="left", fill="x", expand=True)
        self.a_port = Entry(input_row, placeholder="22", width=90)
        self.a_port.pack(side="right", padx=(8, 0))

        self._input(frm, "Username / Access Key", "a_user", "root, admin, AKIA...")

        ctk.CTkLabel(frm, text="Password / Secret", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(9, 2))
        prow = ctk.CTkFrame(frm, fg_color="transparent")
        prow.pack(fill="x")
        self.a_pw = PwEntry(prow)
        self.a_pw.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(prow, text="Generate", width=75, height=38, corner_radius=6, fg_color=COLORS["accent"],
                     hover_color=COLORS["accent_hover"], font=ctk.CTkFont(size=10),
                     command=lambda: (self.a_pw.delete(0, "end"), self.a_pw.insert(0, generate_password()))).pack(side="right", padx=(4, 0))
        def _copy_add_pw():
            val = self.a_pw.get()
            if val:
                ClipboardManager.copy(val)
                _copy_btn_a.configure(text="Copied!")
                self.after(1000, lambda: _copy_btn_a.configure(text="Copy"))
        _copy_btn_a = ctk.CTkButton(prow, text="Copy", width=55, height=38, corner_radius=6,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     font=ctk.CTkFont(size=10), command=_copy_add_pw)
        _copy_btn_a.pack(side="right", padx=(4, 0))

        row2 = ctk.CTkFrame(frm, fg_color="transparent")
        row2.pack(fill="x", pady=(9, 0))
        ef = ctk.CTkFrame(row2, fg_color="transparent")
        ef.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(ef, text="Environment", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 2))
        self.a_env = ctk.CTkComboBox(ef, values=ENVIRONMENTS, height=38, corner_radius=6, border_width=1,
                                     border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                     dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.a_env.pack(fill="x")
        self.a_env.set("Development")
        prf = ctk.CTkFrame(row2, fg_color="transparent")
        prf.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(prf, text="Protocol", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(0, 2))
        self.a_proto = ctk.CTkComboBox(prf, values=PROTOCOLS, height=38, corner_radius=6, border_width=1,
                                       border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                       dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11))
        self.a_proto.pack(fill="x")
        self.a_proto.set("SSH")

        self._input(frm, "Tags (comma separated)", "a_tags", "linux, mysql, us-east, team-backend")

        # Checkboxes row - SSH Key and Notes side by side
        self._a_ssh_visible = ctk.BooleanVar(value=False)
        self._a_notes_visible = ctk.BooleanVar(value=False)
        cb_row = ctk.CTkFrame(frm, fg_color="transparent")
        cb_row.pack(fill="x", pady=(9, 0))
        ctk.CTkCheckBox(cb_row, text="Include SSH Private Key",
                        variable=self._a_ssh_visible,
                        command=lambda: self._toggle_ssh(self._a_ssh_visible, self._a_ssh_inner),
                        font=ctk.CTkFont(size=10, weight="bold"), text_color=COLORS["text_secondary"],
                        fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                        border_color=COLORS["border"], checkmark_color=COLORS["text_primary"]).pack(side="left")
        ctk.CTkCheckBox(cb_row, text="Include Notes",
                        variable=self._a_notes_visible,
                        command=lambda: self._toggle_ssh(self._a_notes_visible, self._a_notes_inner),
                        font=ctk.CTkFont(size=10, weight="bold"), text_color=COLORS["text_secondary"],
                        fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                        border_color=COLORS["border"], checkmark_color=COLORS["text_primary"]).pack(side="left", padx=(14, 0))

        # SSH Key expandable
        self._a_ssh_inner = ctk.CTkFrame(frm, fg_color=COLORS["bg_secondary"], corner_radius=8)
        self.a_ssh_key = ctk.CTkTextbox(self._a_ssh_inner, height=80, corner_radius=6, border_width=1,
                                        border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                        text_color=COLORS["text_primary"],
                                        font=ctk.CTkFont(size=10, family="Consolas"))
        self.a_ssh_key.pack(fill="x", padx=10, pady=9)

        # Notes expandable
        self._a_notes_inner = ctk.CTkFrame(frm, fg_color=COLORS["bg_secondary"], corner_radius=8)
        self.a_notes = ctk.CTkTextbox(self._a_notes_inner, height=60, corner_radius=6, border_width=1,
                                      border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                      text_color=COLORS["text_primary"], font=ctk.CTkFont(size=11))
        self.a_notes.pack(fill="x", padx=10, pady=9)

        self.a_err = ctk.CTkLabel(frm, text="", font=ctk.CTkFont(size=10), text_color=COLORS["danger"])
        self.a_err.pack(fill="x", pady=(6, 0))

        Btn(frm, text="Save", command=self._do_add).pack(fill="x", pady=(6, 16))

    def _input(self, parent, label: str, attr: str, placeholder: str):
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(9, 2))
        e = Entry(parent, placeholder=placeholder)
        e.pack(fill="x")
        setattr(self, attr, e)

    def _do_add(self):
        name = self.a_name.get().strip()
        pw = self.a_pw.get()
        if not name: self.a_err.configure(text="Name required"); return
        if not pw: self.a_err.configure(text="Password required"); return
        ssh_key = self.a_ssh_key.get("1.0", "end").strip() if hasattr(self, 'a_ssh_key') else ""
        self.vault.add(name, self.a_type.get(), self.a_host.get().strip(), self.a_port.get().strip(),
                      self.a_user.get().strip(), pw, self.a_env.get(), self.a_proto.get(),
                      self.a_tags.get().strip(), self.a_notes.get("1.0", "end").strip(), ssh_key)
        self._view_all()

    def _toggle_ssh(self, var: ctk.BooleanVar, inner_frame: ctk.CTkFrame):
        if var.get():
            inner_frame.pack(fill="x", pady=(4, 0))
        else:
            inner_frame.pack_forget()

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

        # Host and Port row - labels first
        lbl_row = ctk.CTkFrame(frm, fg_color="transparent")
        lbl_row.pack(fill="x", pady=(9, 2))
        ctk.CTkLabel(lbl_row, text="Host / IP", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(lbl_row, text="Port", font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w", width=90).pack(side="right", padx=(8, 0))

        # Host and Port row - inputs
        input_row = ctk.CTkFrame(frm, fg_color="transparent")
        input_row.pack(fill="x")
        self.e_host = Entry(input_row)
        self.e_host.pack(side="left", fill="x", expand=True)
        self.e_host.insert(0, e.get("host", ""))
        self.e_port = Entry(input_row, width=90)
        self.e_port.pack(side="right", padx=(8, 0))
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

        # SSH Key (collapsible checkbox toggle)
        existing_ssh = self.vault.get_ssh_key(e["id"])
        self._e_ssh_visible = ctk.BooleanVar(value=bool(existing_ssh))
        ssh_wrapper = ctk.CTkFrame(frm, fg_color="transparent")
        ssh_wrapper.pack(fill="x", pady=(10, 0))
        ctk.CTkCheckBox(ssh_wrapper, text="Include SSH Private Key",
                        variable=self._e_ssh_visible,
                        command=lambda: self._toggle_ssh(self._e_ssh_visible, self._e_ssh_inner),
                        font=ctk.CTkFont(size=10, weight="bold"), text_color=COLORS["text_secondary"],
                        fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                        border_color=COLORS["border"], checkmark_color=COLORS["text_primary"]).pack(anchor="w")
        self._e_ssh_inner = ctk.CTkFrame(ssh_wrapper, fg_color=COLORS["bg_secondary"], corner_radius=8)
        self.e_ssh_key = ctk.CTkTextbox(self._e_ssh_inner, height=80, corner_radius=6, border_width=1,
                                        border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                                        text_color=COLORS["text_primary"],
                                        font=ctk.CTkFont(size=10, family="Consolas"))
        self.e_ssh_key.pack(fill="x", padx=10, pady=10)
        if existing_ssh:
            self.e_ssh_key.insert("1.0", existing_ssh)
            self._e_ssh_inner.pack(fill="x", pady=(4, 0))

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
        ssh_key = self.e_ssh_key.get("1.0", "end").strip() if hasattr(self, 'e_ssh_key') else ""
        self.vault.update(self.edit_id, name=name, type=self.e_type.get(), host=self.e_host.get().strip(),
                         port=self.e_port.get().strip(), username=self.e_user.get().strip(), password=pw,
                         environment=self.e_env.get(), protocol=self.e_proto.get(),
                         tags=self.e_tags.get().strip(), notes=self.e_notes.get("1.0", "end").strip(),
                         ssh_key=ssh_key)
        e = next((x for x in self.vault.list_all() if x["id"] == self.edit_id), None)
        if e: self._view_detail(e)
        else: self._view_all()

    # ===== GENERATOR =====
    def _view_gen(self):
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="Password Generator", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=24, pady=(24, 16))

        cnt = ctk.CTkFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        # Generated password display - modern card style
        self.gen_var = ctk.StringVar(value=generate_password())
        pf = ctk.CTkFrame(cnt, fg_color=COLORS["bg_secondary"], corner_radius=12)
        pf.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(pf, textvariable=self.gen_var, font=ctk.CTkFont(size=15, family="Consolas"),
                    text_color=COLORS["text_primary"], wraplength=500).pack(pady=16, padx=16)

        # Security strength indicator - modern tag style
        str_frame = ctk.CTkFrame(cnt, fg_color=COLORS["bg_secondary"], corner_radius=10)
        str_frame.pack(fill="x", pady=(0, 16))

        str_inner = ctk.CTkFrame(str_frame, fg_color="transparent")
        str_inner.pack(fill="x", padx=16, pady=12)

        self.str_badge = ctk.CTkLabel(str_inner, text="EXCELLENT", font=ctk.CTkFont(size=10, weight="bold"),
                                      fg_color=COLORS["success"], corner_radius=6, width=80, height=22)
        self.str_badge.pack(side="left")

        self.str_pct = ctk.CTkLabel(str_inner, text="100%", font=ctk.CTkFont(size=18, weight="bold"),
                                    text_color=COLORS["success"])
        self.str_pct.pack(side="left", padx=(12, 0))

        self.str_detail = ctk.CTkLabel(str_inner, text="Maximum security", font=ctk.CTkFont(size=10),
                                       text_color=COLORS["text_tertiary"])
        self.str_detail.pack(side="right")

        # Progress bar for visual strength
        self.str_bar = ctk.CTkProgressBar(cnt, height=6, corner_radius=3,
                                          fg_color=COLORS["bg_tertiary"], progress_color=COLORS["success"])
        self.str_bar.pack(fill="x", pady=(0, 20))
        self.str_bar.set(1.0)

        # Action buttons - modern style
        br = ctk.CTkFrame(cnt, fg_color="transparent")
        br.pack(fill="x", pady=(0, 24))
        ctk.CTkButton(br, text="Regenerate", width=140, height=40, corner_radius=10,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     font=ctk.CTkFont(size=12, weight="bold"), command=self._regen).pack(side="left", padx=(0, 8))
        ctk.CTkButton(br, text="Copy to Clipboard", width=140, height=40, corner_radius=10,
                     fg_color=COLORS["bg_tertiary"], hover_color=COLORS["border"],
                     font=ctk.CTkFont(size=12), command=lambda: ClipboardManager.copy(self.gen_var.get())).pack(side="left")
        ctk.CTkButton(br, text="Save as Credential", width=150, height=40, corner_radius=10,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     font=ctk.CTkFont(size=12, weight="bold"),
                     command=self._save_gen_as_credential).pack(side="left", padx=(8, 0))

        # Options section - modern card
        opt_card = ctk.CTkFrame(cnt, fg_color=COLORS["bg_secondary"], corner_radius=12)
        opt_card.pack(fill="x")

        opt_inner = ctk.CTkFrame(opt_card, fg_color="transparent")
        opt_inner.pack(fill="x", padx=16, pady=16)

        ctk.CTkLabel(opt_inner, text="Configuration", font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["text_primary"], anchor="w").pack(fill="x", pady=(0, 12))

        # Length slider - 4 to 128
        lr = ctk.CTkFrame(opt_inner, fg_color="transparent")
        lr.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(lr, text="Length", font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(side="left")
        self.len_lbl = ctk.CTkLabel(lr, text="24", font=ctk.CTkFont(size=13, weight="bold"),
                                    text_color=COLORS["accent"], width=36)
        self.len_lbl.pack(side="right")
        ctk.CTkLabel(lr, text="128", font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(side="right", padx=(0, 4))
        self.len_sl = ctk.CTkSlider(lr, from_=4, to=128, number_of_steps=124, command=self._on_len,
                                    width=200, height=16, corner_radius=8,
                                    fg_color=COLORS["bg_tertiary"], progress_color=COLORS["accent"],
                                    button_color=COLORS["accent"], button_hover_color=COLORS["accent_hover"])
        self.len_sl.set(24)
        self.len_sl.pack(side="right", padx=12)
        ctk.CTkLabel(lr, text="4", font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(side="right")

        # Character type toggles - modern switches
        toggle_frame = ctk.CTkFrame(opt_inner, fg_color="transparent")
        toggle_frame.pack(fill="x")

        self.g_up = ctk.BooleanVar(value=True)
        self.g_lo = ctk.BooleanVar(value=True)
        self.g_num = ctk.BooleanVar(value=True)
        self.g_sym = ctk.BooleanVar(value=True)

        for txt, v, sample in [("Uppercase", self.g_up, "A-Z"), ("Lowercase", self.g_lo, "a-z"),
                                ("Numbers", self.g_num, "0-9"), ("Symbols", self.g_sym, "!@#$")]:
            row = ctk.CTkFrame(toggle_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=txt, font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"]).pack(side="left")
            ctk.CTkLabel(row, text=sample, font=ctk.CTkFont(size=9), text_color=COLORS["text_tertiary"]).pack(side="left", padx=(6, 0))
            ctk.CTkSwitch(row, text="", variable=v, width=40, height=20,
                         fg_color=COLORS["bg_tertiary"], progress_color=COLORS["accent"],
                         button_color=COLORS["text_primary"], command=self._regen).pack(side="right")

        self._upd_str()

    def _on_len(self, v):
        # Clamp value to valid range and force slider back
        clamped = max(MIN_PASSWORD_LENGTH, min(int(float(v)), MAX_PASSWORD_LENGTH))
        if int(float(v)) != clamped:
            self.len_sl.set(clamped)
        self.len_lbl.configure(text=str(clamped))
        self._regen()

    def _regen(self):
        length = max(MIN_PASSWORD_LENGTH, min(int(float(self.len_sl.get())), MAX_PASSWORD_LENGTH))
        self.gen_var.set(generate_password(length, self.g_up.get(), self.g_lo.get(), self.g_num.get(), self.g_sym.get()))
        self._upd_str()

    def _upd_str(self):
        label, score, color, detail = password_strength(self.gen_var.get())
        self.str_badge.configure(text=label.upper(), fg_color=color)
        self.str_pct.configure(text=f"{score}%", text_color=color)
        self.str_detail.configure(text=detail)
        self.str_bar.configure(progress_color=color)
        self.str_bar.set(score / 100)

    def _save_gen_as_credential(self):
        pw = self.gen_var.get()
        self._view_add()
        if hasattr(self, 'a_pw') and pw:
            self.a_pw.delete(0, "end")
            self.a_pw.insert(0, pw)

    # ===== SETTINGS =====
    def _view_settings(self):
        for w in self.content.winfo_children(): w.destroy()
        ctk.CTkLabel(self.content, text="Settings", font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(anchor="w", padx=20, pady=(20, 14))

        cnt = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        cnt.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        settings = get_settings()

        # Theme setting
        self._setting_dropdown(cnt, "Theme", "Switch between dark and light mode",
                               ["Dark", "Light"], "Dark" if settings.get("theme") == "dark" else "Light",
                               self._change_theme)

        # Startup
        self._setting(cnt, "Start with Windows", "Launch minimized at login", in_startup(), self._tog_startup)

        # Clipboard auto-clear
        clear_mins = settings.get("clipboard_clear_seconds", 300) // 60
        self._setting_dropdown(cnt, "Clipboard Auto-Clear", "Automatically clear clipboard after copying passwords",
                               ["1 min", "5 min", "10 min", "30 min", "Never"],
                               f"{clear_mins} min" if clear_mins > 0 else "Never",
                               self._change_clipboard_clear)

        # Exclude $ from passwords
        self._setting(cnt, "Exclude $ from Passwords", "Never include the $ character in generated passwords",
                      settings.get("exclude_dollar", False), self._tog_exclude_dollar)

        # Hotkey configuration
        hotkey_first = settings.get("hotkey_first", DEFAULT_HOTKEY_FIRST)
        hotkey_second = settings.get("hotkey_second", DEFAULT_HOTKEY_SECOND)
        self._setting_hotkey(cnt, "Global Hotkey", f"Current: {hotkey_first}, {hotkey_second}",
                            hotkey_first, hotkey_second)

        # Info sections
        self._info(cnt, "Vault Location", str(get_vault_path()))
        self._info(cnt, "2FA", "Enabled" if self.vault.totp_enabled else "Disabled")
        self._info(cnt, "Encryption", f"AES-256-GCM + {'Argon2id' if HAS_ARGON2 else 'Scrypt'}")
        self._info(cnt, "Password Expiry", f"Credentials older than {PASSWORD_EXPIRY_DAYS} days are flagged")
        self._info(cnt, "PDF Export", "Available" if _load_pdf_modules() else "Install: pip install reportlab PyPDF2")

        # HIBP Check button
        hibp_frame = ctk.CTkFrame(cnt, fg_color=COLORS["bg_secondary"], corner_radius=8)
        hibp_frame.pack(fill="x", pady=(0, 10))
        hibp_inner = ctk.CTkFrame(hibp_frame, fg_color="transparent")
        hibp_inner.pack(fill="x", padx=14, pady=12)
        ctk.CTkLabel(hibp_inner, text="Breach Detection", font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        ctk.CTkLabel(hibp_inner, text="Check passwords against Have I Been Pwned (sends only hash prefix)",
                    font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x", pady=(2, 8))
        ctk.CTkButton(hibp_inner, text="Check All Passwords", height=32, corner_radius=6,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     font=ctk.CTkFont(size=11), command=self._check_all_hibp).pack(anchor="w")

        ctk.CTkLabel(cnt, text=f"SecureVault v{APP_VERSION}", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(pady=(14, 0))

    def _change_theme(self, value):
        theme = "dark" if value == "Dark" else "light"
        get_settings().set("theme", theme)
        ctk.set_appearance_mode(theme)
        self._build_main()

    def _change_clipboard_clear(self, value):
        time_map = {"1 min": 60, "5 min": 300, "10 min": 600, "30 min": 1800, "Never": 0}
        get_settings().set("clipboard_clear_seconds", time_map.get(value, 300))

    def _setting_dropdown(self, parent, title: str, desc: str, options: list, current: str, cmd: Callable):
        fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=8)
        fr.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(fr, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=12)
        ctk.CTkLabel(inner, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        ctk.CTkLabel(inner, text=desc, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x")
        combo = ctk.CTkComboBox(inner, values=options, width=120, height=32, corner_radius=6,
                               border_width=1, border_color=COLORS["border"], fg_color=COLORS["bg_tertiary"],
                               dropdown_fg_color=COLORS["bg_secondary"], font=ctk.CTkFont(size=11), command=cmd)
        combo.set(current)
        combo.place(relx=1.0, rely=0.5, anchor="e")

    def _setting_hotkey(self, parent, title: str, desc: str, first: str, second: str):
        fr = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=8)
        fr.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(fr, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=12)
        ctk.CTkLabel(inner, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color=COLORS["text_primary"], anchor="w").pack(fill="x")
        ctk.CTkLabel(inner, text=desc, font=ctk.CTkFont(size=10), text_color=COLORS["text_secondary"], anchor="w").pack(fill="x")

        btn_frame = ctk.CTkFrame(inner, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(8, 0))

        ctk.CTkLabel(btn_frame, text="First:", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(side="left")
        self.hotkey_first_combo = ctk.CTkComboBox(btn_frame, values=["shift+v", "ctrl+shift+v", "alt+v", "ctrl+alt+v"],
                                                   width=110, height=28, corner_radius=6, font=ctk.CTkFont(size=10),
                                                   fg_color=COLORS["bg_tertiary"], border_color=COLORS["border"])
        self.hotkey_first_combo.set(first)
        self.hotkey_first_combo.pack(side="left", padx=(4, 12))

        ctk.CTkLabel(btn_frame, text="Then:", font=ctk.CTkFont(size=10), text_color=COLORS["text_tertiary"]).pack(side="left")
        self.hotkey_second_combo = ctk.CTkComboBox(btn_frame, values=["p", "v", "k", "s"],
                                                    width=60, height=28, corner_radius=6, font=ctk.CTkFont(size=10),
                                                    fg_color=COLORS["bg_tertiary"], border_color=COLORS["border"])
        self.hotkey_second_combo.set(second)
        self.hotkey_second_combo.pack(side="left", padx=(4, 12))

        ctk.CTkButton(btn_frame, text="Apply", width=60, height=28, corner_radius=6,
                     fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                     font=ctk.CTkFont(size=10), command=self._apply_hotkey).pack(side="left")

    def _apply_hotkey(self):
        settings = get_settings()
        new_first = self.hotkey_first_combo.get()
        new_second = self.hotkey_second_combo.get()
        settings.set("hotkey_first", new_first)
        settings.set("hotkey_second", new_second)
        if self.hotkey_handler:
            self.hotkey_handler.reload_config()
        # Update sidebar hotkey label
        new_display = f"{new_first}, {new_second}".upper()
        if hasattr(self, '_hotkey_label') and self._hotkey_label.winfo_exists():
            self._hotkey_label.configure(text=f"HOTKEY: {new_display}")
        # Update tray tooltip
        if self.tray:
            self.tray.title = f"{APP_NAME}\n{new_display}"
        self._view_settings()

    def _check_all_hibp(self):
        """Check all passwords against HIBP."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Breach Check Results")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=COLORS["bg_primary"])

        ctk.CTkLabel(dialog, text="Checking passwords...", font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=COLORS["text_primary"]).pack(pady=20)

        progress = ctk.CTkProgressBar(dialog, width=400)
        progress.pack(pady=10)
        progress.set(0)

        results_frame = ctk.CTkScrollableFrame(dialog, fg_color="transparent", height=250)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)

        def check_passwords():
            entries = self.vault.list_all()
            breached = []
            for i, e in enumerate(entries):
                progress.set((i + 1) / len(entries))
                dialog.update()
                try:
                    pw = self.vault.get_password(e["id"], track=False)
                    is_breached, count, msg = check_password_hibp(pw)
                    if is_breached and count > 0:
                        breached.append((e["name"], count))
                except:
                    pass

            # Show results
            for w in results_frame.winfo_children():
                w.destroy()

            if breached:
                ctk.CTkLabel(results_frame, text=f"⚠️ {len(breached)} password(s) found in breaches!",
                            font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["danger"]).pack(pady=(0, 10))
                for name, count in breached:
                    fr = ctk.CTkFrame(results_frame, fg_color=COLORS["bg_secondary"], corner_radius=6)
                    fr.pack(fill="x", pady=2)
                    ctk.CTkLabel(fr, text=f"{name}: found {count:,} times",
                                font=ctk.CTkFont(size=11), text_color=COLORS["danger"]).pack(padx=10, pady=6)
            else:
                ctk.CTkLabel(results_frame, text="✓ No passwords found in known breaches!",
                            font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["success"]).pack(pady=20)

            Btn(dialog, text="Close", width=100, command=dialog.destroy).pack(pady=10)

        threading.Thread(target=check_passwords, daemon=True).start()

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

    def _tog_exclude_dollar(self):
        v = getattr(self, "set_exclude_$_from_passwords", None)
        if v is not None:
            get_settings().set("exclude_dollar", v.get())

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
