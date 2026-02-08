#!/bin/bash
# =============================================
#  SecureVault Keychain - Build Script (Linux/macOS)
#  Creates a standalone executable password manager
# =============================================

set -e

echo ""
echo "========================================"
echo " SecureVault Keychain - Build"
echo "========================================"
echo ""

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=Linux;;
    Darwin*)    PLATFORM=macOS;;
    *)          PLATFORM="Unknown"
esac

echo " Platform detected: $PLATFORM"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo " ERROR: Python 3 is not installed"
    echo " Please install Python 3.10+ first"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo " Python version: $PYTHON_VERSION"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo " Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo " Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo " Installing dependencies..."
pip install -r requirements.txt

# Platform-specific checks
if [ "$PLATFORM" = "Linux" ]; then
    echo " Checking Linux dependencies..."

    # Check tkinter
    python3 -c "import tkinter" 2>/dev/null || {
        echo ""
        echo " WARNING: tkinter not found. Install it with:"
        echo "   Ubuntu/Debian: sudo apt-get install python3-tk"
        echo "   Fedora: sudo dnf install python3-tkinter"
        echo "   Arch: sudo pacman -S tk"
        echo ""
    }

    # pystray backend
    PYSTRAY_BACKEND="--hidden-import=pystray._xorg"
else
    PYSTRAY_BACKEND="--hidden-import=pystray._darwin"
fi

# Build the executable
echo ""
echo " Building SecureVault..."
echo ""

if [ "$PLATFORM" = "macOS" ]; then
    pyinstaller \
        --onefile \
        --windowed \
        --name "SecureVault" \
        --clean \
        --noconfirm \
        --hidden-import=argon2 \
        --hidden-import=argon2.low_level \
        --hidden-import=pyotp \
        --hidden-import=qrcode \
        --hidden-import=PIL \
        --hidden-import=PIL.Image \
        --hidden-import=PIL.ImageDraw \
        --hidden-import=customtkinter \
        --hidden-import=pystray \
        --hidden-import=pystray._darwin \
        --hidden-import=keyboard \
        --hidden-import=pyautogui \
        --hidden-import=pyperclip \
        --collect-all customtkinter \
        --collect-all pystray \
        --osx-bundle-identifier "com.securevault.keychain" \
        keychain.py

    echo ""
    echo "========================================"
    echo " Build Complete!"
    echo "========================================"
    echo ""
    echo " Your app is ready at:"
    echo "   dist/SecureVault.app"
    echo ""
    echo " Features:"
    echo "   - Menu bar icon (runs in background)"
    echo "   - Global hotkey: Ctrl+Shift+V"
    echo "   - Quick access popup with Most Used"
    echo "   - Auto-type passwords into any field"
    echo ""

else
    pyinstaller \
        --onefile \
        --windowed \
        --name "SecureVault" \
        --clean \
        --noconfirm \
        --hidden-import=argon2 \
        --hidden-import=argon2.low_level \
        --hidden-import=pyotp \
        --hidden-import=qrcode \
        --hidden-import=PIL \
        --hidden-import=PIL.Image \
        --hidden-import=PIL.ImageDraw \
        --hidden-import=customtkinter \
        --hidden-import=pystray \
        --hidden-import=pystray._xorg \
        --hidden-import=keyboard \
        --hidden-import=pyautogui \
        --hidden-import=pyperclip \
        --collect-all customtkinter \
        --collect-all pystray \
        keychain.py

    chmod +x dist/SecureVault

    echo ""
    echo "========================================"
    echo " Build Complete!"
    echo "========================================"
    echo ""
    echo " Your executable is ready at:"
    echo "   dist/SecureVault"
    echo ""
    echo " Features:"
    echo "   - System tray icon (runs in background)"
    echo "   - Global hotkey: Ctrl+Shift+V"
    echo "   - Quick access popup with Most Used"
    echo "   - Auto-type passwords into any field"
    echo ""
    echo " Note: Run with sudo for global hotkey support"
    echo ""
fi
