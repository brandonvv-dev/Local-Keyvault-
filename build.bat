@echo off
REM =============================================
REM  SecureVault Keychain - Build Script (Windows)
REM  Creates a standalone .exe password manager
REM =============================================

echo.
echo  ========================================
echo   SecureVault Keychain - Windows Build
echo  ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python is not installed or not in PATH
    echo  Please install Python 3.10+ from python.org
    pause
    exit /b 1
)

REM Create virtual environment if not exists
if not exist "venv" (
    echo  Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Upgrade pip
echo  Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo  Installing dependencies...
pip install -r requirements.txt

REM Build the executable
echo.
echo  Building SecureVault.exe...
echo.

REM Check if icon exists
set ICON_FLAG=
if exist "icon.ico" set ICON_FLAG=--icon "icon.ico"

pyinstaller ^
    --onefile ^
    --windowed ^
    --name "SecureVault" ^
    %ICON_FLAG% ^
    --clean ^
    --noconfirm ^
    --hidden-import=argon2 ^
    --hidden-import=argon2.low_level ^
    --hidden-import=pyotp ^
    --hidden-import=qrcode ^
    --hidden-import=PIL ^
    --hidden-import=PIL.Image ^
    --hidden-import=PIL.ImageDraw ^
    --hidden-import=customtkinter ^
    --hidden-import=pystray ^
    --hidden-import=pystray._win32 ^
    --hidden-import=keyboard ^
    --hidden-import=pyautogui ^
    --hidden-import=pyperclip ^
    --collect-all customtkinter ^
    --collect-all pystray ^
    keychain.py

echo.
echo  ========================================
echo   Build Complete!
echo  ========================================
echo.
echo   Your executable is ready at:
echo   dist\SecureVault.exe
echo.
echo   Features:
echo   - System tray icon (runs in background)
echo   - Global hotkey: Ctrl+Shift+V
echo   - Quick access popup with Most Used
echo   - Auto-type passwords into any field
echo.
echo   Share this file with your friends!
echo.

pause
