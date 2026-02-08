@echo off
REM =============================================
REM  SecureVault v3.1.0 - Build Script (Windows)
REM  Creates a standalone .exe password manager
REM =============================================

echo.
echo  ========================================
echo   SecureVault v3.1.0 - Windows Build
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
python -m pip install --upgrade pip >nul 2>&1

REM Install dependencies
echo  Installing dependencies...
pip install -r requirements.txt >nul 2>&1

REM Build the executable
echo.
echo  Building SecureVault.exe...
echo  This may take a few minutes...
echo.

REM Check if icon exists
set ICON_FLAG=
if exist "icon.ico" set ICON_FLAG=--icon "icon.ico"

REM Use spec file if exists, otherwise use command line
if exist "SecureVault.spec" (
    echo  Using optimized spec file...
    pyinstaller SecureVault.spec --clean --noconfirm
) else (
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
        --hidden-import=reportlab ^
        --hidden-import=reportlab.lib ^
        --hidden-import=reportlab.platypus ^
        --hidden-import=PyPDF2 ^
        --collect-all customtkinter ^
        --collect-all pystray ^
        keychain.py
)

if exist "dist\SecureVault.exe" (
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
    echo   - Global hotkey: Shift+V, P (chord)
    echo   - Quick access popup for credentials
    echo   - Auto-type passwords into any field
    echo   - Password-protected PDF export
    echo   - DevOps/SysAdmin focused categories
    echo.
) else (
    echo.
    echo  ERROR: Build failed! Check the output above.
    echo.
)

pause
