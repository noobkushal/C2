@echo off
TITLE NetWatch SOC — Live Physical Packet Capture Setup
echo ======================================================================
echo 🛡️ NetWatch SOC — Live Physical NIC Packet Capture Setup
echo ======================================================================
echo.
cd /d "%~dp0"

REM Check for Administrator privileges
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] This script is NOT running as Administrator!
    echo Physical network card packet capture requires Administrator rights.
    echo Please right-click this file and select "Run as Administrator".
    echo.
    pause
    exit /b 1
)

echo [1/3] Checking Npcap Kernel Driver...
sc query npcap >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ACTION REQUIRED] Npcap driver is not installed.
    echo Launching bundled Npcap installer from installers\npcap-setup.exe...
    echo **IMPORTANT**: Check the box for "Install Npcap in WinPcap API-compatible Mode"!
    start /wait installers\npcap-setup.exe
) else (
    echo [OK] Npcap Kernel Packet Driver is installed and active.
)

echo.
echo [2/3] Checking Python Environment...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ACTION] Installing Python 3.11 via winget...
    winget install --id Python.Python.3.11 -e --scope user --accept-source-agreements --accept-package-agreements
    echo Please re-run this script after Python completes installation.
    pause
    exit /b 0
) else (
    echo [OK] Python detected:
    python --version
)

echo.
echo [3/3] Installing Python Dependencies (Scapy, Streamlit, etc.)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo ======================================================================
echo [READY] Launching NetWatch SOC Live Physical Sniffer Dashboard...
echo ======================================================================
echo Active Adapter detected on your machine: Wireless LAN adapter Wi-Fi
echo.
python -m streamlit run dashboard/app.py

pause
