@echo off
TITLE NetWatch SOC — Npcap Packet Capture Driver Installer
echo ======================================================================
echo 🛡️ NetWatch SOC — Npcap Packet Capture Driver Installer
echo ======================================================================
echo.
echo Installing bundled Npcap packet capture driver for Windows...
echo Note: Please accept administrator prompt and select "WinPcap API-compatible Mode".
echo.

cd /d "%~dp0"
if exist "installers\npcap-setup.exe" (
    echo Launching installers\npcap-setup.exe...
    start /wait installers\npcap-setup.exe /winpcap_mode=yes
    echo Npcap installation step completed.
) else (
    echo Error: installers\npcap-setup.exe not found.
)

pause
