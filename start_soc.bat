@echo off
TITLE NetWatch SOC — Live Real-Time Network Packet Scanner
echo ======================================================================
echo 🛡️ NetWatch SOC — Network Traffic & Real-Time C2 Detection Engine
echo ======================================================================
echo.
echo Launching NetWatch SOC Streamlit Dashboard...
echo Make sure you run this script as Administrator for physical NIC packet sniffing!
echo.
echo Press Ctrl+C in this window to stop the SOC engine.
echo ======================================================================
echo.

cd /d "%~dp0"
python -m streamlit run dashboard/app.py

pause
