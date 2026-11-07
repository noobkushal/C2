@echo off
title NetWatch SOC — Localhost Server
echo Starting NetWatch SOC Localhost Server on port 8501...
cd /d "%~dp0"
start http://localhost:8501/
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0server.ps1" -Port 8501
pause
