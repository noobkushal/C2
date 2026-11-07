@echo off
TITLE NetWatch SOC — GitHub Push
color 0b
echo ======================================================================
echo  NetWatch SOC — Push to https://github.com/noobkushal/C2
echo ======================================================================
echo.

set "GH_EXE=C:\Users\noobm\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"
set "GIT_EXE=C:\Users\noobm\AppData\Local\Microsoft\WinGet\Packages\Git.MinGit_Microsoft.Winget.Source_8wekyb3d8bbwe\cmd\git.exe"

REM Step 1: Check GitHub authentication
"%GH_EXE%" auth status >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [STEP 1/2] GitHub Authentication Required.
    echo A browser window will open automatically.
    echo Please confirm authorization in your browser window.
    echo.
    "%GH_EXE%" auth login --hostname github.com --git-protocol https --web
    echo Configuring Git credential helper...
    "%GH_EXE%" auth setup-git
) else (
    echo [OK] Already authenticated to GitHub!
)

echo.
echo [STEP 2/2] Pushing commits to origin main...
cd /d "%~dp0"
"%GIT_EXE%" push origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ======================================================================
    echo  SUCCESS! All 33 upgraded files successfully pushed to GitHub!
    echo  Repository: https://github.com/noobkushal/C2
    echo  GitHub Pages: https://noobkushal.github.io/C2/
    echo ======================================================================
) else (
    echo.
    echo [ERROR] Git push encountered an error.
)

echo.
echo Press any key to close this window.
pause >nul
