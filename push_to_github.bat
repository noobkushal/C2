@echo off
title Push NetWatch SOC to GitHub
echo ========================================================
echo  Pushing NetWatch SOC updates to https://github.com/noobkushal/C2
echo ========================================================
cd /d "%~dp0"
set "GIT_EXE=C:\Users\noobm\AppData\Local\Microsoft\WinGet\Packages\Git.MinGit_Microsoft.Winget.Source_8wekyb3d8bbwe\cmd\git.exe"
"%GIT_EXE%" push origin main
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  Successfully pushed to GitHub!
    echo ========================================================
) else (
    echo.
    echo If prompted, enter your GitHub Personal Access Token or sign in.
)
pause
