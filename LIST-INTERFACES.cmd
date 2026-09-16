@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\Packet-Inspector.ps1" -Mode Interfaces %*
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
