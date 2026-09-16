@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\Packet-Inspector.ps1" -Mode Start %*
set "RC=%ERRORLEVEL%"
echo Capture exited with code %RC%. Review the final verdict and evidence path above.
pause
exit /b %RC%
