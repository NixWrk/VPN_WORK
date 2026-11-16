@echo off
setlocal
title ChatGPT and Codex VPN guard
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0gpt_vpn_guard.ps1"
set "GUARD_EXIT=%ERRORLEVEL%"
if "%GUARD_EXIT%"=="0" (echo GPT VPN protection was installed.) else (echo Setup failed or was cancelled. Exit code: %GUARD_EXIT%.)
pause
exit /b %GUARD_EXIT%
