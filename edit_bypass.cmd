@echo off
setlocal
chcp 65001 >nul
title VPN bypass addresses
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0split_tunnel.ps1" -EditConfig
if errorlevel 1 (
    pause
    exit /b 1
)
exit /b 0
