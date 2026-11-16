@echo off
setlocal
chcp 65001 >nul
title VPN bypass setup

if /I "%~1"=="--help" goto :help

pushd "%~dp0" || goto :bad_directory

if not exist "split_tunnel.ps1" goto :missing_split
echo [1/2] Updating split-tunnel routes and DNS rules...
echo       Windows may ask for Administrator permission.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0split_tunnel.ps1"
set "SPLIT_EXIT=%ERRORLEVEL%"
goto :run_zotero

:missing_split
set "SPLIT_EXIT=2"
echo ERROR: split_tunnel.ps1 was not found next to this launcher.

:run_zotero
echo.
if not exist "zotero_proxy.ps1" goto :missing_zotero
echo [2/2] Configuring the self-healing Zotero SOCKS5 proxy...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0zotero_proxy.ps1"
set "ZOTERO_EXIT=%ERRORLEVEL%"
goto :summary

:missing_zotero
set "ZOTERO_EXIT=2"
echo ERROR: zotero_proxy.ps1 was not found next to this launcher.

:summary
echo.
if not "%SPLIT_EXIT%"=="0" echo ERROR: split_tunnel.ps1 failed with exit code %SPLIT_EXIT%.
if not "%ZOTERO_EXIT%"=="0" echo ERROR: zotero_proxy.ps1 failed with exit code %ZOTERO_EXIT%.
set "EXIT_CODE=%SPLIT_EXIT%"
if "%EXIT_CODE%"=="0" set "EXIT_CODE=%ZOTERO_EXIT%"
if "%EXIT_CODE%"=="0" echo Done. Restart Zotero and other affected applications if they are open.
popd
pause
exit /b %EXIT_CODE%

:bad_directory
echo ERROR: could not open the launcher directory.
pause
exit /b 3

:help
echo Double-click this file to run split_tunnel.ps1 and zotero_proxy.ps1 independently.
echo The first script requests Administrator permission automatically.
echo Use edit_bypass.cmd to edit per-PC bypass addresses in Notepad, then run this file again.
echo Use gpt_vpn_guard.cmd to install the separate ChatGPT and Codex VPN-only guard.
exit /b 0
