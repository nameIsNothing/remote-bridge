@echo off
setlocal
set "REMOTE_BRIDGE_TARGET_EXE=%~dp0bridge-target.exe"
set "REMOTE_BRIDGE_TARGET_DIR=%~dp0"
powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath $env:REMOTE_BRIDGE_TARGET_EXE -WorkingDirectory $env:REMOTE_BRIDGE_TARGET_DIR -Verb RunAs"
