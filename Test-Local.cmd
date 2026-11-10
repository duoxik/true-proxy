@echo off
rem Build current sources and open an isolated local X-RAY UI preview.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\dev.ps1" preview -Page xray
if errorlevel 1 pause
