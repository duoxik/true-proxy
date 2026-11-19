@echo off
setlocal
rem Build and launch a local test with a separate copy of the installed profile.
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules;%PSModulePath%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\dev.ps1" test-local
set "taskLocalExit=%errorlevel%"
if not "%taskLocalExit%"=="0" pause
exit /b %taskLocalExit%
