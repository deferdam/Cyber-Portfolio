@echo off
REM  run_server.bat -- Mini SOAR SERVER mode
REM  In v8: enables file browser confinement to SIEM_SCAN_ROOT.
REM  Auth and roles arrive in v10.
set BASEDIR=%~dp0
set PYTHONPATH=%BASEDIR%src
set SIEM_MODE=server
set SIEM_SCAN_ROOT=%BASEDIR%
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
echo [*] Mini SOAR  mode=SERVER  confined to %SIEM_SCAN_ROOT%
echo [*] Press Ctrl+C to stop.
%PYEXE% src/server/app.py
