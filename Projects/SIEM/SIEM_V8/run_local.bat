@echo off
REM  run_local.bat -- Mini SOAR LOCAL mode (v8)
REM  Single operator, unrestricted file browser, no login.
REM  Mode is fixed at launch. Restart with run_server.bat to switch.
set BASEDIR=%~dp0
set PYTHONPATH=%BASEDIR%src
set SIEM_MODE=local
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
echo [*] Mini SOAR  mode=LOCAL  http://localhost:5000
echo [*] Press Ctrl+C to stop.
%PYEXE% src/server/app.py
