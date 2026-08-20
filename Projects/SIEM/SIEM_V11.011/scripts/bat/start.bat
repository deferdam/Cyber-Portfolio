@echo off
set HERE=%~dp0..\..
set PYTHONPATH=%HERE%\src
set SIEM_MODE=local
set SIEM_HOST=127.0.0.1
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
echo [*] Mini SOAR ^| mode=LOCAL ^| http://127.0.0.1:5000 ^| browser opens itself. Ctrl+C to stop.
%PYEXE% "%HERE%\src\server\app.py"
