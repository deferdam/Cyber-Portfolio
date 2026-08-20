@echo off
set HERE=%~dp0..\..
set PYTHONPATH=%HERE%\src
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
echo [*] Streaming simulation (fake data). Start the app first, then refresh the UI.
%PYEXE% "%HERE%\src\ingest\stream.py" %*
