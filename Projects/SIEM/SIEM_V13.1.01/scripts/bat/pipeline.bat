@echo off
set HERE=%~dp0..\..
set PYTHONPATH=%HERE%\src
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
set IN=%~1
if "%IN%"=="" set IN=%HERE%\samples\demo_linux_attack.jsonl
set OUT=%~2
if "%OUT%"=="" set OUT=%HERE%\out\large
set FMT=%~3
if "%FMT%"=="" set FMT=auto
echo [*] Pipeline ^| input=%IN% ^| out=%OUT% ^| format=%FMT%
if exist "%OUT%\tickets.jsonl" del "%OUT%\tickets.jsonl"
%PYEXE% -m ingest.replay --input "%IN%" --out-dir "%OUT%" --format "%FMT%"
echo [+] Done. Artifacts in %OUT%
