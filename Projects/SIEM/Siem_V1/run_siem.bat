@echo off
setlocal enabledelayedexpansion

REM === CONFIG ===
set "PY=python"
set "SIEM_SRC=%~dp0src"
set "OUT_DIR=%~dp0out"
set "INPUT_SMALL=events.jsonl"
set "INPUT_LARGE=events_large.jsonl"

REM === ARG PARSING ===
set "MODE=%~1"
if "%MODE%"=="" set "MODE=large"

if /I "%MODE%"=="small" (
  set "INPUT=%INPUT_SMALL%"
  set "OUT=%OUT_DIR%\small"
) else if /I "%MODE%"=="large" (
  set "INPUT=%INPUT_LARGE%"
  set "OUT=%OUT_DIR%\large"
) else (
  echo Usage: run_siem.bat [small^|large]
  exit /b 1
)

REM === RUN ===
echo [*] Running SIEM replay
echo [*] Input: %INPUT%
echo [*] Out:   %OUT%

if not exist "%OUT%" mkdir "%OUT%"

REM IMPORTANT: set PYTHONPATH so "python -m" finds siem package
set "PYTHONPATH=%SIEM_SRC%"

%PY% -m siem.ingest.replay --input "%INPUT%" --out-dir "%OUT%"
if errorlevel 1 (
  echo [!] SIEM run failed.
  exit /b 1
)

echo [+] Done. Check:
echo     %OUT%\alerts.jsonl
echo     %OUT%\signals.jsonl
echo     %OUT%\normalized_events.jsonl
exit /b 0