@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  run_siem.bat — Mini-SIEM launcher
REM
REM  Usage:
REM    run_siem.bat [small|large|syslog]  [--format json|syslog|auto]
REM
REM  Examples:
REM    run_siem.bat                        -> large JSON events (default)
REM    run_siem.bat small                  -> small JSON events
REM    run_siem.bat syslog                 -> syslog input from syslog\security.log
REM    run_siem.bat large --format auto    -> explicit auto-detect
REM ============================================================

REM === ENABLE AUDIT PROCESS CREATION ===========================
REM
REM  Why is it disabled by default?
REM  Microsoft ships Windows with most advanced audit policies OFF to minimise
REM  log volume and avoid performance overhead on low-end hardware.
REM  "Process Creation" (subcategory of "Detailed Tracking") is deliberately
REM  silent by default because on a busy server it can generate thousands of
REM  EventID 4688 entries per minute.  The trade-off was made for
REM  manageability, not security.  The CommandLine inclusion (via GPO) is
REM  ADDITIONALLY disabled because it can capture passwords passed as arguments,
REM  which raises a privacy/compliance concern in some organisations.
REM
REM  We override both here for the lab/SIEM environment.
REM  REQUIRES: elevated (Administrator) privileges.
REM =============================================================

echo [*] Checking admin rights for auditpol...
net session >nul 2>&1
if errorlevel 1 (
    echo [!] WARNING: not running as Administrator. auditpol will be skipped.
    echo     Re-run as Administrator to enable audit policies.
    goto :skip_audit
)

echo [*] Enabling audit policy: Process Creation (EventID 4688)...
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
if errorlevel 1 echo [!] auditpol failed — check Windows Audit Policy service.

echo [*] Enabling CommandLine logging in 4688 events...
REM This requires registry key + policy refresh. We set the reg key directly:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul 2>&1

echo [*] Enabling audit policy: Process Termination...
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable

echo [*] Enabling audit policy: Logon/Logoff events (4624/4625)...
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

echo [*] Enabling audit policy: Scheduled Task (4698/4699/4702)...
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

echo [+] Audit policies applied.

:skip_audit

REM === CONFIG ===================================================
set "PY=python"
set "SIEM_SRC=%~dp0src"
set "OUT_DIR=%~dp0out"
set "INPUT_SMALL=%~dp0events.jsonl"
set "INPUT_LARGE=%~dp0events_large.jsonl"
set "INPUT_SYSLOG=%~dp0syslog\security.log"

REM === ARG PARSING ==============================================
set "MODE=%~1"
if "%MODE%"=="" set "MODE=large"

set "EXTRA_ARGS=%~2"

if /I "%MODE%"=="small" (
    set "INPUT=%INPUT_SMALL%"
    set "OUT=%OUT_DIR%\small"
    set "FMT=json"
) else if /I "%MODE%"=="large" (
    set "INPUT=%INPUT_LARGE%"
    set "OUT=%OUT_DIR%\large"
    set "FMT=json"
) else if /I "%MODE%"=="syslog" (
    set "INPUT=%INPUT_SYSLOG%"
    set "OUT=%OUT_DIR%\syslog"
    set "FMT=syslog"
) else (
    echo Usage: run_siem.bat [small^|large^|syslog]
    exit /b 1
)

REM Allow caller to override format via second arg (e.g. --format auto)
if not "%EXTRA_ARGS%"=="" set "FMT_OVERRIDE=%EXTRA_ARGS:--format =%"
if defined FMT_OVERRIDE set "FMT=%FMT_OVERRIDE%"

REM === SYSLOG DIR SETUP ========================================
if /I "%MODE%"=="syslog" (
    if not exist "%~dp0syslog" mkdir "%~dp0syslog"
    if not exist "%INPUT_SYSLOG%" (
        echo [!] Syslog input not found: %INPUT_SYSLOG%
        echo     Place your syslog file there or pipe via stdin:
        echo     type security.log ^| python -m ingest.replay --format syslog --input - --out-dir out\syslog
        exit /b 1
    )
)

REM === RUN ======================================================
echo [*] Running SIEM replay
echo [*] Mode  : %MODE%
echo [*] Format: %FMT%
echo [*] Input : %INPUT%
echo [*] Out   : %OUT%

if not exist "%OUT%" mkdir "%OUT%"

set "PYTHONPATH=%SIEM_SRC%"
%PY% -m ingest.replay --input "%INPUT%" --out-dir "%OUT%" --format "%FMT%"

if errorlevel 1 (
    echo [!] SIEM run failed.
    exit /b 1
)

echo [+] Done. Artifacts in:
echo     %OUT%\alerts.jsonl
echo     %OUT%\signals.jsonl
echo     %OUT%\normalized_events.jsonl
exit /b 0
