@echo off
setlocal enabledelayedexpansion
set HERE=%~dp0..\..
set PYTHONPATH=%HERE%\src
where py >nul 2>&1
if %errorlevel%==0 (set PYEXE=py) else (set PYEXE=python)
for %%f in ("%HERE%\tests\test_*.py") do (
  for /f "delims=" %%o in ('%PYEXE% "%%f" 2^>^&1 ^| findstr /i "passed failed"') do set "LINE=%%o"
  echo [run] %%~nxf  !LINE!
)
echo -------------------------------------------
echo Done. Review the per-file lines above.
endlocal
