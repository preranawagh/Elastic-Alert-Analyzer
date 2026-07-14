@echo off
REM ============================================================
REM  Elastic Alert Analyzer — scheduled SOC pipeline runner
REM
REM  Windows Task Scheduler (every 5 minutes):
REM    Program/script :  C:\...\Elastic-Alert-Analyzer\run_pipeline.bat
REM    Start in       :  C:\...\Elastic-Alert-Analyzer
REM
REM  Non-interactive. Exit code 0 = success, non-zero = failure.
REM  All stdout/stderr → logs\pipeline_YYYY-MM-DD.log (daily rotation)
REM
REM  Date resolution uses venv Python + a temp file (no PowerShell,
REM  no for /f command substitution — both break on this host).
REM ============================================================
setlocal EnableExtensions

cd /d "%~dp0"
if errorlevel 1 (
    echo ERROR: Could not change to project directory: %~dp0
    exit /b 1
)

if not exist "logs" mkdir "logs"
if not exist "logs" (
    echo ERROR: Could not create logs directory
    exit /b 1
)

set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    >> "logs\pipeline_bat_error.log" echo ===== BAT START %DATE% %TIME% =====
    >> "logs\pipeline_bat_error.log" echo ERROR: Virtual environment Python not found: %PYTHON_EXE%
    >> "logs\pipeline_bat_error.log" echo Create the venv and install requirements before scheduling.
    >> "logs\pipeline_bat_error.log" echo ===== BAT END %DATE% %TIME% exit=1 =====
    exit /b 1
)

REM Resolve ISO date via Python into a temp file (avoids cmd quote/parsing bugs)
set "DATE_FILE=logs\.pipeline_date"
"%PYTHON_EXE%" -c "from datetime import date; open(r'logs\.pipeline_date','w',encoding='utf-8').write(date.today().isoformat())"
if errorlevel 1 (
    >> "logs\pipeline_bat_error.log" echo ERROR: Could not resolve today's date via Python.
    exit /b 1
)
if not exist "%DATE_FILE%" (
    >> "logs\pipeline_bat_error.log" echo ERROR: Date file was not created: %DATE_FILE%
    exit /b 1
)

set /p LOG_DATE=<"%DATE_FILE%"
del "%DATE_FILE%" >nul 2>&1

if not defined LOG_DATE (
    >> "logs\pipeline_bat_error.log" echo ERROR: Empty date from Python.
    exit /b 1
)

set "PIPELINE_LOG=logs\pipeline_%LOG_DATE%.log"
set "PIPELINE_LOG_DATE=%LOG_DATE%"

>> "%PIPELINE_LOG%" echo.
>> "%PIPELINE_LOG%" echo ===== BAT START %DATE% %TIME% =====

REM Avoid duplicate FileHandler writes when bat already redirects stdout
set PIPELINE_LOG_CAPTURED=1

"%PYTHON_EXE%" -u "%~dp0pipeline.py" >> "%PIPELINE_LOG%" 2>&1
set "EXITCODE=%ERRORLEVEL%"

>> "%PIPELINE_LOG%" echo ===== BAT END %DATE% %TIME% exit=%EXITCODE% =====

endlocal & exit /b %EXITCODE%
