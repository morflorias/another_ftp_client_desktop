@echo off
chcp 65001 > nul
echo ==========================================
echo FTP Client - Unit Tests
echo ==========================================
echo.

REM Переходим в директорию скрипта
cd /d "%~dp0"

REM Проверяем виртуальное окружение
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Проверяем pytest
python -c "import pytest" 2>nul
if errorlevel 1 (
    echo Installing test dependencies...
    pip install pytest pytest-cov
)

echo Running tests...
echo ==========================================
echo.

REM Run tests
if "%1"=="--coverage" (
    python -m pytest test_ftp_protocol.py -v --cov=ftp_protocol --cov-report=term-missing
) else if "%1"=="--fast" (
    python -m pytest test_ftp_protocol.py -v -m "not slow"
) else if "%1"=="--slow" (
    python -m pytest test_ftp_protocol.py -v -m "slow"
) else (
    python -m pytest test_ftp_protocol.py -v --tb=short %*
)

echo.
pause
