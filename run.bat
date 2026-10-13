@echo off
chcp 65001 > nul
echo ==========================================
echo FTP Client - Установка и запуск
echo ==========================================
echo.

REM Проверяем Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ОШИБКА: Python не найден!
    echo Установите Python 3.8+ с https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Проверяем наличие виртуального окружения
if not exist "venv" (
    echo Создание виртуального окружения...
    python -m venv venv
    if errorlevel 1 (
        echo ОШИБКА: Не удалось создать виртуальное окружение
        pause
        exit /b 1
    )
)

REM Активируем виртуальное окружение
call venv\Scripts\activate

REM Проверяем наличие зависимостей
python -c "import PySide6; import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Установка зависимостей...
    pip install --upgrade pip
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ОШИБКА: Не удалось установить зависимости
        pause
        exit /b 1
    )
)

echo.
echo Запуск FTP-клиента...
echo ==========================================
python main.py

pause
