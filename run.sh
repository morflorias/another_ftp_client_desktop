#!/bin/bash
# FTP Client - Установка и запуск

echo "=========================================="
echo "FTP Client - Установка и запуск"
echo "=========================================="
echo

# Проверяем Python
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "ОШИБКА: Python не найден!"
        echo "Установите Python 3.8+ с https://www.python.org/downloads/"
        exit 1
    fi
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3"
fi

echo "Python: $($PYTHON_CMD --version)"

# Переходим в директорию скрипта
cd "$(dirname "$0")"

# Проверяем наличие виртуального окружения
if [ ! -d "venv" ]; then
    echo "Создание виртуального окружения..."
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo "ОШИБКА: Не удалось создать виртуальное окружение"
        exit 1
    fi
fi

# Активируем виртуальное окружение
source venv/bin/activate

# Проверяем наличие PySide6
$PYTHON_CMD -c "import PySide6" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Установка зависимостей..."
    pip install --upgrade pip
    pip install PySide6 cryptography
    if [ $? -ne 0 ]; then
        echo "ОШИБКА: Не удалось установить зависимости"
        exit 1
    fi
fi

# Проверяем наличие cryptography
$PYTHON_CMD -c "import cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Установка cryptography..."
    pip install cryptography
fi

echo
echo "Запуск FTP-клиента..."
echo "=========================================="
$PYTHON_CMD main.py

# Деактивируем виртуальное окружение
deactivate
