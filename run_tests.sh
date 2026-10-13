#!/bin/bash
# Run FTP Client Unit Tests

echo "=========================================="
echo "FTP Client - Unit Tests"
echo "=========================================="
echo

# Переходим в директорию скрипта
cd "$(dirname "$0")"

# Проверяем виртуальное окружение
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Проверяем pytest
if ! python3 -c "import pytest" 2>/dev/null; then
    echo "Installing test dependencies..."
    pip install pytest pytest-cov
fi

echo "Running tests..."
echo "=========================================="
echo

# Run tests
if [ "$1" = "--coverage" ]; then
    python3 -m pytest test_ftp_protocol.py -v --cov=ftp_protocol --cov-report=term-missing
elif [ "$1" = "--fast" ]; then
    python3 -m pytest test_ftp_protocol.py -v -m "not slow"
elif [ "$1" = "--slow" ]; then
    python3 -m pytest test_ftp_protocol.py -v -m "slow"
else
    python3 -m pytest test_ftp_protocol.py -v --tb=short "$@"
fi
