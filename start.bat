@echo off
chcp 65001 >nul
cd /d "%~dp0"

where pythonw >nul 2>nul
if not errorlevel 1 (
  start "" pythonw app.py
  exit /b 0
)

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install Python 3.10+ and add it to PATH.
  echo         https://www.python.org/downloads/
  pause
  exit /b 1
)

python app.py
if errorlevel 1 pause
