@echo off
rem Double-click to open the exposeye app. First run sets everything up.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up exposeye, this takes a minute...
    python -m venv .venv || (echo Python 3.10+ is required: https://www.python.org/downloads/ & pause & exit /b 1)
    ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
    ".venv\Scripts\python.exe" -m pip install --quiet -e ".[desktop]" || (pause & exit /b 1)
)
".venv\Scripts\exposeye-app.exe" %*
if errorlevel 1 pause
