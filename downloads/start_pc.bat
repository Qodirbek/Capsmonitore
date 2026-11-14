@echo off
cd /d "%~dp0"
if not exist config.json copy config.example.json config.json
python reporter.py
if errorlevel 1 py reporter.py
pause
