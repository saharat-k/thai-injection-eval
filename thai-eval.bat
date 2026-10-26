@echo off
REM Thai Injection Eval CLI entry point for Windows
setlocal
set "DIR=%~dp0"
if exist "%DIR%.venv\Scripts\python.exe" (
    "%DIR%.venv\Scripts\python.exe" -m core.cli %*
) else (
    python -m core.cli %*
)
exit /b %ERRORLEVEL%
