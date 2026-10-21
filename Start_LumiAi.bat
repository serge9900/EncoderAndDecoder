@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 -c "import cryptography" >nul 2>nul
    if errorlevel 1 (
        py -3 -m pip install -r requirements.txt
        if errorlevel 1 goto error
    )
    py -3 LumiAi.py
) else (
    python -c "import cryptography" >nul 2>nul
    if errorlevel 1 (
        python -m pip install -r requirements.txt
        if errorlevel 1 goto error
    )
    python LumiAi.py
)
if errorlevel 1 goto error
exit /b 0
:error
echo.
echo LumiAi could not start. Make sure Python 3.10+ is installed.
pause
exit /b 1
