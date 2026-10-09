@echo off
setlocal
cd /d "%~dp0"

if not exist "node_modules\vite\bin\vite.js" (
    call npm install
    if errorlevel 1 goto failed
)

call npm run build
if errorlevel 1 goto failed

python server.py --open-browser
if errorlevel 1 goto failed
exit /b 0

:failed
echo.
echo CANHACK web demo could not start. Check the messages above.
pause
