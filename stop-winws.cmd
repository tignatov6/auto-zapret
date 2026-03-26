@echo off
chcp 65001 >nul
echo ========================================
echo   Остановка WinWS
echo ========================================
echo.

cd /d "%~dp0"
set "DATA_DIR=%CD%\data"

echo [1/2] Остановка WinWS...
taskkill /F /FI "IMAGENAME eq winws.exe" 2>nul

echo [2/2] Очистка PID файлов...
del /F /Q "%DATA_DIR%\*.pid" 2>nul

echo.
echo ========================================
echo   WinWS остановлен
echo ========================================
timeout /t 1 /nobreak >nul
