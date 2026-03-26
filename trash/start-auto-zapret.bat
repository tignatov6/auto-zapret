@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM ========================================
REM Auto-Zapret - запуск WinWS + Web UI
REM Окно остаётся открытым пока не закроете
REM ========================================

title Auto-Zapret Manager

cd /d "%~dp0"

REM ========================================
REM Проверка прав администратора с авто-запросом UAC
REM ========================================
net session >nul 2>&1
if errorlevel 1 (
    echo [INFO] Запрос прав администратора...
    
    REM Создаём временный VBS скрипт для запроса UAC
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\UAC_Request.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c cd /d ""%~dp0"" && ""%~f0"" %*", "", "runas", 1 >> "%temp%\UAC_Request.vbs"
    
    REM Запускаем от админа
    cscript.exe //nologo "%temp%\UAC_Request.vbs"
    
    REM Удаляем VBS
    del "%temp%\UAC_Request.vbs"
    
    REM Закрываем текущее окно без прав
    exit /b 0
)

echo [OK] Права администратора подтверждены

REM Пути
set "ZAPRET_DIR=%CD%\zapret-src\zapret-v72.12"
set "BINARIES=%ZAPRET_DIR%\binaries\windows-x86_64"
set "DATA_DIR=%CD%\data"
set "LOG_DIR=%CD%\logs"
set "PYTHON=python"

REM Файлы
set "AUTOHOSTLIST_FILE=%DATA_DIR%\zapret-hosts-auto.txt"
set "LOG_FILE=%LOG_DIR%\autohostlist.log"
set "STRAT_YOUTUBE=%DATA_DIR%\strat-youtube.txt"
set "STRAT_DISCORD=%DATA_DIR%\strat-discord.txt"
set "STRAT_DEFAULT=%DATA_DIR%\strat-default.txt"

echo.
echo ========================================
echo   Auto-Zapret Manager
echo ========================================
echo.

REM ========================================
REM Проверка WinDivert
REM ========================================
echo [1/3] Проверка WinDivert...
sc query WinDivert >nul 2>&1
if errorlevel 1 (
    echo [ERROR] WinDivert не установлен!
    echo [INFO] Запустите install-windivert.cmd
    REM start "WinDivert-install" "%CD%\install-windivert.cmd"
)
echo [OK] WinDivert установлен

REM ========================================
REM Подготовка файлов
REM ========================================
echo [2/3] Подготовка файлов...
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Очищаем autohostlist при каждом запуске!
echo # Auto-generated hostlist > "%AUTOHOSTLIST_FILE%"
echo [INFO] Autohostlist очищен

if not exist "%STRAT_YOUTUBE%" (
    echo # Strategy: youtube > "%STRAT_YOUTUBE%"
    echo # Params: --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 >> "%STRAT_YOUTUBE%"
)
if not exist "%STRAT_DISCORD%" (
    echo # Strategy: discord > "%STRAT_DISCORD%"
    echo # Params: --dpi-desync=split --dpi-desync-split-pos=1,midsld >> "%STRAT_DISCORD%"
)
if not exist "%STRAT_DEFAULT%" (
    echo # Strategy: default > "%STRAT_DEFAULT%"
    echo # Params: --dpi-desync=fake --dpi-desync-fooling=md5sig >> "%STRAT_DEFAULT%"
)
echo [OK] Файлы готовы

REM ========================================
REM Остановка старых процессов
REM ========================================
echo [3/3] Остановка старых процессов...
taskkill /F /FI "IMAGENAME eq winws.exe" 2>nul
taskkill /F /FI "WINDOWTITLE eq Auto-Zapret*" 2>nul
timeout /t 1 /nobreak >nul
echo [OK] Готово

REM ========================================
REM Запуск WinWS в отдельном окне
REM ========================================
REM echo.
REM echo Запуск WinWS (только autohostlist, brute force)...
REM start "WinWS" "%BINARIES%\winws.exe" ^
REM   --wf-tcp=80,443 ^
REM   --filter-tcp=443 ^
REM   --filter-tcp=80 ^
REM   --hostlist-auto="%AUTOHOSTLIST_FILE%" ^
REM   --hostlist-auto-fail-threshold=3 ^
REM   --hostlist-auto-debug="%LOG_FILE%"

REM timeout /t 2 /nobreak >nul

REM ========================================
REM Запуск Auto-Zapret Web UI в отдельном окне
REM ========================================
echo Запуск Auto-Zapret Web UI...
start "Auto-Zapret Web UI" %PYTHON% -m autozapret.main serve --port 8000

timeout /t 3 /nobreak >nul

REM ========================================
REM Проверка статуса
REM ========================================
echo.
echo ========================================
echo   Статус
echo ========================================

tasklist /FI "IMAGENAME eq winws.exe" 2>nul | findstr /C:"winws.exe" >nul 2>&1
if not errorlevel 1 (
    echo [OK] WinWS - запущен
) else (
    echo [ERROR] WinWS - НЕ запущен
)

curl -s http://localhost:8000/api/stats >nul 2>&1
if not errorlevel 1 (
    echo [OK] Auto-Zapret Web UI - запущен
) else (
    echo [ERROR] Auto-Zapret Web UI - НЕ запущен
)

echo.
echo ========================================
echo   ГОТОВО!
echo ========================================
echo.
echo Web UI: http://localhost:8000
echo Логи: %LOG_FILE%
echo.
echo ========================================
echo ЗАКРОЙТЕ ЭТО ОКНО для остановки
echo ========================================
echo.
