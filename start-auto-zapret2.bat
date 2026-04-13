@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM ========================================
REM Auto-Zapret2 (Zapret2) - запуск WinWS2 + Web UI
REM Окно остаётся открытым пока не закроете
REM ========================================

title Auto-Zapret2 Manager

cd /d "%~dp0"

REM ========================================
REM Проверка прав администратора с авто-запросом UAC
REM ========================================
net session >nul 2>&1
if errorlevel 1 (
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

REM ========================================
REM Настройки Zapret2
REM ========================================
set "ZAPRET2_DIR=%CD%\bin\zapret2"
set "ZAPRET2_BIN=%ZAPRET2_DIR%\winws2.exe"
set "ZAPRET2_LUA=%ZAPRET2_DIR%\lua"
set "DATA_DIR=%CD%\data"
set "LOG_DIR=%CD%\logs"
set "PYTHON=python"

REM Файлы
set "AUTOHOSTLIST_FILE=%DATA_DIR%\zapret-hosts-auto.txt"
set "LOG_FILE=%LOG_DIR%\autohostlist.log"

echo.
echo ========================================
echo   Auto-Zapret2 Manager (Zapret2)
echo ========================================
echo.

REM ========================================
REM Проверка Zapret2
REM ========================================
echo [1/4] Проверка Zapret2...
if not exist "%ZAPRET2_BIN%" (
    echo [ERROR] winws2.exe не найден в %ZAPRET2_BIN%!
    echo [INFO] Запустите install-zapret2.cmd для установки
    pause
    exit /b 1
)
echo [OK] winws2.exe найден

if not exist "%ZAPRET2_LUA%\zapret-lib.lua" (
    echo [WARNING] Lua скрипты не найдены в %ZAPRET2_LUA%
    echo [INFO] Скопируйте из zaprets-sources\zapret2\lua\ в bin\zapret2\lua\
) else (
    echo [OK] Lua скрипты найдены
)

REM ========================================
REM Проверка WinDivert
REM ========================================
echo [2/4] Проверка WinDivert...
sc query WinDivert >nul 2>&1
if errorlevel 1 (
    echo [ERROR] WinDivert не установлен!
    echo [INFO] Запустите install-zapret2.cmd или install-windivert.cmd
    pause
    exit /b 1
)
echo [OK] WinDivert установлен

REM ========================================
REM Подготовка файлов
REM ========================================
echo [3/4] Подготовка файлов...
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Очищаем autohostlist при каждом запуске!
echo # Auto-generated hostlist (Zapret2) > "%AUTOHOSTLIST_FILE%"
echo [INFO] Autohostlist очищен

REM ========================================
REM Остановка старых процессов
REM ========================================
echo [4/4] Остановка старых процессов...
taskkill /F /FI "IMAGENAME eq winws2.exe" 2>nul
taskkill /F /FI "IMAGENAME eq winws.exe" 2>nul
taskkill /F /FI "WINDOWTITLE eq Auto-Zapret*" 2>nul
timeout /t 1 /nobreak >nul
echo [OK] Готово

REM ========================================
REM Запуск Auto-Zapret2 Web UI (наследуем права админа)
REM ВАЖНО: НЕ используем start - он теряет права админа!
REM ========================================
echo.
echo Запуск Auto-Zapret2 Web UI...
echo [INFO] Web UI: http://localhost:8000
echo [INFO] Нажмите CTRL+C в этом окне для остановки
echo.

REM Запускаем напрямую чтобы сохранить права администратора
%PYTHON% -m autozapret2.main serve --port 8000

echo.
echo ========================================
echo   ГОТОВО!
echo ========================================
echo.
echo Web UI: http://localhost:8000
echo Логи: %LOG_FILE%
echo Движок: Zapret2 (winws2.exe)
echo Lua: %ZAPRET2_LUA%
echo.
echo ========================================
echo ЗАКРОЙТЕ ЭТО ОКНО для остановки
echo ========================================
echo.

echo.
echo [INFO] Auto-Zapret2 остановлен