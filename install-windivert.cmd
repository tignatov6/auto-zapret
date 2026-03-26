@echo off
chcp 65001 >nul
setlocal

REM ========================================
REM Установка драйвера WinDivert
REM Запускать ОТ АДМИНИСТРАТОРА!
REM ========================================

title WinDivert Installer

echo ========================================
echo   WinDivert Driver Installer
echo ========================================
echo.

cd /d "%~dp0"

set "ZAPRET_DIR=%CD%\zapret-src\zapret-v72.12"
set "BINARIES=%ZAPRET_DIR%\binaries\windows-x86_64"
set "WINDIVERT_SYS=%BINARIES%\WinDivert64.sys"

REM Проверка прав администратора
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Запустите скрипт ОТ АДМИНИСТРАТОРА!
    echo.
    pause
    exit /b 1
)

echo [1/4] Проверка файлов WinDivert...
if not exist "%WINDIVERT_SYS%" (
    echo [ERROR] Файл не найден: %WINDIVERT_SYS%
    echo [INFO] Убедитесь что Zapret распакован
    pause
    exit /b 1
)
echo [OK] Файлы найдены

echo.
echo [2/4] Удаление старого драйвера (если есть)...
sc stop WinDivert >nul 2>&1
sc delete WinDivert >nul 2>&1
timeout /t 2 /nobreak >nul
echo [OK] Старый драйвер удалён

echo.
echo [3/4] Установка нового драйвера...
sc create WinDivert type= kernel binPath= "%WINDIVERT_SYS%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Не удалось создать службу WinDivert
    pause
    exit /b 1
)
echo [OK] Служба WinDivert создана

echo.
echo [4/4] Запуск драйвера...
sc start WinDivert >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Не удалось запустить службу WinDivert
    echo [INFO] Это нормально, драйвер загрузится при использовании
) else (
    echo [OK] Драйвер WinDivert запущен
)

echo.
echo ========================================
echo   Установка завершена!
echo ========================================
echo.
echo [INFO] Теперь можете запустить:
echo       start-auto-zapret.bat
echo.

pause
