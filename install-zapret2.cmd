@echo off
chcp 65001 >nul
REM ============================================================
REM Установка Zapret2 (winws2) для Windows
REM ============================================================
REM Этот скрипт скачивает готовый бинарник Zapret2 с GitHub
REM и устанавливает его в директорию bin\
REM
REM ТРЕБОВАНИЯ:
REM - Windows 10 или выше
REM - Запуск от имени АДМИНИСТРАТОРА
REM - PowerShell 5+
REM ============================================================

REM ════════════════════════════════════════════════════════════
REM Автоматический запрос прав администратора
REM ════════════════════════════════════════════════════════════
net session >nul 2>&1
if %errorlevel% neq 0 (
    REM Создаём временный VBS скрипт для запроса UAC
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\UAC_Request.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c cd /d ""%~dp0"" && ""%~f0""", "", "runas", 1 >> "%temp%\UAC_Request.vbs"

    REM Запускаем от админа
    cscript.exe //nologo "%temp%\UAC_Request.vbs"

    REM Удаляем VBS
    del "%temp%\UAC_Request.vbs"

    REM Закрываем текущее окно без прав
    exit /b 0
)

setlocal enabledelayedexpansion

echo.
echo ========================================
echo  Zapret2 Installer for Windows
echo ========================================
echo.

echo [1/6] Проверка системных требований...

REM Проверка архитектуры
echo [DEBUG] Архитектура: %PROCESSOR_ARCHITECTURE%
if /i not "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    echo [WARNING] Обнаружена не-x64 архитектура: %PROCESSOR_ARCHITECTURE%
    echo Zapret2 поддерживает только x86_64 (AMD64)
    echo Продолжить? (Y/N)
    choice /C YN /N /M ""
    if errorlevel 2 exit /b 1
)
echo [OK] Архитектура: %PROCESSOR_ARCHITECTURE%

REM Проверка версии Windows
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul') do set "WINBUILD=%%a"
echo [DEBUG] Windows Build: %WINBUILD%
if defined WINBUILD (
    if %WINBUILD% LSS 19041 (
        echo [WARNING] Версия Windows может быть недостаточно новой (Build %WINBUILD%)
        echo Рекомендуется Windows 10 2004+ (Build 19041+)
        echo Продолжить? (Y/N)
        choice /C YN /N /M ""
        if errorlevel 2 exit /b 1
    )
)
echo [OK] Windows Build: %WINBUILD%

echo.
echo [2/6] Создание директории bin\...

cd /d "%~dp0"
if not exist "bin" mkdir bin
if not exist "bin\zapret2" mkdir bin\zapret2
if not exist "bin\zapret2\lua" mkdir bin\zapret2\lua
if not exist "bin\zapret2\files" mkdir bin\zapret2\files
if not exist "bin\zapret2\files\fake" mkdir bin\zapret2\files\fake

echo [OK] Директории созданы

echo.
echo [3/6] Скачивание Zapret2 с GitHub...

REM Определяем последнюю версию
echo Поиск последней версии Zapret2...
for /f "delims=" %%a in ('powershell -NoProfile -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (Invoke-RestMethod -Uri 'https://api.github.com/repos/bol-van/zapret2/releases/latest').tag_name" 2^>nul') do set LATEST_VERSION=%%a

if "!LATEST_VERSION!"=="" (
    echo [ERROR] Не удалось определить последнюю версию Zapret2
    echo Проверьте подключение к интернету
    pause
    exit /b 1
)
echo [OK] Последняя версия: !LATEST_VERSION!

REM Скачиваем архив (формат имени: zapret2-vX.Y.Z.zip)
set DOWNLOAD_URL=https://github.com/bol-van/zapret2/releases/download/!LATEST_VERSION!/zapret2-!LATEST_VERSION!.zip
set DOWNLOAD_FILE=%TEMP%\zapret2-!LATEST_VERSION!.zip

echo Скачивание: !DOWNLOAD_URL!
powershell -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '%DOWNLOAD_FILE%' -UseBasicParsing"

if not exist "%DOWNLOAD_FILE%" (
    echo [ERROR] Не удалось скачать Zapret2
    pause
    exit /b 1
)
for %%A in ("%DOWNLOAD_FILE%") do set DOWNLOAD_SIZE=%%~zA
echo [OK] Загружено: !DOWNLOAD_SIZE! байт

echo.
echo [4/6] Распаковка архива...

REM Распаковываем во временную директорию
set TEMP_EXTRACT=%TEMP%\zapret2-extract
if exist "%TEMP_EXTRACT%" rmdir /s /q "%TEMP_EXTRACT%"
mkdir "%TEMP_EXTRACT%"

powershell -Command "Expand-Archive -Path '%DOWNLOAD_FILE%' -DestinationPath '%TEMP_EXTRACT%' -Force"

echo [OK] Распаковано

echo.
echo [5/6] Копирование файлов...

REM Определяем директорию внутри архива
set "EXTRACTED_DIR=%TEMP_EXTRACT%\zapret2-!LATEST_VERSION!\binaries\windows-x86_64"

if not exist "!EXTRACTED_DIR!\winws2.exe" (
    echo [ERROR] winws2.exe не найден в распакованном архиве!
    echo Ожидаемый путь: !EXTRACTED_DIR!\winws2.exe
    echo Содержимое архива:
    dir /s /b "%TEMP_EXTRACT%"
    pause
    exit /b 1
)

REM Копируем бинарники из windows-x86_64
copy /Y "!EXTRACTED_DIR!\winws2.exe" "bin\zapret2\winws2.exe" >nul
copy /Y "!EXTRACTED_DIR!\cygwin1.dll" "bin\zapret2\cygwin1.dll" >nul
copy /Y "!EXTRACTED_DIR!\WinDivert.dll" "bin\zapret2\WinDivert.dll" >nul
copy /Y "!EXTRACTED_DIR!\WinDivert64.sys" "bin\zapret2\WinDivert64.sys" >nul
if exist "!EXTRACTED_DIR!\killall.exe" copy /Y "!EXTRACTED_DIR!\killall.exe" "bin\zapret2\killall.exe" >nul
if exist "!EXTRACTED_DIR!\mdig.exe" copy /Y "!EXTRACTED_DIR!\mdig.exe" "bin\zapret2\mdig.exe" >nul
if exist "!EXTRACTED_DIR!\ip2net.exe" copy /Y "!EXTRACTED_DIR!\ip2net.exe" "bin\zapret2\ip2net.exe" >nul

REM Копируем Lua скрипты из репозитория zapret2
if exist "zaprets-sources\zapret2\lua" (
    echo Копирование Lua скриптов...
    xcopy /E /I /Y "zaprets-sources\zapret2\lua\*.lua" "bin\zapret2\lua\" >nul
)

REM Копируем fake файлы если есть
if exist "zaprets-sources\zapret2\files\fake" (
    echo Копирование fake файлов...
    xcopy /E /I /Y "zaprets-sources\zapret2\files\fake\*.*" "bin\zapret2\files\fake\" >nul
)

echo [OK] Файлы скопированы

echo.
echo [6/6] Установка драйвера WinDivert...

REM Копируем sys в системную директорию
if not exist "C:\Windows\System32\drivers" mkdir "C:\Windows\System32\drivers"
copy /Y "WinDivert64.sys" "C:\Windows\System32\drivers\WinDivert64.sys" >nul

REM Проверяем статус драйвера
sc query WinDivert >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Драйвер WinDivert уже установлен
    REM Пробуем запустить
    sc start WinDivert >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Драйвер WinDivert запущен
    ) else (
        echo [INFO] Драйвер WinDivert уже работает
    )
) else (
    echo Регистрация WinDivert64.sys...
    sc create WinDivert binPath= "C:\Windows\System32\drivers\WinDivert64.sys" type= kernel start= demand error= normal DisplayName= "WinDivert Packet Filter" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Драйвер WinDivert установлен
        sc start WinDivert >nul 2>&1
        if %errorlevel% equ 0 (
            echo [OK] Драйвер WinDivert запущен
        ) else (
            echo [WARNING] Не удалось запустить драйвер
            echo Попробуйте перезагрузить компьютер
        )
    ) else (
        echo [WARNING] Не удалось зарегистрировать драйвер (ошибка 1072)
        echo.
        echo РЕШЕНИЕ: Перезагрузите компьютер и драйвер заработает автоматически.
        echo Или запустите вручную от администратора:
        echo   sc start WinDivert
    )
)

cd /d "%~dp0"

REM Очистка временных файлов
del /F /Q "%DOWNLOAD_FILE%" >nul
rmdir /s /q "%TEMP_EXTRACT%" >nul

echo.
echo ========================================
echo  Zapret2 успешно установлен!
echo ========================================
echo.
echo Файлы установлены в: bin\zapret2\
echo.
echo Содержимое:
dir /b "bin\zapret2"
echo.
echo Lua скрипты: bin\zapret2\lua\
if exist "bin\zapret2\lua" dir /b "bin\zapret2\lua"
echo.
echo Fake файлы: bin\zapret2\files\fake\
if exist "bin\zapret2\files\fake" dir /b "bin\zapret2\files\fake"
echo.
echo Для запуска auto-zapret с Zapret2:
echo   start-auto-zapret2.bat
echo.
echo Для ручной проверки winws2:
echo   bin\zapret2\winws2.exe --help
echo.
pause
