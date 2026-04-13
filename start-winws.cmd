@echo off
chcp 65001 >nul
REM Запуск winws с autohostlist для Auto-Zapret

cd /d "%~dp0"

REM Пути
set ZAPRET_DIR=D:\t1pe\Projects\auto-zapret\zapret-src\zapret-v72.12
set BINARIES=%ZAPRET_DIR%\binaries\windows-x86_64
set DATA_DIR=D:\t1pe\Projects\auto-zapret\data
set LOG_DIR=D:\t1pe\Projects\auto-zapret\logs

REM Создаём директории
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Файлы
set AUTOHOSTLIST_FILE=%DATA_DIR%\zapret-hosts-auto.txt
set LOG_FILE=%LOG_DIR%\autohostlist.log
set PID_FILE=%DATA_DIR%\nfqws.pid

REM Стратегии (создаются автоматически)
set STRAT_YOUTUBE=%DATA_DIR%\strat-youtube.txt
set STRAT_DISCORD=%DATA_DIR%\strat-discord.txt
set STRAT_DEFAULT=%DATA_DIR%\strat-default.txt

echo ========================================
echo Auto-Zapret + WinWS
echo ========================================
echo Данные: %DATA_DIR%
echo Логи: %LOG_DIR%
echo.

REM Проверяем запущен ли уже winws
if exist "%PID_FILE%" (
    echo [WARNING] PID file exists. Stopping existing process...
    call "%BINARIES%\killall.exe" -TERM winws 2>nul
    timeout /t 2 /nobreak >nul
    del /F /Q "%PID_FILE%" 2>nul
)

echo [INFO] Starting winws with autohostlist...
echo.

REM Запуск winws
REM --wf-tcp=* : перехватываем ВСЕ TCP соединения (не только 80/443)
REM --wf-udp=* : перехватываем ВСЕ UDP соединения (нужно для Discord, игр и т.д.)
REM --hostlist-auto : файл куда nfqws пишет проблемные домены
REM --hostlist-auto-fail-threshold : через сколько неудач добавлять
REM --hostlist-auto-debug : лог событий
REM --new : поддержка нескольких стратегий
REM --dpi-desync : стратегия по умолчанию для autohostlist

start "WinWS Auto-Zapret" /B "%BINARIES%\winws.exe" ^
  --wf-tcp=* ^
  --wf-udp=* ^
  --filter-tcp=443 ^
  --filter-tcp=80 ^
  --hostlist-auto="%AUTOHOSTLIST_FILE%" ^
  --hostlist-auto-fail-threshold=3 ^
  --hostlist-auto-debug="%LOG_FILE%" ^
  --dpi-desync=fake --dpi-desync-fooling=md5sig

echo [OK] WinWS запущен"
echo [INFO] PID: %ERRORLEVEL%
echo.
echo [INFO] Лог: %LOG_FILE%
echo [INFO] Автохостлист: %AUTOHOSTLIST_FILE%
echo.
echo [INFO] Запустите 'python -m autozapret.main serve --port 8000' для Web UI
echo.

REM Сохраняем PID (приблизительно)
echo %ERRORLEVEL% > "%PID_FILE%"

REM Ждём чтобы окно не закрывалось сразу
echo [INFO] Нажмите Ctrl+C для остановки
pause >nul
