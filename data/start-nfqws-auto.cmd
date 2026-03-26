@echo off
chcp 65001 >nul
REM Auto-generated winws startup script
REM Generated at: 2026-03-26T23:51:51.361305

cd /d "%~dp0"

REM Configuration
set ZAPRET_DIR=D:\t1pe\Projects\auto-zapret\zapret-src
set BINARIES=%ZAPRET_DIR%\binaries\windows-x86_64
set DATA_DIR=D:\t1pe\Projects\auto-zapret\data

REM Create directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

REM PID file
set PID_FILE=%DATA_DIR%\nfqws.pid

REM Stop existing process
if exist "%PID_FILE%" (
    echo Stopping existing winws process...
    "%BINARIES%\killall.exe" -TERM winws 2>nul
    timeout /t 2 /nobreak >nul
    del /F /Q "%PID_FILE%" 2>nul
)

echo Starting winws...

REM Start winws
start "WinWS" /B "%BINARIES%\winws.exe" ^
  --wf-l3=ipv4 ^
  --wf-tcp=80,443 ^
  --wf-udp=443 ^
  --dpi-desync-fake-quic=D:\t1pe\Projects\auto-zapret\files\fake\quic_initial_facebook_com.bin ^
  --dpi-desync-fake-tls=D:\t1pe\Projects\auto-zapret\files\fake\dtls_clienthello_w3_org.bin ^
  --dpi-desync-fake-http=D:\t1pe\Projects\auto-zapret\files\fake\http_iana_org.bin ^
  --filter-udp=443 ^
  --dpi-desync=fake ^
  --dpi-desync-repeats=4 ^
  --new ^
  --filter-udp=443 ^
  --dpi-desync=ipfrag2 ^
  --dpi-desync-ipfrag-pos-udp=24 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_59396e745b7b.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=1 ^
  --wssize=1:6 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_a875bc6f1701.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=2 ^
  --dpi-desync-split-seqovl=2 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_5f090db05800.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=sniext+4 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_6cfcaab52a2d.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=1,sniext+1,host+1,midsld-2,midsld,midsld+2 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_51f929425c44.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=10 ^
  --dpi-desync-split-seqovl=2 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_285387f2c904.txt ^
  --dpi-desync=multidisorder ^
  --dpi-desync-split-pos=10,midsld ^
  --dpi-desync-split-seqovl=2 ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_6f6e825003df.txt ^
  --dpi-desync=fake,multisplit ^
  --dpi-desync-ttl=1 ^
  --dpi-desync-autottl=-4 ^
  --orig-ttl=1 ^
  --orig-mod-start=s1 ^
  --orig-mod-cutoff=d1 ^
  --dpi-desync-split-pos=midsld ^
  --new ^
  --filter-tcp=443 ^
  --hostlist=D:\t1pe\Projects\auto-zapret\data\strat-strategy_34b174c5a02e.txt ^
  --dpi-desync=fake,multidisorder ^
  --dpi-desync-fooling=badsum ^
  --dpi-desync-split-pos=1 ^
  --new ^
  --filter-tcp=80,443 ^
  --hostlist-auto=D:\t1pe\Projects\auto-zapret\data\zapret-hosts-auto.txt ^
  --hostlist-auto-fail-threshold=3 ^
  --hostlist-auto-debug=D:\t1pe\Projects\auto-zapret\logs\autohostlist.log

echo WinWS started
echo %ERRORLEVEL% > "%PID_FILE%"

pause >nul