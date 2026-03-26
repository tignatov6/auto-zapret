"""
Тест: Запуск заведомо рабочей стратегии из Ultimate F.bat
"""

import asyncio
import subprocess
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
WINWS_PATH = BASE_DIR / "bin" / "winws.exe"
FAKE_QUIC = BASE_DIR / "files" / "fake" / "quic_initial_facebook_com.bin"
FAKE_TLS = BASE_DIR / "files" / "fake" / "dtls_clienthello_w3_org.bin"

TEST_DOMAIN = "www.youtube.com"

def kill_winws():
    """Убить winws"""
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'winws.exe'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except:
        pass
    time.sleep(1)

async def test_curl():
    """Тест curl"""
    try:
        start = time.time()
        process = await asyncio.create_subprocess_exec(
            'curl', '-s', '-o', 'nul', '-w', '%{http_code}|%{time_total}',
            '--max-time', '5', '--connect-timeout', '5',
            f'https://{TEST_DOMAIN}/',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode().strip()
            parts = output.split('|')
            if len(parts) == 2:
                http_code = int(parts[0])
                return True, f"HTTP {http_code}, {rtt:.0f}ms"
        return False, f"code={process.returncode}, {rtt:.0f}ms"
    except Exception as e:
        return False, str(e)

async def run_ultimate_strategy():
    """Запуск стратегии из Ultimate F.bat"""
    print("\n" + "="*60)
    print("ТЕСТ: Запуск рабочей стратегии из Ultimate F.bat")
    print("="*60)
    
    # Стратегия для YouTube из батника:
    # --filter-tcp=443 --hostlist="%LISTS%list-google.txt" 
    # --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 
    # --dpi-desync-fooling=ts --dpi-desync-repeats=8 
    # --dpi-desync-split-seqovl-pattern="bin/tls_clienthello_www_google_com.bin" 
    # --dpi-desync-fake-tls="bin/tls_clienthello_www_google_com.bin" --ip-id=zero
    
    cmd = [
        str(WINWS_PATH),
        "--wf-tcp=80,443",
        "--filter-tcp=443",
        "--dpi-desync=fake,multisplit",
        "--dpi-desync-split-seqovl=681",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-repeats=8",
        f"--dpi-desync-split-seqovl-pattern={BASE_DIR / 'files' / 'fake' / 'tls_clienthello_www_google_com.bin'}",
        f"--dpi-desync-fake-tls={BASE_DIR / 'files' / 'fake' / 'tls_clienthello_www_google_com.bin'}",
        "--ip-id=zero"
    ]
    
    print(f"\nКоманда:")
    print(" ".join(cmd))
    
    # Тест ДО запуска winws
    print(f"\n📊 Тест ДО запуска winws:")
    ok, msg = await test_curl()
    print(f"   {'✅' if ok else '❌'} {msg}")
    
    # Запуск winws
    print(f"\n🚀 Запуск winws...")
    proc = subprocess.Popen(cmd)
    
    # Ждём запуска
    print(f"   Ожидание 5 сек...")
    await asyncio.sleep(5)
    
    # Тест ПОСЛЕ запуска winws
    print(f"\n📊 Тест ПОСЛЕ запуска winws:")
    ok, msg = await test_curl()
    print(f"   {'✅' if ok else '❌'} {msg}")
    
    # Остановка
    print(f"\n🛑 Остановка winws...")
    proc.terminate()
    kill_winws()
    
    return ok

async def run_simple_fake_strategy():
    """Запуск простой fake стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ: Запуск простой fake стратегии")
    print("="*60)
    
    cmd = [
        str(WINWS_PATH),
        "--wf-tcp=80,443",
        "--filter-tcp=443",
        "--dpi-desync=fake",
        "--dpi-desync-fooling=md5sig",
        "--dpi-desync-repeats=5"
    ]
    
    print(f"\nКоманда:")
    print(" ".join(cmd))
    
    # Тест ДО
    print(f"\n📊 Тест ДО запуска winws:")
    ok, msg = await test_curl()
    print(f"   {'✅' if ok else '❌'} {msg}")
    
    # Запуск
    print(f"\n🚀 Запуск winws...")
    proc = subprocess.Popen(cmd)
    
    await asyncio.sleep(5)
    
    # Тест ПОСЛЕ
    print(f"\n📊 Тест ПОСЛЕ запуска winws:")
    ok, msg = await test_curl()
    print(f"   {'✅' if ok else '❌'} {msg}")
    
    # Остановка
    print(f"\n🛑 Остановка winws...")
    proc.terminate()
    kill_winws()
    
    return ok

async def main():
    print("\n🔍 ПРОВЕРКА РАБОЧИХ СТРАТЕГИЙ")
    print("="*60)
    
    # Проверка наличия файлов
    print(f"\nПроверка файлов:")
    print(f"   winws.exe: {'✅' if WINWS_PATH.exists() else '❌'}")
    print(f"   tls_clienthello_www_google_com.bin: {'✅' if (BASE_DIR / 'files' / 'fake' / 'tls_clienthello_www_google_com.bin').exists() else '❌'}")
    print(f"   quic_initial_facebook_com.bin: {'✅' if (BASE_DIR / 'files' / 'fake' / 'quic_initial_facebook_com.bin').exists() else '❌'}")
    
    # Тест 1: Простая стратегия
    result1 = await run_simple_fake_strategy()
    await asyncio.sleep(2)
    
    # Тест 2: Ultimate стратегия
    result2 = await run_ultimate_strategy()
    
    # Итоги
    print("\n" + "="*60)
    print("ИТОГИ")
    print("="*60)
    print(f"Простая fake стратегия: {'✅ РАБОТАЕТ' if result1 else '❌ НЕ РАБОТАЕТ'}")
    print(f"Ultimate стратегия: {'✅ РАБОТАЕТ' if result2 else '❌ НЕ РАБОТАЕТ'}")

if __name__ == '__main__':
    asyncio.run(main())
