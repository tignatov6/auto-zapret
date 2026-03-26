"""
Тест: Проверка работы winws и стратегий
"""

import asyncio
import subprocess
import time
from pathlib import Path

# ══════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════

WINWS_PID_FILE = Path("data/nfqws.pid")
AUTOHOSTLIST_FILE = Path("data/zapret-hosts-auto.txt")
TEST_DOMAIN = "www.youtube.com"

# ══════════════════════════════════════════════════════════
# ТЕСТ 1: Проверка что winws запущен
# ══════════════════════════════════════════════════════════

def check_winws_running():
    """Проверка что winws запущен"""
    print("\n" + "="*60)
    print("ТЕСТ 1: Проверка winws")
    print("="*60)
    
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq winws.exe', '/FO', 'CSV', '/NH'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'winws.exe' in result.stdout:
            print(f"✅ winws.exe ЗАПУЩЕН")
            
            # Получим PID
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq winws.exe', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = result.stdout.strip().split('\n')
            if lines:
                parts = lines[0].split(',')
                pid = parts[1].strip('"')
                print(f"   PID: {pid}")
            return True
        else:
            print(f"❌ winws.exe НЕ ЗАПУЩЕН")
            return False
            
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 2: Прямой curl без стратегии
# ══════════════════════════════════════════════════════════

async def test_curl_no_strategy():
    """Тест curl без стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 2: curl без стратегии")
    print("="*60)
    
    try:
        start = time.time()
        
        process = await asyncio.create_subprocess_exec(
            'curl',
            '-s', '-o', 'nul', '-w', '%{http_code}|%{time_total}',
            '--max-time', '5',
            '--connect-timeout', '5',
            f'https://{TEST_DOMAIN}/',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore').strip()
            parts = output.split('|')
            if len(parts) == 2:
                http_code = int(parts[0])
                time_total = float(parts[1])
                print(f"✅ curl УСПЕХ: HTTP {http_code}, {time_total*1000:.0f}ms")
                return True
            else:
                print(f"❌ curl parse error: {output}")
                return False
        else:
            print(f"❌ curl FAILED: code={process.returncode}, {rtt:.0f}ms")
            return False
            
    except asyncio.TimeoutError:
        print(f"❌ curl TIMEOUT: 5 сек")
        return False
    except FileNotFoundError:
        print(f"❌ curl НЕ НАЙДЕН (нет в PATH)")
        return False
    except Exception as e:
        print(f"❌ curl ERROR: {e}")
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 3: Применение стратегии через executor
# ══════════════════════════════════════════════════════════

async def test_apply_strategy():
    """Применение тестовой стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 3: Применение стратегии")
    print("="*60)
    
    try:
        from autozapret.executor import Executor
        from autozapret.config import get_config
        
        config = get_config()
        executor = Executor(config)
        
        # Проверяем PID
        pid = executor._find_nfqws_pid()
        if not pid:
            print(f"❌ nfqws/winws НЕ НАЙДЕН")
            return False
        
        print(f"✅ nfqws/winws найден: PID={pid}")
        
        # Очищаем autohostlist
        if AUTOHOSTLIST_FILE.exists():
            AUTOHOSTLIST_FILE.unlink()
            print(f"✅ autohostlist очищен")
        
        # Применяем стратегию
        strategy = '--dpi-desync=fake --dpi-desync-fooling=md5sig'
        success, msg = await executor.apply_strategy(TEST_DOMAIN, strategy)
        
        if success:
            print(f"✅ Стратегия применена: {msg}")
        else:
            print(f"❌ Не удалось применить: {msg}")
            return False
        
        # Ждём применения
        print(f"   Ожидание применения (3 сек)...")
        await asyncio.sleep(3)
        
        # Проверяем что домен в файле
        if AUTOHOSTLIST_FILE.exists():
            content = AUTOHOSTLIST_FILE.read_text(encoding='utf-8')
            if TEST_DOMAIN in content:
                print(f"✅ Домен в autohostlist")
                print(f"   Содержимое: {content.strip()[:100]}")
                return True
            else:
                print(f"❌ Домен НЕ в autohostlist")
                print(f"   Содержимое файла: {content[:200] if content else 'пусто'}")
                return False
        else:
            print(f"❌ autohostlist файл НЕ создан")
            return False
        
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 4: curl после применения стратегии
# ══════════════════════════════════════════════════════════

async def test_curl_with_strategy():
    """Тест curl с применённой стратегией"""
    print("\n" + "="*60)
    print("ТЕСТ 4: curl с стратегией")
    print("="*60)
    
    try:
        start = time.time()
        
        process = await asyncio.create_subprocess_exec(
            'curl',
            '-s', '-o', 'nul', '-w', '%{http_code}|%{time_total}',
            '--max-time', '5',
            '--connect-timeout', '5',
            f'https://{TEST_DOMAIN}/',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore').strip()
            parts = output.split('|')
            if len(parts) == 2:
                http_code = int(parts[0])
                time_total = float(parts[1])
                print(f"✅ curl УСПЕХ: HTTP {http_code}, {time_total*1000:.0f}ms")
                return True
            else:
                print(f"❌ curl parse error: {output}")
                return False
        else:
            print(f"❌ curl FAILED: code={process.returncode}, {rtt:.0f}ms")
            stderr_text = stderr.decode('utf-8', errors='ignore')[:200]
            print(f"   stderr: {stderr_text}")
            return False
            
    except asyncio.TimeoutError:
        print(f"❌ curl TIMEOUT: 5 сек")
        return False
    except Exception as e:
        print(f"❌ curl ERROR: {e}")
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 5: Проверка стратегии через strategy_tester
# ══════════════════════════════════════════════════════════

async def test_strategy_tester():
    """Тест strategy_tester"""
    print("\n" + "="*60)
    print("ТЕСТ 5: Strategy Tester")
    print("="*60)
    
    try:
        from autozapret.strategy_tester import get_tester
        from autozapret.storage import Storage
        from autozapret.executor import Executor
        from autozapret.config import get_config
        
        config = get_config()
        storage = Storage(config.database_path)
        await storage.connect()
        
        executor = Executor(config)
        tester = get_tester(storage, executor, config)
        
        # Тестируем стратегию
        print(f"Тестирование стратегии на {TEST_DOMAIN}...")
        result = await tester.test_strategy(
            domain=TEST_DOMAIN,
            strategy_params='--dpi-desync=fake --dpi-desync-fooling=md5sig',
            timeout=5.0
        )
        
        print(f"Результат:")
        print(f"   Статус: {result.status.value}")
        print(f"   Domain: {result.domain}")
        print(f"   Response time: {result.response_time_ms:.0f}ms")
        if result.error:
            print(f"   Error: {result.error}")
        if result.details:
            print(f"   Details: {result.details}")
        
        await storage.close()
        return result.status.value == 'works'
        
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

# ══════════════════════════════════════════════════════════
# ГЛАВНЫЙ ТЕСТ
# ══════════════════════════════════════════════════════════

async def main():
    print("\n" + "="*60)
    print("🔍 ПРОВЕРКА РАБОТЫ WINWS И СТРАТЕГИЙ")
    print("="*60)
    
    results = {}
    
    # Тест 1: winws запущен?
    results['winws_running'] = check_winws_running()
    
    if not results['winws_running']:
        print("\n" + "="*60)
        print("❌ WINWS НЕ ЗАПУЩЕН!")
        print("="*60)
        print("\nЗапусти свой батник и потом перезапусти этот тест.")
        print("Или запусти auto-zapret:")
        print("  python -m autozapret.main serve")
        return
    
    await asyncio.sleep(1)
    
    # Тест 2: curl без стратегии
    results['curl_no_strategy'] = await test_curl_no_strategy()
    
    await asyncio.sleep(1)
    
    # Тест 3: Применение стратегии
    results['apply_strategy'] = await test_apply_strategy()
    
    await asyncio.sleep(1)
    
    # Тест 4: curl с стратегией
    results['curl_with_strategy'] = await test_curl_with_strategy()
    
    await asyncio.sleep(1)
    
    # Тест 5: strategy_tester
    results['strategy_tester'] = await test_strategy_tester()
    
    # Итоги
    print("\n" + "="*60)
    print("📊 ИТОГИ")
    print("="*60)
    
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test}")
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    print(f"\nПройдено: {passed}/{total} тестов")
    
    if passed == total:
        print("\n✅ Все тесты пройдены!")
    elif results['curl_with_strategy']:
        print("\n✅ curl РАБОТАЕТ с стратегией!")
        print("   → Проблема в brute force логике")
    else:
        print("\n❌ curl НЕ РАБОТАЕТ с стратегией")
        print("   → winws не перехватывает curl трафик")

if __name__ == '__main__':
    asyncio.run(main())
