"""
Диагностика brute force - проверка каждого компонента
"""

import asyncio
import aiohttp
import time
import sys

# ══════════════════════════════════════════════════════════
# ТЕСТ 1: Проверка доступности youtube.com
# ══════════════════════════════════════════════════════════

async def test_youtube_direct():
    """Прямой тест youtube.com без стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 1: Прямое подключение к youtube.com")
    print("="*60)
    
    try:
        start = time.time()
        
        # Правильный способ установки server_hostname
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        conn = aiohttp.TCPConnector(ssl=ssl_context, limit=1)
        session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=10))
        
        async with session.get('https://www.youtube.com/', timeout=aiohttp.ClientTimeout(total=10)) as resp:
            rtt = (time.time() - start) * 1000
            await resp.read()
            await session.close()
            
            print(f"✅ УСПЕХ: youtube.com доступен")
            print(f"   Статус: {resp.status}")
            print(f"   RTT: {rtt:.0f}ms")
            return True
            
    except asyncio.TimeoutError:
        print(f"❌ ОШИБКА: Timeout (10 сек)")
        return False
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 2: Проверка доступности discord.com
# ══════════════════════════════════════════════════════════

async def test_discord_direct():
    """Прямой тест discord.com без стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 2: Прямое подключение к discord.com")
    print("="*60)
    
    try:
        start = time.time()
        
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        conn = aiohttp.TCPConnector(ssl=ssl_context, limit=1)
        session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=10))
        
        async with session.get('https://discord.com/', timeout=aiohttp.ClientTimeout(total=10)) as resp:
            rtt = (time.time() - start) * 1000
            await resp.read()
            await session.close()
            
            print(f"✅ УСПЕХ: discord.com доступен")
            print(f"   Статус: {resp.status}")
            print(f"   RTT: {rtt:.0f}ms")
            return True
            
    except asyncio.TimeoutError:
        print(f"❌ ОШИБКА: Timeout (10 сек)")
        return False
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 3: Проверка executor
# ══════════════════════════════════════════════════════════

async def test_executor():
    """Проверка что executor может применять стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 3: Проверка Executor")
    print("="*60)
    
    try:
        from autozapret.executor import Executor
        from autozapret.config import get_config
        
        config = get_config()
        executor = Executor(config)
        
        # Проверяем что executor инициализирован
        print(f"✅ Executor инициализирован")
        print(f"   Config: {config}")
        print(f"   nfqws_log_file: {config.nfqws_log_file}")
        print(f"   auto_hostlist_file: {config.auto_hostlist_file}")
        
        # Проверяем наличие nfqws/winws
        pid = executor._find_nfqws_pid()
        if pid:
            print(f"✅ nfqws/winws найден: PID={pid}")
        else:
            print(f"❌ nfqws/winws НЕ найден")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 4: Проверка strategy_tester
# ══════════════════════════════════════════════════════════

async def test_strategy_tester():
    """Проверка strategy_tester на простой стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 4: Проверка Strategy Tester")
    print("="*60)
    
    try:
        from autozapret.strategy_tester import StrategyTester, get_tester
        from autozapret.storage import Storage
        from autozapret.config import get_config
        
        config = get_config()
        storage = Storage(config.database_path)
        await storage.connect()
        
        from autozapret.executor import Executor
        executor = Executor(config)
        
        tester = get_tester(storage, executor, config)
        
        # Проверяем калибровку
        print("Калибровка таймаутов...")
        calibration = await tester.calibrate()
        print(f"✅ Калибровка:")
        print(f"   Mean RTT: {calibration.mean_rtt_ms:.0f}ms")
        print(f"   Timeout base: {calibration.timeout_base:.2f}s")
        print(f"   Timeout extended: {calibration.timeout_extended:.2f}s")
        print(f"   Success rate: {calibration.success_rate:.1%}")
        
        # Тестируем простую стратегию (без изменений)
        print("\nТестирование стратегии 'fake' на youtube.com...")
        result = await tester.test_strategy(
            domain='www.youtube.com',
            strategy_params='--dpi-desync=fake --dpi-desync-fooling=md5sig',
            timeout=5.0  # Явно указываем таймаут
        )
        
        print(f"Результат:")
        print(f"   Статус: {result.status.value}")
        print(f"   Domain: {result.domain}")
        print(f"   Params: {result.strategy_params[:50]}...")
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
# ТЕСТ 5: Проверка генератора стратегий
# ══════════════════════════════════════════════════════════

async def test_strategy_generator():
    """Проверка генератора стратегий"""
    print("\n" + "="*60)
    print("ТЕСТ 5: Проверка Strategy Generator")
    print("="*60)
    
    try:
        from autozapret.strategy_generator import StrategyGenerator
        
        gen = StrategyGenerator(has_fake_files=True)
        strategies = gen.generate_all()
        
        print(f"✅ Сгенерировано {len(strategies)} стратегий")
        
        # Показываем первые 10
        print("\nПервые 10 стратегий:")
        for i, s in enumerate(strategies[:10], 1):
            print(f"   {i}. {s.name}: {s.to_params()[:60]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

# ══════════════════════════════════════════════════════════
# ТЕСТ 6: Проверка что nfqws применяет стратегии
# ══════════════════════════════════════════════════════════

async def test_nfqws_apply():
    """Проверка что nfqws применяет стратегии"""
    print("\n" + "="*60)
    print("ТЕСТ 6: Проверка применения стратегии nfqws")
    print("="*60)
    
    try:
        from autozapret.executor import Executor
        from autozapret.config import get_config
        
        config = get_config()
        executor = Executor(config)
        
        # Применяем тестовую стратегию
        print("Применяем тестовую стратегию...")
        success, msg = await executor.apply_strategy('www.youtube.com', '--dpi-desync=fake')
        
        if success:
            print(f"✅ Стратегия применена: {msg}")
        else:
            print(f"❌ Не удалось применить: {msg}")
        
        # Ждём применения
        print("Ожидание применения (2 сек)...")
        await asyncio.sleep(2)
        
        # Проверяем что стратегия в файле
        import aiofiles
        from pathlib import Path
        
        autohostlist_path = Path(config.auto_hostlist_file)
        if not autohost_path.is_absolute():
            autohostlist_path = Path.cwd() / autohostlist_path
        
        if autohostlist_path.exists():
            async with aiofiles.open(autohostlist_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                if 'www.youtube.com' in content:
                    print(f"✅ Домен в autohostlist")
                else:
                    print(f"❌ Домен НЕ в autohostlist")
        else:
            print(f"❌ Autohostlist файл не найден: {autohostlist_path}")
        
        return success
        
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
    print("🔍 ДИАГНОСТИКА BRUTE FORCE")
    print("="*60)
    print(f"Платформа: {sys.platform}")
    print(f"Python: {sys.version}")
    
    results = {}
    
    # Тест 1: Прямое подключение
    results['youtube_direct'] = await test_youtube_direct()
    await asyncio.sleep(1)
    
    # Тест 2: Discord
    results['discord_direct'] = await test_discord_direct()
    await asyncio.sleep(1)
    
    # Тест 3: Executor
    results['executor'] = await test_executor()
    await asyncio.sleep(1)
    
    # Тест 4: Strategy Tester
    results['strategy_tester'] = await test_strategy_tester()
    await asyncio.sleep(1)
    
    # Тест 5: Generator
    results['generator'] = await test_strategy_generator()
    await asyncio.sleep(1)
    
    # Тест 6: NFQWS apply
    results['nfqws_apply'] = await test_nfqws_apply()
    
    # Итоги
    print("\n" + "="*60)
    print("📊 ИТОГИ ДИАГНОСТИКИ")
    print("="*60)
    
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test}")
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    print(f"\nПройдено: {passed}/{total} тестов")
    
    if passed == total:
        print("\n✅ Все тесты пройдены!")
    else:
        print("\n❌ Есть проблемы - см. выводы выше")

if __name__ == '__main__':
    asyncio.run(main())
