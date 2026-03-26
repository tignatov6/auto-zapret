"""
Тест полного цикла работы Auto-Zapret
Проверка добавления доменов t.me, discord.com, youtube.com
"""

import asyncio
import os
from datetime import datetime
from autozapret.config import get_config
from autozapret.storage import Storage
from autozapret.executor import Executor
from autozapret.monitor import LogParser, EventType, AutoHostlistEvent
from autozapret.analyzer import Analyzer

async def test_full_cycle():
    """Тестирование полного цикла работы"""
    print("=" * 60)
    print("Auto-Zapret Full Cycle Test")
    print("=" * 60)
    
    config = get_config()
    print(f"\n📁 Config:")
    print(f"   Hostlists dir: {config.hostlists_dir}")
    print(f"   Strategy prefix: {config.strategy_prefix}")
    print(f"   Fail threshold: {config.fail_threshold}")
    print(f"   Database: {config.database_path}")
    
    # Инициализация хранилища
    print("\n📦 Initializing storage...")
    storage = Storage(config.database_path)
    await storage.connect()
    
    # Проверяем стратегии
    strategies = await storage.list_strategies()
    print(f"   Found {len(strategies)} strategies:")
    for s in strategies:
        print(f"   - {s.name} (priority={s.priority}, success_rate={s.success_rate:.2f})")
    
    # Инициализация executor
    print("\n⚙️  Initializing executor...")
    executor = Executor(config)
    
    # Создаём файлы стратегий если не существуют
    print("\n📝 Creating strategy files...")
    for strat in strategies:
        filepath = config.get_strategy_file(strat.name)
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"# Strategy: {strat.name}\n")
                f.write(f"# Params: {strat.zapret_params}\n")
                f.write(f"# Created: {datetime.now().isoformat()}\n")
            print(f"   Created: {filepath}")
        else:
            print(f"   Exists: {filepath}")
    
    # Создаём autohostlist файл
    autohostlist_path = config.get_auto_hostlist_path()
    if not os.path.exists(autohostlist_path):
        with open(autohostlist_path, 'w', encoding='utf-8') as f:
            f.write("# Auto-generated hostlist\n")
        print(f"   Created: {autohostlist_path}")
    
    # Тестовые домены для проверки
    test_domains = [
        ("t.me", "telegram"),
        ("discord.com", "discord"),
        ("www.youtube.com", "youtube")
    ]
    
    print("\n🧪 Testing domain addition...")
    
    for domain, strategy_name in test_domains:
        print(f"\n--- Testing: {domain} ---")
        
        # Проверяем есть ли уже стратегия
        existing = await storage.get_domain(domain)
        if existing:
            print(f"   ⚠️  Domain already has strategy: {existing.strategy_id}")
            continue
        
        # Находим стратегию по имени
        strategy = await storage.get_strategy(strategy_name)
        if not strategy:
            # Используем default
            strategy = await storage.get_strategy("default")
            print(f"   ⚠️  Strategy '{strategy_name}' not found, using 'default'")
        
        if not strategy:
            print(f"   ❌ No strategies available!")
            continue
        
        print(f"   📌 Strategy: {strategy.name} (params: {strategy.zapret_params[:50]}...)")
        
        # Добавляем домен в базу
        await storage.assign_domain(domain, strategy.id)
        print(f"   ✅ Domain assigned to strategy in DB")
        
        # Добавляем домен в файл стратегии через executor
        filepath = config.get_strategy_file(strategy.name)
        success, msg = executor.add_domain_to_hostlist(filepath, domain)
        if success:
            print(f"   ✅ Domain added to file: {filepath}")
        else:
            print(f"   ⚠️  {msg}")
    
    # Проверяем содержимое файлов
    print("\n📄 Strategy file contents:")
    for strat in strategies:
        filepath = config.get_strategy_file(strat.name)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    lines = [l for l in content.split('\n') if l and not l.startswith('#')]
                    if lines:
                        print(f"\n   {strat.name}:")
                        for line in lines:
                            print(f"      - {line}")
    
    # Проверяем autohostlist
    print("\n📄 Autohostlist contents:")
    if os.path.exists(autohostlist_path):
        with open(autohostlist_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if content.strip():
                print(f"   {content[:500]}...")
            else:
                print("   (empty)")
    
    # Статистика
    print("\n📊 Final Statistics:")
    domains = await storage.list_domains()
    print(f"   Total domains: {len(domains)}")
    for d in domains:
        strat = await storage.get_strategy_by_id(d.strategy_id)
        strat_name = strat.name if strat else f"ID:{d.strategy_id}"
        status = "✓" if d.is_active else "✗"
        print(f"   {status} {d.domain} → {strat_name}")
    
    # Cleanup
    await storage.close()
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_full_cycle())
