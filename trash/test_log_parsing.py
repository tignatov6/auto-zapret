"""
Тест парсинга логов и обработки событий для t.me, discord.com, youtube.com
"""

import asyncio
from autozapret.monitor import LogParser, EventType

def test_log_parser():
    """Тестирование парсера логов"""
    print("=" * 60)
    print("Log Parser Test")
    print("=" * 60)
    
    parser = LogParser()
    
    # Тестовые строки из реального лога
    test_lines = [
        # youtube.com
        "21.03.2026 01:18:18 : www.youtube.com : profile 1 : client 192.168.1.74:53471 : proto tls : fail counter 3/3",
        "21.03.2026 01:18:18 : www.youtube.com : profile 1 : client 192.168.1.74:53471 : proto tls : adding to D:\\t1pe\\Projects\\auto-zapret\\data\\zapret-hosts-auto.txt",
        
        # discord.com
        "21.03.2026 01:18:54 : discord.com : profile 1 : client 192.168.1.74:62559 : proto tls : fail counter 3/3",
        "21.03.2026 01:18:54 : discord.com : profile 1 : client 192.168.1.74:62559 : proto tls : adding to D:\\t1pe\\Projects\\auto-zapret\\data\\zapret-hosts-auto.txt",
        
        # t.me
        "21.03.2026 01:19:11 : t.me : profile 1 : client 192.168.1.74:49486 : proto tls : fail counter 3/3",
        "21.03.2026 01:19:11 : t.me : profile 1 : client 192.168.1.74:49486 : proto tls : adding to D:\\t1pe\\Projects\\auto-zapret\\data\\zapret-hosts-auto.txt",
        
        # Дополнительные события
        "21.03.2026 01:15:41 : www.youtube.com : profile 1 : client 192.168.1.74:59459 : proto tls : fail counter 1/3",
        "21.03.2026 01:18:09 : discord.com : profile 1 : client 192.168.1.74:53437 : proto tls : fail counter 1/3",
        "21.03.2026 01:18:52 : t.me : profile 1 : client 192.168.1.74:50784 : proto tls : fail counter 1/3",
    ]
    
    print("\n📝 Parsing test lines:\n")
    
    for line in test_lines:
        event = parser.parse_line(line)
        if event:
            print(f"✅ Parsed: {event.domain}")
            print(f"   Type: {event.event_type.value}")
            print(f"   Counter: {event.fail_counter}/{event.fail_threshold}")
            print(f"   Protocol: {event.protocol}")
            print(f"   Client: {event.client}")
            print(f"   Profile: {event.profile_id}")
            if event.strategy_file:
                print(f"   Strategy file: {event.strategy_file}")
            print()
        else:
            print(f"❌ Failed to parse: {line[:50]}...")
            print()
    
    print("=" * 60)
    print("Parser test completed!")
    print("=" * 60)


async def test_monitor_with_real_log():
    """Тестирование Monitor с реальным логом"""
    print("\n" + "=" * 60)
    print("Monitor Real Log Test")
    print("=" * 60)
    
    from autozapret.config import get_config
    from autozapret.monitor import Monitor
    
    config = get_config()
    monitor = Monitor(config)
    
    # Читаем существующий лог
    print(f"\n📖 Reading log file: {config.nfqws_log_file}")
    events = await monitor.read_log_file()
    
    print(f"   Found {len(events)} events\n")
    
    # Фильтруем события для t.me, discord.com, youtube.com
    target_domains = ['t.me', 'discord.com', 'www.youtube.com', 'youtube.com']
    
    print(f"📊 Events for target domains:\n")
    
    domain_stats = {}
    
    for event in events:
        # Нормализуем домен
        domain = event.domain.lower()
        
        # Проверяем если домен целевой или содержит целевой
        is_target = any(
            domain == td or domain.endswith('.' + td) or td.endswith(domain)
            for td in target_domains
        )
        
        if is_target:
            if domain not in domain_stats:
                domain_stats[domain] = {
                    'fail_counters': [],
                    'added': False,
                    'reset': False
                }
            
            if event.event_type == EventType.FAIL_COUNTER:
                domain_stats[domain]['fail_counters'].append(event.fail_counter)
                print(f"🔴 {domain}: fail counter {event.fail_counter}/{event.fail_threshold} ({event.protocol})")
            
            elif event.event_type == EventType.DOMAIN_ADDED:
                domain_stats[domain]['added'] = True
                print(f"✅ {domain}: added to {event.strategy_file}")
            
            elif event.event_type == EventType.FAIL_RESET:
                domain_stats[domain]['reset'] = True
                print(f"🟢 {domain}: fail counter reset (working)")
    
    print(f"\n📈 Summary:\n")
    for domain, stats in domain_stats.items():
        print(f"   {domain}:")
        print(f"      Fail counters: {stats['fail_counters']}")
        print(f"      Added to autohostlist: {'Yes' if stats['added'] else 'No'}")
        print(f"      Reset detected: {'Yes' if stats['reset'] else 'No'}")
        
        # Определяем статус
        if stats['added']:
            max_counter = max(stats['fail_counters']) if stats['fail_counters'] else 0
            if max_counter >= 3:
                print(f"      Status: ✅ Threshold reached, added to autohostlist")
        elif stats['fail_counters']:
            max_counter = max(stats['fail_counters'])
            print(f"      Status: ⏳ In progress ({max_counter}/3)")
    
    print("\n" + "=" * 60)
    print("Monitor test completed!")
    print("=" * 60)


if __name__ == "__main__":
    test_log_parser()
    asyncio.run(test_monitor_with_real_log())
