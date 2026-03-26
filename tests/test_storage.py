"""
Тесты для модуля storage.py
"""

import pytest
import pytest_asyncio

from autozapret.storage import Storage, Strategy, Domain, StatEvent


@pytest.mark.asyncio
async def test_storage_connect(storage: Storage):
    """Тест подключения к базе данных"""
    assert storage._db is not None


@pytest.mark.asyncio
async def test_add_strategy(storage: Storage):
    """Тест добавления стратегии"""
    strategy = Strategy(
        name="test_strategy",
        description="Test description",
        zapret_params="--test-param=value",
        priority=50
    )
    
    strategy_id = await storage.add_strategy(strategy)
    assert strategy_id is not None
    
    # Проверяем что стратегия сохранилась
    retrieved = await storage.get_strategy("test_strategy")
    assert retrieved is not None
    assert retrieved.name == "test_strategy"
    assert retrieved.description == "Test description"
    assert retrieved.zapret_params == "--test-param=value"
    assert retrieved.priority == 50


@pytest.mark.asyncio
async def test_get_strategy_by_id(storage: Storage):
    """Тест получения стратегии по ID"""
    strategy = Strategy(
        name="test_by_id",
        description="Get by ID test",
        zapret_params="--test",
        priority=10
    )
    
    strategy_id = await storage.add_strategy(strategy)
    retrieved = await storage.get_strategy_by_id(strategy_id)
    
    assert retrieved is not None
    assert retrieved.id == strategy_id
    assert retrieved.name == "test_by_id"


@pytest.mark.asyncio
async def test_list_strategies(storage: Storage):
    """Тест списка стратегий"""
    strategies = await storage.list_strategies()
    
    # Должны быть хотя бы 2 стратегии из конфига
    assert len(strategies) >= 2
    
    # Проверяем сортировку по приоритету
    priorities = [s.priority for s in strategies]
    assert priorities == sorted(priorities)


@pytest.mark.asyncio
async def test_assign_domain(storage: Storage):
    """Тест привязки домена к стратегии"""
    # Получаем первую стратегию
    strategies = await storage.list_strategies()
    strategy = strategies[0]
    
    # Привязываем домен
    success = await storage.assign_domain("test-domain.com", strategy.id)
    assert success
    
    # Проверяем
    domain = await storage.get_domain("test-domain.com")
    assert domain is not None
    assert domain.domain == "test-domain.com"
    assert domain.strategy_id == strategy.id
    assert domain.fail_count == 0


@pytest.mark.asyncio
async def test_get_domain_strategy(storage: Storage):
    """Тест получения стратегии домена"""
    strategies = await storage.list_strategies()
    strategy = strategies[0]
    
    await storage.assign_domain("strategy-test.com", strategy.id)
    
    retrieved_strategy = await storage.get_domain_strategy("strategy-test.com")
    assert retrieved_strategy is not None
    assert retrieved_strategy.id == strategy.id


@pytest.mark.asyncio
async def test_increment_failCount(storage: Storage):
    """Тест увеличения счётчика неудач"""
    await storage.assign_domain("fail-test.com", 1)
    
    # Увеличиваем 3 раза
    count1 = await storage.increment_fail_count("fail-test.com")
    assert count1 == 1
    
    count2 = await storage.increment_fail_count("fail-test.com")
    assert count2 == 2
    
    count3 = await storage.increment_fail_count("fail-test.com")
    assert count3 == 3


@pytest.mark.asyncio
async def test_reset_fail_count(storage: Storage):
    """Тест сброса счётчика неудач"""
    await storage.assign_domain("reset-test.com", 1)
    
    # Увеличиваем
    await storage.increment_fail_count("reset-test.com")
    await storage.increment_fail_count("reset-test.com")
    
    # Проверяем
    domain = await storage.get_domain("reset-test.com")
    assert domain.fail_count == 2
    
    # Сбрасываем
    await storage.reset_fail_count("reset-test.com")
    
    # Проверяем сброс
    domain = await storage.get_domain("reset-test.com")
    assert domain.fail_count == 0


@pytest.mark.asyncio
async def test_log_event(storage: Storage):
    """Тест логирования событий"""
    event = StatEvent(
        domain="event-test.com",
        event_type="fail",
        strategy_id=1,
        details="Test event"
    )
    
    event_id = await storage.log_event(event)
    assert event_id is not None
    
    # Получаем события
    events = await storage.get_stats(domain="event-test.com")
    assert len(events) > 0
    assert events[0].event_type == "fail"


@pytest.mark.asyncio
async def test_remove_domain(storage: Storage):
    """Тест удаления домена"""
    await storage.assign_domain("remove-test.com", 1)
    
    # Проверяем что домен есть
    domain = await storage.get_domain("remove-test.com")
    assert domain is not None
    assert domain.is_active == 1
    
    # Удаляем (деактивируем)
    await storage.remove_domain("remove-test.com")
    
    # Проверяем деактивацию
    domain = await storage.get_domain("remove-test.com")
    assert domain.is_active == 0


@pytest.mark.asyncio
async def test_hard_remove_domain(storage: Storage):
    """Тест полного удаления домена"""
    await storage.assign_domain("hard-remove-test.com", 1)
    
    # Полностью удаляем
    await storage.hard_remove_domain("hard-remove-test.com")
    
    # Проверяем что домена нет
    domain = await storage.get_domain("hard-remove-test.com")
    assert domain is None


@pytest.mark.asyncio
async def test_duplicate_strategy(storage: Storage):
    """Тест обработки дубликатов стратегий"""
    strategy1 = Strategy(name="duplicate_test", priority=10)
    strategy2 = Strategy(name="duplicate_test", priority=20)
    
    id1 = await storage.add_strategy(strategy1)
    id2 = await storage.add_strategy(strategy2)
    
    # INSERT OR REPLACE создаёт новую запись с новым ID
    # но имя остаётся уникальным
    retrieved = await storage.get_strategy("duplicate_test")
    assert retrieved is not None
    assert retrieved.name == "duplicate_test"
    # Приоритет должен обновиться до последнего
    assert retrieved.priority == 20


@pytest.mark.asyncio
async def test_domain_stats(storage: Storage):
    """Тест статистики домена"""
    domain_name = "stats-test.com"
    
    # Создаём несколько событий
    await storage.assign_domain(domain_name, 1)
    await storage.increment_fail_count(domain_name)
    
    await storage.log_event(StatEvent(domain=domain_name, event_type="fail", strategy_id=1))
    await storage.log_event(StatEvent(domain=domain_name, event_type="applied", strategy_id=1))
    await storage.log_event(StatEvent(domain=domain_name, event_type="success", strategy_id=1))
    
    stats = await storage.get_domain_stats(domain_name)
    
    assert stats["total_events"] >= 3
    assert "fails" in stats
    assert "successes" in stats
