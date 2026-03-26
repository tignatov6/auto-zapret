"""
Тесты для новой логики Analyzer
"""

import pytest
import pytest_asyncio

from autozapret.analyzer import Analyzer
from autozapret.monitor import AutoHostlistEvent, EventType
from autozapret.storage import Strategy


@pytest.mark.asyncio
async def test_handle_fail_counter(analyzer, storage):
    """Тест обработки fail counter"""
    domain = "test-fail-counter.com"
    
    # Сначала создаём домен в БД
    strategy = Strategy(name="default_strat", zapret_params="--test")
    strategy_id = await storage.add_strategy(strategy)
    await storage.assign_domain(domain, strategy_id)
    
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain=domain,
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=1,
        fail_threshold=3
    )

    await analyzer.handle_event(event)

    # Проверяем что счётчик обновился в БД
    domain_info = await storage.get_domain(domain)
    # Fail count должен быть установлен в 1
    assert domain_info is not None
    assert domain_info.fail_count == 1


@pytest.mark.asyncio
async def test_handle_fail_counter_threshold(analyzer, storage):
    """Тест достижения порога fail counter"""
    domain = "threshold-test.com"

    # Эмулируем 3 неудачи (порог)
    for i in range(1, 4):
        event = AutoHostlistEvent(
            event_type=EventType.FAIL_COUNTER,
            domain=domain,
            profile_id=1,
            client="192.168.1.1:12345",
            protocol="TLS",
            fail_counter=i,
            fail_threshold=3
        )
        await analyzer.handle_event(event)

    # После достижения порога должна быть попытка применить стратегию
    # Домен должен быть в базе (с cooldown или стратегией)
    status = await analyzer.get_domain_status(domain)
    assert status is not None


@pytest.mark.asyncio
async def test_handle_fail_reset(analyzer, storage):
    """Тест обработки сброса неудач"""
    domain = "reset-test.com"

    # Сначала добавляем домен и увеличиваем fail count
    await storage.assign_domain(domain, 1)
    await storage.increment_fail_count(domain)
    await storage.set_strategy_cooldown(domain, 60, "test")

    # Проверяем что cooldown установлен
    cooldown = await storage.get_strategy_cooldown(domain)
    assert cooldown is not None

    # Эмулируем сброс
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_RESET,
        domain=domain,
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS"
    )
    await analyzer.handle_event(event)

    # Проверяем что cooldown сброшен
    cooldown = await storage.get_strategy_cooldown(domain)
    assert cooldown is None


@pytest.mark.asyncio
async def test_get_domain_status_with_strategy(analyzer, storage):
    """Тест получения статуса домена со стратегией"""
    domain = "status-test.com"
    await storage.assign_domain(domain, 1)

    status = await analyzer.get_domain_status(domain)

    assert status["has_strategy"] is True
    assert status["domain"] == domain


@pytest.mark.asyncio
async def test_get_domain_status_with_cooldown(analyzer, storage):
    """Тест получения статуса домена с cooldown"""
    domain = "cooldown-status-test.com"
    await storage.set_strategy_cooldown(domain, 60, "test")

    status = await analyzer.get_domain_status(domain)

    assert status["has_strategy"] is False
    assert status["cooldown_until"] is not None


@pytest.mark.asyncio
async def test_get_domain_status_nothing(analyzer):
    """Тест получения статуса домена без ничего"""
    domain = "nothing-test.com"

    status = await analyzer.get_domain_status(domain)

    assert status["has_strategy"] is False
    assert status["cooldown_until"] is None


@pytest.mark.asyncio
async def test_test_strategy(analyzer):
    """Тест тестирования стратегии (заглушка)"""
    from autozapret.analyzer import StrategyTestResult
    # Проверяем что метод возвращает StrategyTestResult
    result = await analyzer._test_strategy("test.com", "--dpi-desync=fake")
    assert isinstance(result, StrategyTestResult)


@pytest.mark.asyncio
async def test_brute_force_strategies(analyzer):
    """Тест подбора стратегий"""
    from autozapret.analyzer import BruteForceResult
    # Проверяем что метод возвращает BruteForceResult
    result = await analyzer._brute_force_strategies("brute-test.com")
    assert isinstance(result, BruteForceResult)


@pytest.mark.asyncio
async def test_handle_domain_added(analyzer, storage):
    """Тест обработки добавления домена"""
    domain = "added-test.com"
    await storage.assign_domain(domain, 1)

    event = AutoHostlistEvent(
        event_type=EventType.DOMAIN_ADDED,
        domain=domain,
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        strategy_file="/test/file.txt"
    )
    await analyzer.handle_event(event)

    # Проверяем что событие залогировано
    events = await storage.get_stats(domain=domain)
    assert len(events) > 0


@pytest.mark.asyncio
async def test_apply_strategy_to_domain_existing(analyzer, storage, monkeypatch):
    """Тест применения существующей стратегии"""
    # Создаём стратегию с высоким success_rate
    strategy = Strategy(
        name="test_strat",
        zapret_params="--test",
        priority=1,
        success_rate=0.95,
        domains_count=10
    )
    strategy_id = await storage.add_strategy(strategy)

    domain = "existing-strategy-test.com"

    # Мокаем _test_strategy чтобы возвращал StrategyTestResult(WORKS)
    from autozapret.analyzer import StrategyTestResult, StrategyTestStatus
    async def mock_test(domain, params):
        return StrategyTestResult(
            status=StrategyTestStatus.WORKS,
            domain=domain,
            strategy_params=params,
            success_rate=1.0
        )

    monkeypatch.setattr(analyzer, '_test_strategy', mock_test)

    # Применяем стратегию
    await analyzer._apply_strategy_to_domain(domain)

    # Проверяем что домен добавлен
    domain_info = await storage.get_domain(domain)
    assert domain_info is not None


@pytest.mark.asyncio
async def test_apply_strategy_to_domain_cooldown(analyzer, storage):
    """Тест что cooldown предотвращает применение"""
    domain = "cooldown-apply-test.com"
    await storage.set_strategy_cooldown(domain, 60, "test")

    # Не должно делать ничего
    await analyzer._apply_strategy_to_domain(domain)

    # Проверяем что домен не добавлен
    domain_info = await storage.get_domain(domain)
    assert domain_info is None


@pytest.mark.asyncio
async def test_purge_expired_cooldowns(storage):
    """Тест очистки истёкших cooldown"""
    from datetime import datetime, timedelta

    # Добавляем истёкший cooldown
    await storage.set_strategy_cooldown("expired.com", -1, "test")

    # Очищаем
    count = await storage.purge_expired_cooldowns()

    assert count >= 1


@pytest.mark.asyncio
async def test_update_strategy_stats(storage):
    """Тест обновления статистики стратегии"""
    strategy = Strategy(
        name="stats-test",
        zapret_params="--test",
        priority=1
    )
    strategy_id = await storage.add_strategy(strategy)

    # Обновляем статистику
    await storage.update_strategy_stats(strategy_id, success=True)
    await storage.update_strategy_stats(strategy_id, success=True)
    await storage.update_strategy_stats(strategy_id, success=False)

    # Проверяем
    updated = await storage.get_strategy_by_id(strategy_id)
    assert updated.total_checks == 3
    assert 0.5 < updated.success_rate < 0.8  # Примерно 2/3


@pytest.mark.asyncio
async def test_get_strategies_by_priority(storage):
    """Тест получения стратегий по приоритету"""
    # Создаём несколько стратегий
    for i, priority in enumerate([3, 1, 2]):
        strategy = Strategy(
            name=f"priority_{priority}",
            zapret_params=f"--test{i}",
            priority=priority,
            success_rate=0.9
        )
        await storage.add_strategy(strategy)

    # Получаем отсортированные
    strategies = await storage.get_strategies_by_priority(min_success_rate=0.5)

    # Первая должна быть с priority=1
    assert len(strategies) >= 3
    assert strategies[0].priority == 1


@pytest.mark.asyncio
async def test_create_and_assign_strategy(storage):
    """Тест создания и привязки стратегии"""
    strategy_id = await storage.add_strategy(Strategy(
        name="auto_strategy_test_unique",
        description="Test auto strategy",
        zapret_params="--dpi-desync=fake-test-unique",
        priority=99
    ))

    assert strategy_id is not None

    # Проверяем что стратегия создана
    strategy = await storage.get_strategy("auto_strategy_test_unique")
    assert strategy is not None
    
    # Привязываем домен
    await storage.assign_domain("auto-test-unique.com", strategy_id)
    
    # Проверяем domains_count
    strategy = await storage.get_strategy("auto_strategy_test_unique")
    assert strategy.domains_count == 1
