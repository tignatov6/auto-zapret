"""
Тесты для модуля monitor.py
"""

import asyncio
import os
import pytest
import pytest_asyncio

from autozapret.monitor import (
    Monitor, LogParser, LogSimulator, 
    AutoHostlistEvent, EventType
)
from autozapret.config import Config


class TestLogParser:
    """Тесты парсера логов"""
    
    def test_parse_fail_counter(self):
        """Тест парсинга fail counter"""
        parser = LogParser()
        line = "example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : fail counter 2/3"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.FAIL_COUNTER
        assert event.domain == "example.com"
        assert event.profile_id == 3
        assert event.client == "192.168.1.1:12345"
        assert event.protocol == "TLS"
        assert event.fail_counter == 2
        assert event.fail_threshold == 3
    
    def test_parse_domain_added(self):
        """Тест парсинга domain added"""
        parser = LogParser()
        line = "youtube.com : profile 1 : client 10.0.0.5:54321 : proto HTTP : adding to /opt/zapret/strat-youtube.txt"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.DOMAIN_ADDED
        assert event.domain == "youtube.com"
        assert event.profile_id == 1
        assert event.strategy_file == "/opt/zapret/strat-youtube.txt"
    
    def test_parse_domain_not_added(self):
        """Тест парсинга domain not added"""
        parser = LogParser()
        line = "duplicate.com : profile 2 : client 172.16.0.1:22222 : proto QUIC : NOT adding, duplicate detected"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.DOMAIN_NOT_ADDED
        assert event.domain == "duplicate.com"
    
    def test_parse_fail_reset(self):
        """Тест парсинга fail reset"""
        parser = LogParser()
        line = "working.com : profile 1 : client 192.168.1.50:33333 : proto TLS : fail counter reset"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.FAIL_RESET
        assert event.domain == "working.com"
    
    def test_parse_invalid_line(self):
        """Тест парсинга невалидной строки"""
        parser = LogParser()
        line = "This is not a valid log line"
        
        event = parser.parse_line(line)
        
        assert event is None
    
    def test_parse_empty_line(self):
        """Тест парсинга пустой строки"""
        parser = LogParser()
        
        event = parser.parse_line("")
        
        assert event is None
    
    def test_parse_comment_line(self):
        """Тест парсинга комментария"""
        parser = LogParser()
        
        event = parser.parse_line("# This is a comment")
        
        assert event is None
    
    def test_parse_wildcard_domain(self):
        """Тест парсинга домена с wildcard"""
        parser = LogParser()
        line = "*.google.com : profile 1 : client 192.168.1.1:12345 : proto TLS : fail counter 1/3"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.domain == "*.google.com"


@pytest.mark.asyncio
async def test_log_simulator_write(log_simulator: LogSimulator, test_config: Config):
    """Тест записи событий симулятором"""
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain="simulator-test.com",
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=1,
        fail_threshold=3
    )
    
    await log_simulator.write_event(event)
    
    # Проверяем что запись появилась в файле
    assert os.path.exists(test_config.nfqws_log_file)
    
    with open(test_config.nfqws_log_file, "r") as f:
        content = f.read()
    
    assert "simulator-test.com" in content
    assert "fail counter 1/3" in content


@pytest.mark.asyncio
async def test_log_simulator_clear(log_simulator: LogSimulator, test_config: Config):
    """Тест очистки лога"""
    # Сначала пишем событие
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain="clear-test.com",
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=1,
        fail_threshold=3
    )
    await log_simulator.write_event(event)
    
    # Очищаем
    await log_simulator.clear()
    
    # Проверяем что файл пуст
    with open(test_config.nfqws_log_file, "r") as f:
        content = f.read()
    
    assert content.strip() == ""


@pytest.mark.asyncio
async def test_monitor_read_log_file(monitor: Monitor, log_simulator: LogSimulator):
    """Тест чтения всего лога"""
    # Пишем несколько событий
    events_to_write = [
        AutoHostlistEvent(
            event_type=EventType.FAIL_COUNTER,
            domain="read-test1.com",
            profile_id=1,
            client="192.168.1.1:12345",
            protocol="TLS",
            fail_counter=1,
            fail_threshold=3
        ),
        AutoHostlistEvent(
            event_type=EventType.DOMAIN_ADDED,
            domain="read-test2.com",
            profile_id=2,
            client="192.168.1.2:12346",
            protocol="HTTP",
            strategy_file="/test/file.txt"
        ),
    ]
    
    for event in events_to_write:
        await log_simulator.write_event(event)
    
    # Читаем через монитор
    events = await monitor.read_log_file()
    
    assert len(events) >= 2
    domains = [e.domain for e in events]
    assert "read-test1.com" in domains
    assert "read-test2.com" in domains


@pytest.mark.asyncio
async def test_monitor_callback(monitor: Monitor, log_simulator: LogSimulator):
    """Тест callback для событий"""
    received_events = []

    def callback(event: AutoHostlistEvent):
        received_events.append(event)

    monitor.register_callback(callback)

    # Пишем событие
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain="callback-test.com",
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=2,
        fail_threshold=3
    )
    await log_simulator.write_event(event)

    # Читаем лог и вручную вызываем callback
    events = await monitor.read_log_file()
    for e in events:
        await monitor._notify_callbacks(e)

    # Проверяем что callback сработал
    assert len(received_events) > 0
    assert any(e.domain == "callback-test.com" for e in received_events)


@pytest.mark.asyncio
async def test_monitor_unregister_callback(monitor: Monitor):
    """Тест отписки callback"""
    call_count = 0
    
    def callback(event: AutoHostlistEvent):
        nonlocal call_count
        call_count += 1
    
    monitor.register_callback(callback)
    monitor.unregister_callback(callback)
    
    # Проверяем что callback удалён
    assert callback not in monitor._callbacks


@pytest.mark.asyncio
async def test_monitor_start_stop(monitor: Monitor):
    """Тест запуска и остановки монитора"""
    assert monitor._running is False
    
    # Просто проверяем что stop() работает
    monitor.stop()
    assert monitor._running is False


@pytest.mark.asyncio
async def test_event_str_representation():
    """Тест строкового представления событий"""
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain="test.com",
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=2,
        fail_threshold=3
    )
    
    event_str = str(event)
    
    assert "test.com" in event_str
    assert "profile 1" in event_str
    assert "counter=2/3" in event_str


@pytest.mark.asyncio
async def test_async_callback(monitor: Monitor, log_simulator: LogSimulator):
    """Тест асинхронного callback"""
    received = []

    async def async_callback(event: AutoHostlistEvent):
        await asyncio.sleep(0.01)  # Имитация асинхронной работы
        received.append(event)

    monitor.register_callback(async_callback)

    # Пишем и читаем событие
    event = AutoHostlistEvent(
        event_type=EventType.FAIL_COUNTER,
        domain="async-test.com",
        profile_id=1,
        client="192.168.1.1:12345",
        protocol="TLS",
        fail_counter=1,
        fail_threshold=3
    )
    await log_simulator.write_event(event)
    events = await monitor.read_log_file()
    for e in events:
        await monitor._notify_callbacks(e)

    # Проверяем что асинхронный callback сработал
    assert len(received) > 0
