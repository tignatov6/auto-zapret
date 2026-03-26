"""
Fixtures для тестов Auto-Zapret
"""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio

from autozapret.config import Config
from autozapret.storage import Storage, Strategy, Domain, StatEvent
from autozapret.executor import Executor
from autozapret.monitor import Monitor, LogSimulator
from autozapret.analyzer import Analyzer


@pytest.fixture(scope="session")
def test_dir() -> str:
    """Создание временной директории для тестов"""
    test_dir = tempfile.mkdtemp(prefix="autozapret_test_")
    yield test_dir
    # Очистка после тестов
    shutil.rmtree(test_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def test_config(test_dir: str) -> Config:
    """Создание тестовой конфигурации"""
    import uuid
    unique_id = uuid.uuid4().hex[:8]

    config = Config(
        nfqws_pid_file=os.path.join(test_dir, f"nfqws_{unique_id}.pid"),
        nfqws_log_file=os.path.join(test_dir, f"test_{unique_id}.log"),
        hostlists_dir=os.path.join(test_dir, f"hostlists_{unique_id}"),
        auto_hostlist_file="test-auto.txt",
        strategy_prefix="test-strat-",
        fail_threshold=3,
        retrans_threshold=3,
        signal_cooldown_seconds=1,
        database_path=os.path.join(test_dir, f"test_{unique_id}.db"),
        log_level="DEBUG"
    )

    # Загружаем тестовые стратегии
    config.strategies = [
        {
            "name": "test_youtube",
            "description": "Test strategy for YouTube",
            "zapret_params": "--dpi-desync=fake,multisplit",
            "priority": 1
        },
        {
            "name": "test_discord",
            "description": "Test strategy for Discord",
            "zapret_params": "--dpi-desync=split --disorder",
            "priority": 2
        },
        {
            "name": "test_default",
            "description": "Test default strategy",
            "zapret_params": "--dpi-desync=fake",
            "priority": 99
        }
    ]

    # Создаём директорию для hostlists
    os.makedirs(config.hostlists_dir, exist_ok=True)

    return config


@pytest_asyncio.fixture(scope="function")
async def storage(test_config: Config) -> AsyncGenerator[Storage, None]:
    """Создание хранилища для тестов"""
    store = Storage(test_config.database_path)
    await store.connect()
    # Загружаем тестовые стратегии напрямую
    for strat_data in test_config.strategies:
        strategy = Strategy(
            name=strat_data["name"],
            description=strat_data.get("description", ""),
            zapret_params=strat_data.get("zapret_params", ""),
            priority=strat_data.get("priority", 99)
        )
        await store.add_strategy(strategy)
    yield store
    await store.close()


@pytest.fixture
def executor(test_config: Config) -> Executor:
    """Создание Executor для тестов"""
    return Executor(test_config)


@pytest.fixture
def monitor(test_config: Config) -> Monitor:
    """Создание Monitor для тестов"""
    return Monitor(test_config)


@pytest_asyncio.fixture
async def log_simulator(test_config: Config) -> AsyncGenerator[LogSimulator, None]:
    """Симулятор логов для тестов"""
    simulator = LogSimulator(test_config.nfqws_log_file)
    await simulator.clear()
    yield simulator


@pytest_asyncio.fixture
async def analyzer(storage: Storage, executor: Executor,
                   test_config: Config) -> AsyncGenerator[Analyzer, None]:
    """Создание Analyzer для тестов"""
    ana = Analyzer(storage, executor, test_config)
    yield ana


@pytest_asyncio.fixture
async def full_app(test_config: Config) -> AsyncGenerator[dict, None]:
    """Полный набор компонентов для интеграционных тестов"""
    storage = Storage(test_config.database_path)
    await storage.connect()
    # Загружаем тестовые стратегии
    for strat_data in test_config.strategies:
        strategy = Strategy(
            name=strat_data["name"],
            description=strat_data.get("description", ""),
            zapret_params=strat_data.get("zapret_params", ""),
            priority=strat_data.get("priority", 99)
        )
        await storage.add_strategy(strategy)

    executor = Executor(test_config)
    analyzer = Analyzer(storage, executor, test_config)
    monitor = Monitor(test_config)
    monitor.register_callback(analyzer.handle_event)

    yield {
        "config": test_config,
        "storage": storage,
        "executor": executor,
        "analyzer": analyzer,
        "monitor": monitor
    }

    await storage.close()


@pytest.fixture
def app_with_db(test_config):
    """Приложение с инициализированной БД для CLI тестов"""
    # Создаём БД и инициализируем стратегии
    async def init():
        storage = Storage(test_config.database_path)
        await storage.connect()
        # Загружаем тестовые стратегии
        for strat_data in test_config.strategies:
            strategy = Strategy(
                name=strat_data["name"],
                description=strat_data.get("description", ""),
                zapret_params=strat_data.get("zapret_params", ""),
                priority=strat_data.get("priority", 99)
            )
            await storage.add_strategy(strategy)
        await storage.close()
        return test_config

    return asyncio.run(init())


@pytest.fixture
def sample_log_lines() -> list:
    """Примеры строк лога для тестов парсинга"""
    return [
        # Fail counter
        "example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : fail counter 1/3",
        "youtube.com : profile 1 : client 10.0.0.5:54321 : proto HTTP : fail counter 2/3",

        # Domain added
        "blocked-site.com : profile 2 : client 192.168.1.100:11111 : proto TLS : adding to /opt/zapret/ipset/strat-discord.txt",

        # Domain not added (duplicate)
        "already-exists.com : profile 1 : client 172.16.0.1:22222 : proto QUIC : NOT adding, duplicate detected",

        # Fail reset
        "working-site.com : profile 1 : client 192.168.1.50:33333 : proto TLS : fail counter reset",

        # Invalid lines
        "This is not a valid log line",
        "",
        "# Comment line",
    ]
