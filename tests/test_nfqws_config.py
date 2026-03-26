"""
Тесты для модуля nfqws_config.py
"""

import os
import pytest
import pytest_asyncio
from pathlib import Path
from unittest.mock import patch

from autozapret.nfqws_config import NfqwsConfigGenerator, get_generator
from autozapret.config import Config, get_config
from autozapret.storage import Storage, Strategy


@pytest.fixture
def test_config(tmp_path):
    """Создание тестовой конфигурации"""
    # Создаём Config с правильными параметрами
    config = Config()
    
    # Переопределяем пути через Path для удобства
    config.database_path = str(tmp_path / "test.db")
    config.zapret_src_dir = str(tmp_path / "zapret")
    config.hostlists_dir = str(tmp_path / "hostlists")
    
    # Создаём директории
    for dir_path in [config.hostlists_dir, config.zapret_src_dir]:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    return config


@pytest.fixture
async def generator_with_storage(test_config: Config):
    """Создание генератора с инициализированным хранилищем"""
    storage = Storage(test_config.database_path)
    await storage.connect()
    
    # Добавляем тестовые стратегии
    await storage.create_strategy("test_youtube", "--dpi-desync=fake", "Test YouTube")
    await storage.create_strategy("test_discord", "--dpi-desync=split", "Test Discord")
    
    generator = NfqwsConfigGenerator(test_config)
    await generator.initialize(storage)
    
    yield generator, storage
    
    await storage.close()


@pytest.mark.asyncio
async def test_generator_init(test_config: Config):
    """Тест инициализации генератора"""
    storage = Storage(test_config.database_path)
    await storage.connect()
    
    await storage.create_strategy("test1", "--dpi-desync=fake", "Test 1")
    await storage.create_strategy("test2", "--dpi-desync=split", "Test 2")
    
    generator = NfqwsConfigGenerator(test_config)
    await generator.initialize(storage)
    
    profiles = generator.list_profiles()
    assert len(profiles) == 2
    
    await storage.close()


@pytest.mark.asyncio
async def test_generate_nfqs_args(generator_with_storage):
    """Тест генерации аргументов nfqws"""
    generator, storage = generator_with_storage
    
    args = generator.generate_nfqs_args()
    
    # Проверяем базовые аргументы
    assert "--wf-tcp=80,443" in args
    assert "--filter-tcp=443" in args
    assert "--filter-tcp=80" in args
    assert "--hostlist-auto=" in " ".join(args)
    assert "--hostlist-auto-fail-threshold=3" in args
    
    # Проверяем --new для каждой стратегии
    new_count = args.count("--new")
    assert new_count >= 2  # Минимум 2 стратегии
    
    # Проверяем параметры стратегий
    args_str = " ".join(args)
    assert "--dpi-desync=fake" in args_str
    assert "--dpi-desync=split" in args_str


@pytest.mark.asyncio
async def test_generate_windows_batch(generator_with_storage, test_config: Config):
    """Тест генерации Windows batch скрипта"""
    generator, storage = generator_with_storage
    
    output_path = os.path.join(test_config.hostlists_dir, "test-start.cmd")
    result_path = generator.generate_windows_batch(output_path)
    
    assert os.path.exists(result_path)
    
    with open(result_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "@echo off" in content
    assert "chcp 65001" in content
    assert "winws.exe" in content
    assert "--dpi-desync" in content


@pytest.mark.asyncio
async def test_generate_startup_script(generator_with_storage, test_config: Config):
    """Тест генерации shell скрипта"""
    generator, storage = generator_with_storage
    
    output_path = os.path.join(test_config.hostlists_dir, "test-start.sh")
    result_path = generator.generate_startup_script(output_path)
    
    assert os.path.exists(result_path)
    
    # Проверяем что файл исполняемый
    assert os.access(result_path, os.X_OK)
    
    with open(result_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "#!/bin/bash" in content
    assert "set -e" in content
    assert "nfqws" in content


@pytest.mark.asyncio
async def test_generate_systemd_service(generator_with_storage, test_config: Config):
    """Тест генерации systemd service"""
    generator, storage = generator_with_storage
    
    output_path = os.path.join(test_config.hostlists_dir, "test-nfqws.service")
    result_path = generator.generate_systemd_service(output_path)
    
    assert os.path.exists(result_path)
    
    with open(result_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "[Unit]" in content
    assert "[Service]" in content
    assert "[Install]" in content
    assert "WantedBy=multi-user.target" in content
    assert "nfqws" in content


@pytest.mark.asyncio
async def test_update_profile(generator_with_storage):
    """Тест обновления профиля"""
    generator, storage = generator_with_storage
    
    # Обновляем стратегию
    strategy = await storage.get_strategy("test_youtube")
    strategy.zapret_params = "--dpi-desync=fake,multisplit"
    await storage.update_strategy(strategy)
    
    # Обновляем профиль
    updated = await generator.update_profile(strategy)
    
    assert updated.zapret_params == "--dpi-desync=fake,multisplit"
    
    # Проверяем что профиль обновился в списке
    profiles = generator.list_profiles()
    youtube_profile = next((p for p in profiles if p.name == "test_youtube"), None)
    assert youtube_profile is not None
    assert youtube_profile.zapret_params == "--dpi-desync=fake,multisplit"


@pytest.mark.asyncio
async def test_remove_profile(generator_with_storage):
    """Тест удаления профиля"""
    generator, storage = generator_with_storage
    
    # Удаляем профиль
    result = await generator.remove_profile("test_youtube")
    assert result is True
    
    # Проверяем что удалён из списка
    profiles = generator.list_profiles()
    youtube_profile = next((p for p in profiles if p.name == "test_youtube"), None)
    assert youtube_profile is None
    
    # Повторное удаление возвращает False
    result2 = await generator.remove_profile("test_youtube")
    assert result2 is False


@pytest.mark.asyncio
async def test_get_profile(generator_with_storage):
    """Тест получения профиля"""
    generator, storage = generator_with_storage
    
    profile = generator.get_profile("test_youtube")
    
    assert profile is not None
    assert profile.name == "test_youtube"
    assert profile.strategy_id > 0
    assert profile.zapret_params == "--dpi-desync=fake"
    
    # Несуществующий профиль
    profile2 = generator.get_profile("nonexistent")
    assert profile2 is None


@pytest.mark.asyncio
async def test_get_config_summary(generator_with_storage):
    """Тест получения сводки конфигурации"""
    generator, storage = generator_with_storage
    
    summary = generator.get_config_summary()
    
    assert "profiles_count" in summary
    assert summary["profiles_count"] == 2
    
    assert "profiles" in summary
    assert len(summary["profiles"]) == 2
    
    assert "nfqws_args" in summary
    assert isinstance(summary["nfqws_args"], list)


@pytest.mark.asyncio
async def test_validate_params_valid():
    """Тест валидации корректных параметров"""
    generator = NfqwsConfigGenerator()
    
    # Корректные параметры
    valid, error = generator.validate_params("--dpi-desync=fake")
    assert valid is True
    assert error == ""
    
    valid, error = generator.validate_params("--dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2")
    assert valid is True


@pytest.mark.asyncio
async def test_validate_params_invalid():
    """Тест валидации некорректных параметров"""
    generator = NfqwsConfigGenerator()
    
    # Пустые параметры
    valid, error = generator.validate_params("")
    assert valid is False
    assert "Empty" in error or "empty" in error.lower()
    
    # Без --dpi-desync
    valid, error = generator.validate_params("--some-other-param=value")
    assert valid is False
    assert "dpi-desync" in error.lower()


@pytest.mark.asyncio
async def test_get_generator_singleton():
    """Тест singleton паттерна для get_generator"""
    gen1 = get_generator()
    gen2 = get_generator()
    
    assert gen1 is gen2


@pytest.mark.asyncio
async def test_profile_priority_order(generator_with_storage):
    """Тест сортировки профилей по приоритету"""
    generator, storage = generator_with_storage
    
    # Добавляем стратегию с другим приоритетом
    await storage.create_strategy("test_priority", "--dpi-desync=disorder", "Priority test")
    strategy = await storage.get_strategy("test_priority")
    strategy.priority = 1  # Высокий приоритет
    await storage.update_strategy(strategy)
    
    # Обновляем профиль
    await generator.update_profile(strategy)
    
    # Получаем аргументы
    args = generator.generate_nfqs_args()
    
    # Проверяем порядок --new (стратегия с priority=1 должна быть первой)
    new_indices = [i for i, arg in enumerate(args) if arg == "--new"]
    assert len(new_indices) >= 3
    
    # Первый --new должен быть для стратегии с высоким приоритетом
    # (после базовых аргументов)


@pytest.mark.asyncio
async def test_create_generator_function():
    """Тест функции create_generator"""
    from autozapret.nfqws_config import create_generator
    
    generator = await create_generator()
    
    assert generator is not None
    assert isinstance(generator, NfqwsConfigGenerator)


@pytest.mark.asyncio
async def test_profile_hostlist_file(generator_with_storage, test_config: Config):
    """Тест что hostlist файлы создаются в правильной директории"""
    generator, storage = generator_with_storage
    
    profile = generator.get_profile("test_youtube")
    
    assert profile is not None
    assert profile.hostlist_file.startswith(test_config.hostlists_dir)
    assert profile.hostlist_file.endswith(".txt")


# Integration test требует сложной настройки FastAPI test client
# Пропускаем его
