"""
Тесты для CLI (main.py)

Примечание: Эти тесты требуют полной изоляции БД.
Временно отключены до реализации правильной изоляции тестового окружения CLI.
"""

import pytest
import asyncio
from pathlib import Path
from click.testing import CliRunner

from autozapret.main import cli
from autozapret.config import Config
from autozapret.storage import Storage, Strategy


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_init_db_command(runner):
    """Тест команды init-db"""
    result = runner.invoke(cli, ['init-db'])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_strategies_list_command(runner):
    """Тест команды strategies list"""
    result = runner.invoke(cli, ['strategies', 'list'])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_strategies_add_command(runner):
    """Тест команды strategies add"""
    result = runner.invoke(cli, [
        'strategies', 'add', 'test_strat_cli',
        '--params=--dpi-desync=fake',
        '--description=Test strategy',
        '--priority=50'
    ])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_domains_list_command(runner):
    """Тест команды domains list"""
    result = runner.invoke(cli, ['domains', 'list'])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_domains_assign_command(runner):
    """Тест команды domains assign"""
    result = runner.invoke(cli, [
        'domains', 'assign', 'test.com', 'youtube'
    ])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_domains_remove_command(runner):
    """Тест команды domains remove"""
    result = runner.invoke(cli, ['domains', 'remove', 'test.com'])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_stats_command(runner):
    """Тест команды stats"""
    result = runner.invoke(cli, ['stats'])
    assert result.exit_code == 0


@pytest.mark.skip(reason="Требует изоляции БД - CLI использует глобальный конфиг")
def test_domains_list_all_flag(runner):
    """Тест domains list --all"""
    result = runner.invoke(cli, ['domains', 'list', '--all'])
    assert result.exit_code == 0


# Эти тесты работают без БД
def test_cli_help(runner):
    """Тест --help"""
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'Auto-Zapret' in result.output
    assert 'Commands:' in result.output


def test_cli_version(runner):
    """Тест --version"""
    result = runner.invoke(cli, ['--version'])
    assert result.exit_code == 0
    assert '0.1.0' in result.output


def test_status_command(runner):
    """Тест команды status"""
    result = runner.invoke(cli, ['status'])
    assert result.exit_code == 0
    assert 'Auto-Zapret Status' in result.output
    assert 'Config directory' in result.output


def test_cli_with_config_dir(runner, test_config):
    """Тест с кастомной директорией конфига"""
    # Создаём тестовый конфиг
    config_dir = Path(test_config.hostlists_dir).parent
    config_file = config_dir / "autozapret.json"
    if not config_file.exists():
        config_file.write_text('{"fail_threshold": 5}')

    result = runner.invoke(cli, ['--config-dir', str(config_dir), 'status'])
    # Конфиг должен загрузиться
    assert result.exit_code == 0
