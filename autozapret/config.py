"""
Модуль конфигурации
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from .utils.profiler import get_profiler

profiler = get_profiler("config")

# Базовая директория проекта (определяется автоматически)
BASE_DIR = Path(__file__).parent.parent.resolve()


@dataclass
class Config:
    # Пути по умолчанию - относительные, работают на Windows и Linux
    nfqws_pid_file: str = ""  # Определяется в __post_init__
    nfqws_log_file: str = ""  # Определяется в __post_init__
    hostlists_dir: str = ""   # Определяется в __post_init__
    auto_hostlist_file: str = ""  # Определяется в __post_init__
    strategy_prefix: str = "strat-"
    fail_threshold: int = 3
    retrans_threshold: int = 3
    signal_cooldown_seconds: int = 5
    database_path: str = ""  # Определяется в __post_init__
    log_level: str = "INFO"
    data_dir: str = ""  # Определяется в __post_init__
    config_dir: str = ""  # Определяется в __post_init__

    # Новые параметры
    zapret_src_dir: str = ""  # Определяется в __post_init__
    blockcheck_path: str = ""
    use_sudo_for_blockcheck: bool = False
    strategy_cooldown_minutes: int = 30
    bruteforce_cooldown_minutes: int = 60
    monitor_replay_existing_logs: bool = False
    analysis_max_parallel: int = 5
    
    # Режимы brute-force
    brute_force_mode: str = "first_working"  # "first_working" или "all_best"
    brute_force_quick_mode: bool = True  # Быстрый режим (меньше тестов)

    # IP-мониторинг для приложений без SNI (Discord, игры и т.д.)
    ip_monitor_enabled: bool = True
    ip_monitor_interval: int = 5  # Секунды между проверками
    ip_monitor_fail_threshold: int = 3  # Количество неудач для триггера
    ip_monitor_retrans_threshold: int = 5  # Ретрансмиссий для детекта проблемы
    # Целевые IP для мониторинга (список dict)
    # Формат: [{"ip": "162.159.128.0/24", "port": 443, "proto": "tcp", "app": "discord"}, ...]
    ip_targets: List[Dict[str, Any]] = field(default_factory=list)

    # Стратегии из strategies.json
    strategies: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """Инициализация путей по умолчанию на основе BASE_DIR"""
        # Пути в формате pathlib для кроссплатформенности
        self._base_dir = BASE_DIR
        
        # Устанавливаем defaults если пустые
        if not self.data_dir:
            self.data_dir = str(self._base_dir / "data")
        if not self.config_dir:
            self.config_dir = str(self._base_dir / "config")
        if not self.hostlists_dir:
            self.hostlists_dir = str(self._base_dir / "data")
        if not self.database_path:
            self.database_path = str(self._base_dir / "data" / "autozapret.db")
        if not self.nfqws_log_file:
            self.nfqws_log_file = str(self._base_dir / "logs" / "autohostlist.log")
        if not self.nfqws_pid_file:
            self.nfqws_pid_file = str(self._base_dir / "data" / "nfqws.pid")
        if not self.auto_hostlist_file:
            self.auto_hostlist_file = str(self._base_dir / "data" / "zapret-hosts-auto.txt")
        if not self.zapret_src_dir:
            self.zapret_src_dir = str(self._base_dir / "zapret-src")

        # Дефолтные IP-цели для Discord если не заданы
        if not self.ip_targets:
            self.ip_targets = [
                # Discord API (Cloudflare)
                {"ip": "162.159.128.0/24", "port": 443, "proto": "tcp", "app": "discord_api"},
                # Discord Voice (i3D.net)
                {"ip": "162.159.128.0/24", "port": "50000-50100", "proto": "udp", "app": "discord_voice"},
            ]

    @classmethod
    @profiler
    def load(cls, config_dir: Optional[str] = None) -> "Config":
        """Загрузка конфигурации из JSON файлов"""
        if config_dir is None:
            config_dir = BASE_DIR / "config"
        else:
            config_dir = Path(config_dir)

        # Создаём экземпляр (это вызовет __post_init__ с defaults)
        config = cls()
        config.config_dir = str(config_dir)

        # Загружаем основной конфиг
        main_config_path = config_dir / "autozapret.json"
        if main_config_path.exists():
            logger_msg = f"Loading config from {main_config_path}"
            with open(main_config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key, value in data.items():
                    if hasattr(config, key) and key != "strategies":
                        setattr(config, key, value)
        else:
            # Конфиг не найден - используем defaults
            import logging
            logging.getLogger(__name__).info(
                f"Config file not found at {main_config_path}, using defaults"
            )

        # Загружаем стратегии
        strategies_path = config_dir / "strategies.json"
        if strategies_path.exists():
            with open(strategies_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.strategies = data.get("strategies", [])

        return config

    @profiler
    def get_strategy_file(self, strategy_name: str) -> str:
        """Получить путь к файлу hostlist для стратегии"""
        return os.path.join(self.hostlists_dir, f"{self.strategy_prefix}{strategy_name}.txt")

    @profiler
    def get_auto_hostlist_path(self) -> str:
        """Получить путь к основному autohostlist файлу"""
        return self.auto_hostlist_file

    def get_absolute_path(self, path: str) -> str:
        """Преобразовать путь в абсолютный (если он относительный)"""
        if os.path.isabs(path):
            return path
        return str(self._base_dir / path)

    def ensure_directories(self) -> None:
        """Создать все необходимые директории"""
        dirs_to_create = [
            self.data_dir,
            self.hostlists_dir,
            Path(self.nfqws_log_file).parent,
            Path(self.database_path).parent,
        ]
        for dir_path in dirs_to_create:
            Path(dir_path).mkdir(parents=True, exist_ok=True)


# Глобальный экземпляр конфигурации
_config: Optional[Config] = None


@profiler
def get_config() -> Config:
    """Получить глобальный экземпляр конфигурации"""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


@profiler
def reload_config() -> Config:
    """Перезагрузить конфигурацию"""
    global _config
    _config = Config.load()
    return _config