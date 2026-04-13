"""
NFQWS Config Generator - модуль генерации runtime-конфигурации для nfqws/winws

Создаёт и обновляет конфигурационные файлы для поддержки динамических стратегий.
"""

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging

from .config import Config, get_config
from .storage import Storage, Strategy
from .helpers import normalize_domain
from .utils.profiler import get_profiler
profiler = get_profiler("nfqws_config")

logger = logging.getLogger(__name__)


@dataclass
class NfqwsProfile:
    """Профиль стратегии для nfqws"""
    name: str
    strategy_id: int
    zapret_params: str
    hostlist_file: str
    priority: int
    domains_count: int = 0
    created_at: str = ""
    updated_at: str = ""


class NfqwsConfigGenerator:
    """
    Генератор конфигурации для nfqws/winws
    
    Поддерживает:
    - Создание профилей стратегий в формате nfqws --new
    - Генерацию shell-скриптов для запуска
    - Обновление конфигурации при изменении стратегий
    - Валидацию параметров
    """

    @profiler
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._profiles: Dict[str, NfqwsProfile] = {}
        self._config_file: Optional[str] = None
        self._storage: Optional[Storage] = None  # Сохраняем для синхронизации

    @profiler
    async def initialize(self, storage: Storage) -> None:
        """
        Инициализация генератора из базы данных
        
        Args:
            storage: Хранилище данных
        """
        self._storage = storage  # Сохраняем для будущей синхронизации
        await self.sync_from_storage()

    @profiler
    async def sync_from_storage(self) -> None:
        """
        Синхронизация profiles из базы данных
        
        ВАЖНО: Вызывать перед generate_nfqs_args() если profiles могли измениться!
        """
        if self._storage is None:
            logger.warning("Cannot sync: storage not initialized")
            return
        
        # Очищаем и загружаем заново
        self._profiles = {}
        strategies = await self._storage.list_strategies()
        
        for strategy in strategies:
            profile = await self._create_profile(strategy)
            self._profiles[strategy.name] = profile
        
        logger.info(f"Synced {len(self._profiles)} nfqws profiles from storage")

    @profiler
    async def _create_profile(self, strategy: Strategy) -> NfqwsProfile:
        """Создание профиля из стратегии"""
        timestamp = datetime.now().isoformat()
        
        # Определяем имя файла hostlist
        hostlist_file = self.config.get_strategy_file(strategy.name)
        
        return NfqwsProfile(
            name=strategy.name,
            strategy_id=strategy.id,
            zapret_params=strategy.zapret_params,
            hostlist_file=hostlist_file,
            priority=strategy.priority,
            domains_count=strategy.domains_count,
            created_at=strategy.created_at or timestamp,
            updated_at=timestamp
        )

    @profiler
    def generate_nfqs_args(self, include_ipv6: bool = False, include_quic: bool = True) -> List[str]:
        """
        Генерация аргументов командной строки для nfqws/winws
        
        Структура команды соответствует smart_tuner.py и blockcheck.sh:
        1. WinDivert фильтры (--wf-l3, --wf-tcp, --wf-udp)
        2. Файлы фейков (если есть)
        3. UDP профиль для QUIC (fake, ipfrag2)
        4. TCP профили стратегий через --new
        5. Autohostlist профиль
        
        Args:
            include_ipv6: Включить IPv6 фильтры
            include_quic: Включить QUIC/UDP профиль
            
        Returns:
            Список аргументов
        """
        args = []
        
        # 1. WinDivert фильтры - L3 (IPv4/IPv6)
        if include_ipv6:
            args.append("--wf-l3=ipv4,ipv6")
        else:
            args.append("--wf-l3=ipv4")

        # ПЕРЕХВАТ ВСЕГО ТРАФИКА (не только 80/443)
        # Это нужно для работы с приложениями типа Discord, которые используют
        # другие порты (UDP 50000-50100 для голоса, TCP для WebSocket и т.д.)
        args.append("--wf-tcp=*")  # Все TCP соединения
        args.append("--wf-udp=*")  # Все UDP соединения
        
        # 2. Файлы фейков (ищем в стандартных местах)
        fake_quic, fake_tls, fake_http, fake_syndata = self._find_fake_files()
        has_fake_files = fake_quic is not None and fake_tls is not None
        
        if fake_quic:
            args.append(f"--dpi-desync-fake-quic={fake_quic}")
        if fake_tls:
            args.append(f"--dpi-desync-fake-tls={fake_tls}")
        if fake_http:
            args.append(f"--dpi-desync-fake-http={fake_http}")
        if fake_syndata:
            args.append(f"--dpi-desync-fake-syndata={fake_syndata}")
        
        # 3. UDP профиль для QUIC
        if include_quic:
            args.append("--filter-udp=443")
            if has_fake_files:
                # Основной QUIC режим - fake
                args.append("--dpi-desync=fake")
                args.append("--dpi-desync-repeats=4")  # Стандартное значение для QUIC
            else:
                # Fallback - multisplit
                args.append("--dpi-desync=multisplit")
                args.append("--dpi-desync-repeats=2")
            
            # QUIC ipfrag2 как альтернатива (для IPv4)
            args.append("--new")
            args.append("--filter-udp=443")
            args.append("--dpi-desync=ipfrag2")
            args.append("--dpi-desync-ipfrag-pos-udp=24")  # Оптимальная позиция
        
        # 4. TCP профили стратегий через --new
        sorted_profiles = sorted(self._profiles.values(), key=lambda p: p.priority)
        
        for profile in sorted_profiles:
            args.append("--new")
            args.append("--filter-tcp=443")
            args.append(f"--hostlist={profile.hostlist_file}")
            
            # Разбиваем параметры на отдельные аргументы
            params = profile.zapret_params.split()
            args.extend(params)
        
        # 5. Autohostlist профиль (последний - ловит всё остальное)
        # ПУСТАЯ СТРАТЕГИЯ: без --dpi-desync winws просто пропускает трафик,
        # но детектирует проблемы и логирует fail_counter в лог-файл.
        # Auto-Zapret сам подберёт стратегию и добавит домен в нужный hostlist.
        args.append("--new")
        args.append("--filter-tcp=80,443")
        autohostlist_file = os.path.join(self.config.hostlists_dir, "zapret-hosts-auto.txt")
        args.append(f"--hostlist-auto={autohostlist_file}")
        args.append("--hostlist-auto-fail-threshold=3")
        # КРИТИЧЕСКИ ВАЖНО: указываем файл для логирования autohostlist событий!
        # Без этого параметра winws НЕ будет писать лог fail_counter!
        # ВАЖНО: Используем АБСОЛЮТНЫЙ путь, иначе winws пишет лог в свою рабочую директорию!
        log_file_abs = os.path.abspath(self.config.nfqws_log_file)
        args.append(f"--hostlist-auto-debug={log_file_abs}")
        # Без --dpi-desync = прозрачный пропуск трафика
        
        return args
    
    @profiler
    def _find_fake_files(self) -> Tuple[Optional[Path], Optional[Path], Optional[Path], Optional[Path]]:
        """
        Поиск файлов фейков для QUIC, TLS, HTTP и syndata
        
        Returns:
            (fake_quic, fake_tls, fake_http, fake_syndata)
        """
        base_dir = Path(self.config.hostlists_dir).parent
        
        # Возможные пути к файлам fake
        possible_paths = [
            base_dir / "bin" / "blockcheck" / "zapret" / "files" / "fake",
            base_dir / "bin" / "blockcheck" / "files" / "fake",
            base_dir / "bin" / "files" / "fake",
            base_dir / "files" / "fake",
            # Также проверяем zapret-win-bundle структуру
            base_dir / "zapret" / "files" / "fake",
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_dir():
                bins = list(path.glob("*.bin"))
                if bins:
                    # Ищем по ключевым словам в имени файла
                    quic_match = [f for f in bins if 'quic' in f.name.lower()]
                    tls_match = [f for f in bins if 'tls' in f.name.lower() and 'clienthello' in f.name.lower()]
                    http_match = [f for f in bins if 'http' in f.name.lower()]
                    syndata_match = [f for f in bins if 'syndata' in f.name.lower()]
                    
                    # Fallback: если нет точного совпадения, берём первые доступные
                    quic = quic_match[0] if quic_match else None
                    tls = tls_match[0] if tls_match else None
                    http = http_match[0] if http_match else None
                    syndata = syndata_match[0] if syndata_match else None
                    
                    # Если TLS не найден, пробуем любой с 'tls' в имени
                    if not tls:
                        tls_any = [f for f in bins if 'tls' in f.name.lower()]
                        tls = tls_any[0] if tls_any else None
                    
                    return quic, tls, http, syndata
        
        return None, None, None, None

    @profiler
    def generate_startup_script(self, output_path: str, include_daemon: bool = True) -> str:
        """
        Генерация shell-скрипта для запуска nfqws
        
        Args:
            output_path: Путь для сохранения скрипта
            include_daemon: Включить демонизацию процесса
            
        Returns:
            Путь к созданному файлу
        """
        script_lines = [
            "#!/bin/bash",
            "# Auto-generated nfqws startup script",
            f"# Generated at: {datetime.now().isoformat()}",
            "",
            "set -e",
            "",
            "# Configuration",
            f'ZAPRET_DIR="{self.config.zapret_src_dir}"',
            f'BINARIES="$ZAPRET_DIR/binaries/windows-x86_64"',
            f'DATA_DIR="{self.config.hostlists_dir}"',
            f'LOG_DIR="{self.config.nfqws_log_file.rsplit("/", 1)[0] if "/" in self.config.nfqws_log_file else "."}"',
            "",
            "# Create directories",
            'mkdir -p "$DATA_DIR" "$LOG_DIR"',
            "",
            "# PID file",
            'PID_FILE="$DATA_DIR/nfqws.pid"',
            "",
            "# Stop existing process if running",
            'if [ -f "$PID_FILE" ]; then',
            '    if ps -p $(cat "$PID_FILE") > /dev/null 2>&1; then',
            '        echo "Stopping existing nfqws process..."',
            '        kill $(cat "$PID_FILE") 2>/dev/null || true',
            '        sleep 2',
            '    fi',
            '    rm -f "$PID_FILE"',
            'fi',
            "",
            "# Starting nfqws with auto-generated configuration",
            'echo "Starting nfqws..."',
            "",
            "# Command",
            "CMD=(",
        ]
        
        # Добавляем аргументы
        args = self.generate_nfqs_args()
        for arg in args:
            if arg:
                script_lines.append(f'    "{arg}"')
        
        script_lines.extend([
            ")",
            "",
            "# Запуск в фоне или демоне",
            f'if [ "{include_daemon}" = "true" ]; then',
            '    nohup "$BINARIES/nfqws" "${CMD[@]}" > "$LOG_DIR/nfqws.log" 2>&1 &',
            '    echo $! > "$PID_FILE"',
            '    echo "nfqws started with PID $(cat $PID_FILE)"',
            'else',
            '    exec "$BINARIES/nfqws" "${CMD[@]}"',
            'fi',
            "",
            'echo "Done"',
        ])
        
        script_content = "\n".join(script_lines)
        
        # Записываем файл
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(script_content)
        
        # Делаем исполняемым
        os.chmod(output_file, 0o755)
        
        logger.info(f"Generated startup script: {output_file}")
        return str(output_file)

    @profiler
    def generate_windows_batch(self, output_path: str) -> str:
        """
        Генерация Windows batch-файла для запуска winws
        
        Args:
            output_path: Путь для сохранения файла
            
        Returns:
            Путь к созданному файлу
        """
        lines = [
            "@echo off",
            "chcp 65001 >nul",
            "REM Auto-generated winws startup script",
            f"REM Generated at: {datetime.now().isoformat()}",
            "",
            f'cd /d "%~dp0"',
            "",
            "REM Configuration",
            f'set ZAPRET_DIR={self.config.zapret_src_dir}',
            f'set BINARIES=%ZAPRET_DIR%\\binaries\\windows-x86_64',
            f'set DATA_DIR={self.config.hostlists_dir}',
            "",
            "REM Create directories",
            'if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"',
            "",
            "REM PID file",
            'set PID_FILE=%DATA_DIR%\\nfqws.pid',
            "",
            "REM Stop existing process",
            'if exist "%PID_FILE%" (',
            '    echo Stopping existing winws process...',
            '    "%BINARIES%\\killall.exe" -TERM winws 2>nul',
            '    timeout /t 2 /nobreak >nul',
            '    del /F /Q "%PID_FILE%" 2>nul',
            ')',
            "",
            'echo Starting winws...',
            "",
            "REM Start winws",
            'start "WinWS" /B "%BINARIES%\\winws.exe" ^',
        ]
        
        # Добавляем аргументы
        args = self.generate_nfqs_args()
        for i, arg in enumerate(args):
            if arg:
                suffix = " ^" if i < len(args) - 1 else ""
                lines.append(f'  {arg}{suffix}')
        
        lines.extend([
            "",
            'echo WinWS started',
            'echo %ERRORLEVEL% > "%PID_FILE%"',
            "",
            "pause >nul",
        ])
        
        script_content = "\n".join(lines)
        
        # Записываем файл
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(script_content)
        
        logger.info(f"Generated Windows batch script: {output_file}")
        return str(output_file)

    @profiler
    def generate_systemd_service(self, output_path: str) -> str:
        """
        Генерация systemd service файла
        
        Args:
            output_path: Путь для сохранения файла
            
        Returns:
            Путь к созданному файлу
        """
        script_path = self.generate_startup_script(
            os.path.join(self.config.hostlists_dir, "start-nfqws.sh"),
            include_daemon=False
        )
        
        # Получаем директорию для логов
        log_dir = self.config.nfqws_log_file.rsplit("/", 1)[0] if "/" in self.config.nfqws_log_file else "/var/log"
        
        service_content = f"""[Unit]
Description=NFQWS Auto-Zapret Service
After=network.target

[Service]
Type=forking
ExecStart={script_path}
ExecStop=/bin/kill -TERM $MAINPID
PIDFile={self.config.hostlists_dir}/nfqws.pid
Restart=on-failure
RestartSec=10

# Environment
Environment="ZAPRET_DIR={self.config.zapret_src_dir}"
Environment="DATA_DIR={self.config.hostlists_dir}"
Environment="LOG_DIR={log_dir}"

# Security
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={self.config.hostlists_dir} {log_dir}

[Install]
WantedBy=multi-user.target
"""
        
        # Записываем файл
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(service_content)
        
        logger.info(f"Generated systemd service: {output_file}")
        return str(output_file)

    @profiler
    async def update_profile(self, strategy: Strategy) -> NfqwsProfile:
        """
        Обновление профиля стратегии
        
        Args:
            strategy: Обновлённая стратегия
            
        Returns:
            Обновлённый профиль
        """
        profile = await self._create_profile(strategy)
        self._profiles[strategy.name] = profile
        
        logger.info(f"Updated profile for strategy '{strategy.name}'")
        return profile

    @profiler
    async def remove_profile(self, strategy_name: str) -> bool:
        """
        Удаление профиля стратегии
        
        Args:
            strategy_name: Имя стратегии
            
        Returns:
            True если удалён
        """
        if strategy_name in self._profiles:
            del self._profiles[strategy_name]
            logger.info(f"Removed profile for strategy '{strategy_name}'")
            return True
        
        return False

    @profiler
    def get_profile(self, name: str) -> Optional[NfqwsProfile]:
        """Получение профиля по имени"""
        return self._profiles.get(name)

    @profiler
    def list_profiles(self) -> List[NfqwsProfile]:
        """Список всех профилей"""
        return list(self._profiles.values())

    @profiler
    def validate_params(self, params: str) -> Tuple[bool, str]:
        """
        Валидация параметров zapret

        Args:
            params: Параметры для проверки

        Returns:
            (valid, error_message)
        """
        if not params or not params.strip():
            return False, "Empty parameters"

        # Проверяем наличие --dpi-desync
        if "--dpi-desync" not in params:
            return False, "Missing required --dpi-desync parameter"

        # Проверяем корректность синтаксиса (базовая)
        # Разрешаем буквы, цифры, -, _, =, ,, +, ., :, /, @ и пробелы
        invalid_chars = set(params) - set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=,+.:/@ "
        )
        if invalid_chars:
            return False, f"Invalid characters in parameters: {invalid_chars}"

        return True, ""

    @profiler
    def get_config_summary(self) -> Dict[str, Any]:
        """Получение сводки конфигурации"""
        return {
            "profiles_count": len(self._profiles),
            "profiles": [
                {
                    "name": p.name,
                    "strategy_id": p.strategy_id,
                    "priority": p.priority,
                    "domains_count": p.domains_count,
                    "zapret_params": p.zapret_params,
                    "hostlist_file": p.hostlist_file,
                }
                for p in sorted(self._profiles.values(), key=lambda x: x.priority)
            ],
            "nfqws_args": self.generate_nfqs_args(),
        }


# Глобальный экземпляр
_generator: Optional[NfqwsConfigGenerator] = None


@profiler
def get_generator(config: Optional[Config] = None) -> NfqwsConfigGenerator:
    """Получить глобальный экземпляр генератора"""
    global _generator
    
    if _generator is None:
        _generator = NfqwsConfigGenerator(config or get_config())
    
    return _generator


@profiler
async def create_generator(config: Optional[Config] = None) -> NfqwsConfigGenerator:
    """Создание и инициализация генератора"""
    generator = NfqwsConfigGenerator(config or get_config())
    return generator