"""
NFQWS Config Generator - модуль генерации runtime-конфигурации для nfqws/winws (Zapret2)

Создаёт и обновляет конфигурационные файлы для поддержки динамических стратегий.
Адаптировано для Zapret2 с поддержкой --lua-desync, --lua-init, --payload.
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
        Генерация аргументов командной строки для nfqws2/winws2 (Zapret2)

        Структура команды соответствует blockcheck2.sh:
        1. WinDivert фильтры (--wf-l3, --wf-tcp-out, --wf-udp)
        2. Lua инициализация (--lua-init для zapret-lib.lua и zapret-antidpi.lua)
        3. Файлы фейков (blob файлы)
        4. UDP профиль для QUIC (lua-desync fake)
        5. TCP профили стратегий через --new (lua-desync)
        6. Autohostlist профиль

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

        # Zapret2: используем --wf-tcp-out вместо --wf-tcp
        args.append("--wf-tcp-out=80,443")

        # Zapret2: Windows специфичные флаги
        args.append("--wf-dup-check=0")
        args.append("--wf-tcp-empty=1")

        if include_quic:
            args.append("--wf-udp=443")

        # 2. Lua инициализация (КРИТИЧЕСКИ ВАЖНО для Zapret2!)
        lua_dir = self.config.zapret2_lua_dir
        if lua_dir and os.path.exists(lua_dir):
            zapret_lib = os.path.join(lua_dir, "zapret-lib.lua")
            antidpi_lib = os.path.join(lua_dir, "zapret-antidpi.lua")
            if os.path.exists(zapret_lib):
                args.append(f"--lua-init=@{zapret_lib}")
            if os.path.exists(antidpi_lib):
                args.append(f"--lua-init=@{antidpi_lib}")
            else:
                logger.warning(f"Lua antidpi script not found: {antidpi_lib}")
        elif lua_dir:
            logger.error(f"Lua directory not found: {lua_dir}. WinWS2 may not function correctly.")
        else:
            logger.error("zapret2_lua_dir is not configured. WinWS2 will not have Lua support.")

        # 3. Файлы фейков (blob файлы для Zapret2)
        # В Zapret2 фейки задаются через --lua-desync=fake:blob=..., НЕ через --dpi-desync-fake-*
        fake_quic, fake_tls, fake_http, fake_syndata = self._find_fake_files()
        has_fake_files = fake_quic is not None and fake_tls is not None

        # 4. UDP профиль для QUIC
        if include_quic:
            args.append("--filter-udp=443")
            if has_fake_files:
                # Zapret2: используем lua-desync вместо dpi-desync
                args.append("--lua-desync=fake:blob=fake_default_quic:repeats=4")
            else:
                # Fallback - multisplit
                args.append("--lua-desync=multisplit:pos=1:repeats=2")

            # QUIC ipfrag2 как альтернатива (для IPv6 extension headers)
            args.append("--new")
            args.append("--filter-udp=443")
            args.append("--lua-desync=send:ip6_hopbyhop:ip6_destopt")

        # 5. TCP профили стратегий через --new
        sorted_profiles = sorted(self._profiles.values(), key=lambda p: p.priority)

        for profile in sorted_profiles:
            args.append("--new")
            args.append("--filter-tcp=443")
            args.append(f"--hostlist={profile.hostlist_file}")

            # Zapret2: преобразуем параметры в lua-desync формат
            lua_params = self._convert_to_lua_desync(profile.zapret_params)
            args.extend(lua_params)

        # 6. Autohostlist профиль (последний - ловит всё остальное)
        # ПУСТАЯ СТРАТЕГИЯ: без --lua-desync winws2 просто пропускает трафик,
        # но детектирует проблемы и логирует fail_counter в лог-файл.
        args.append("--new")
        args.append("--filter-tcp=80,443")
        autohostlist_file = os.path.join(self.config.hostlists_dir, "zapret-hosts-auto.txt")
        args.append(f"--hostlist-auto={autohostlist_file}")
        args.append("--hostlist-auto-fail-threshold=3")
        # КРИТИЧЕСКИ ВАЖНО: указываем файл для логирования autohostlist событий!
        log_file_abs = os.path.abspath(self.config.nfqws_log_file)
        args.append(f"--hostlist-auto-debug={log_file_abs}")

        return args

    @profiler
    def _convert_to_lua_desync(self, zapret_params: str) -> List[str]:
        """
        Конвертация параметров Zapret1 в формат Zapret2 lua-desync

        Поддерживает ВСЕ функции Zapret2:
        - Basic: fake, multisplit, multidisorder, fakedsplit, fakeddisorder
        - HTTP: http_hostcase, http_domcase, http_methodeol, http_unixeol
        - SYN-ACK: synack, synack_split
        - TLS: tls_client_hello_clone
        - Obfuscation: synhide, wgobfs, ippxor, udp2icmp
        - UDP: udplen
        - IP frag: ipfrag_disorder
        - Orchestrators: circular, condition, stopif, repeater

        Args:
            zapret_params: Строка параметров в формате Zapret1

        Returns:
            Список аргументов в формате Zapret2
        """
        from .helpers import parse_lua_desync_params, build_lua_desync_params

        # Если параметры уже в формате lua-desync, возвращаем как есть
        if "--lua-desync=" in zapret_params:
            return zapret_params.split()

        # Парсим старые параметры
        parts = zapret_params.split()
        params_dict = {}

        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                params_dict[key] = value
            else:
                params_dict[part] = True

        # Проверяем HTTP-модификаторы
        http_modifiers = ["http_hostcase", "http_domcase", "http_methodeol", "http_unixeol"]
        for modifier in http_modifiers:
            if modifier in params_dict:
                lua_params = build_lua_desync_params(modifier)
                return [f"--lua-desync={lua_params}"]

        # Проверяем оркестраторы
        orchestrators = ["circular", "condition", "stopif", "repeater"]
        for orch in orchestrators:
            if orch in params_dict:
                # Передаём параметры оркестратора как есть
                return [f"--lua-desync={zapret_params.strip()}"]

        # Проверяем обфускацию
        obfuscation = ["synhide", "wgobfs", "ippxor", "udp2icmp"]
        for obfs in obfuscation:
            if obfs in params_dict:
                lua_params = build_lua_desync_params(obfs)
                return [f"--lua-desync={lua_params}"]

        # Проверяем SYN-ACK
        if "synack" in params_dict or "synack_split" in params_dict:
            mode = params_dict.get("--dpi-desync-synack-mode", "")
            desync_type = "synack_split" if "synack_split" in params_dict else "synack"
            if mode:
                lua_params = build_lua_desync_params(desync_type, mode=mode)
            else:
                lua_params = build_lua_desync_params(desync_type)
            return [f"--lua-desync={lua_params}"]

        # Проверяем TLS clone
        if "tls_client_hello_clone" in params_dict:
            sni_action = params_dict.get("--dpi-desync-tls-clone-action", "mod")
            sni = params_dict.get("--dpi-desync-tls-clone-sni", "example.com")
            lua_params = build_lua_desync_params("tls_client_hello_clone", sni_action=sni_action, sni=sni)
            return [f"--lua-desync={lua_params}"]

        # Проверяем udplen
        if "udplen" in params_dict:
            length = params_dict.get("--dpi-desync-udplen", "")
            if length:
                lua_params = build_lua_desync_params("udplen", length=length)
            else:
                lua_params = build_lua_desync_params("udplen")
            return [f"--lua-desync={lua_params}"]

        # Проверяем ipfrag_disorder
        if "ipfrag_disorder" in params_dict:
            next_proto = params_dict.get("--dpi-desync-ipfrag-next-proto", "")
            if next_proto:
                lua_params = build_lua_desync_params("ipfrag_disorder", next_proto=next_proto)
            else:
                lua_params = build_lua_desync_params("ipfrag_disorder")
            return [f"--lua-desync={lua_params}"]

        # Стандартная конвертация для базовых типов
        lua_args = []

        # Определяем тип десинхронизации
        desync_mode = params_dict.get("--dpi-desync", "multisplit")

        # Базовые параметры lua-desync
        lua_params = {}

        # Конвертируем fooling в параметры lua-desync
        fool = params_dict.get("--dpi-desync-fooling")
        if fool:
            # Маппинг старых fooling методов в новые
            fool_map = {
                "ts": "tcp_ts=-1000",
                "md5sig": "tcp_md5",
                "badseq": "tcp_seq=-3000",
                "badsum": "badsum",
                "datanoack": "tcp_flags_unset=ACK",
                "hopbyhop": "ip6_hopbyhop",
                "hopbyhop2": "ip6_hopbyhop:ip6_hopbyhop2",
                "destopt": "ip6_destopt",
            }
            lua_params["fooling"] = fool_map.get(fool, fool)

        # Конвертируем TTL
        ttl = params_dict.get("--dpi-desync-ttl")
        if ttl:
            lua_params["ip4_ttl"] = ttl

        # Конвертируем split-pos
        pos = params_dict.get("--dpi-desync-split-pos")
        if pos:
            lua_params["pos"] = pos

        # Конвертируем wssize
        wssize = params_dict.get("--wssize")
        if wssize:
            wsize_parts = wssize.split(":")
            lua_params["wsize"] = wsize_parts[0] if len(wsize_parts) > 0 else "1"
            if len(wsize_parts) > 1:
                lua_params["scale"] = wsize_parts[1]
            desync_mode = "wssize"

        # Конвертируем seqovl
        seqovl = params_dict.get("--dpi-desync-split-seqovl")
        if seqovl:
            lua_params["seqovl"] = seqovl
            desync_mode = "tcpseg"

        # Конвертируем autottl
        autottl = params_dict.get("--dpi-desync-autottl")
        if autottl:
            lua_params["autottl"] = autottl

        # Определяем payload
        payload = params_dict.get("--payload", "tls_client_hello")

        # Строим lua-desync строку
        if desync_mode == "fake":
            lua_params["blob"] = "fake_default_tls"
            lua_desync = build_lua_desync_params("fake", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "multisplit":
            lua_desync = build_lua_desync_params("multisplit", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "multidisorder":
            lua_desync = build_lua_desync_params("multidisorder", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "fakedsplit":
            lua_desync = build_lua_desync_params("fakedsplit", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "fakeddisorder":
            lua_desync = build_lua_desync_params("fakeddisorder", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "hostfakesplit":
            lua_desync = build_lua_desync_params("hostfakesplit", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "wssize":
            lua_desync = build_lua_desync_params("wssize", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "syndata":
            lua_params["blob"] = "fake_default_syndata"
            lua_desync = build_lua_desync_params("syndata", **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")
        elif desync_mode == "ipfrag2":
            lua_args.append("--lua-desync=send:ip6_hopbyhop:ip6_destopt")
        else:
            # Fallback
            lua_desync = build_lua_desync_params(desync_mode, **lua_params)
            lua_args.append(f"--lua-desync={lua_desync}")

        # Добавляем payload если есть
        if payload:
            lua_args.append(f"--payload={payload}")

        return lua_args if lua_args else [f"--lua-desync={desync_mode}"]
    
    @profiler
    def _find_fake_files(self) -> Tuple[Optional[Path], Optional[Path], Optional[Path], Optional[Path]]:
        """
        Поиск файлов фейков для QUIC, TLS, HTTP и syndata

        Returns:
            (fake_quic, fake_tls, fake_http, fake_syndata)
        """
        base_dir = Path(self.config.hostlists_dir).parent

        if not base_dir.exists():
            logger.warning(f"[fake_files] Base directory does not exist: {base_dir}")
            return None, None, None, None

        # Возможные пути к файлам fake
        possible_paths = [
            base_dir / "bin" / "zapret2" / "files" / "fake",  # Zapret2 путь
            base_dir / "bin" / "blockcheck" / "zapret" / "files" / "fake",
            base_dir / "bin" / "blockcheck" / "files" / "fake",
            base_dir / "bin" / "files" / "fake",
            base_dir / "files" / "fake",
            # Также проверяем zapret-win-bundle структуру
            base_dir / "zapret" / "files" / "fake",
        ]

        for path in possible_paths:
            if not path.exists():
                logger.debug(f"[fake_files] Path not found: {path}")
                continue
            if not path.is_dir():
                logger.debug(f"[fake_files] Path is not a directory: {path}")
                continue
            bins = list(path.glob("*.bin"))
            if not bins:
                logger.debug(f"[fake_files] No .bin files in: {path}")
                continue

            logger.info(f"[fake_files] Found {len(bins)} .bin files in {path}")

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

        logger.warning("[fake_files] No fake files found in any path!")
        return None, None, None, None

    @profiler
    def generate_startup_script(self, output_path: str, include_daemon: bool = True) -> str:
        """
        Генерация shell-скрипта для запуска nfqws2 (Zapret2)

        Args:
            output_path: Путь для сохранения скрипта
            include_daemon: Включить демонизацию процесса

        Returns:
            Путь к созданному файлу
        """
        # Проверяем существование директории с бинарниками
        binaries_dir = os.path.join(self.config.zapret_src_dir, "binaries", "linux-x86_64")
        if not os.path.exists(binaries_dir):
            raise FileNotFoundError(
                f"Binaries directory not found: {binaries_dir}. "
                f"Ensure Zapret2 is properly installed at {self.config.zapret_src_dir}"
            )

        script_lines = [
            "#!/bin/bash",
            "# Auto-generated nfqws2 startup script (Zapret2)",
            f"# Generated at: {datetime.now().isoformat()}",
            "",
            "set -e",
            "",
            "# Configuration",
            f'ZAPRET_DIR="{self.config.zapret_src_dir}"',
            f'BINARIES="$ZAPRET_DIR/binaries/linux-x86_64"',
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
            '        echo "Stopping existing nfqws2 process..."',
            '        kill $(cat "$PID_FILE") 2>/dev/null || true',
            '        sleep 2',
            '    fi',
            '    rm -f "$PID_FILE"',
            'fi',
            "",
            "# Starting nfqws2...",
            'echo "Starting nfqws2..."',
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
            '    nohup "$BINARIES/nfqws2" "${CMD[@]}" > "$LOG_DIR/nfqws2.log" 2>&1 &',
            '    echo $! > "$PID_FILE"',
            '    echo "nfqws2 started with PID $(cat $PID_FILE)"',
            'else',
            '    exec "$BINARIES/nfqws2" "${CMD[@]}"',
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
        Генерация Windows batch-файла для запуска winws2

        Args:
            output_path: Путь для сохранения файла

        Returns:
            Путь к созданному файлу
        """
        # Проверяем существование директории с бинарниками
        binaries_dir = os.path.join(self.config.zapret_src_dir, "binaries", "windows-x86_64")
        if not os.path.exists(binaries_dir):
            raise FileNotFoundError(
                f"Windows binaries directory not found: {binaries_dir}. "
                f"Ensure Zapret2 is properly installed at {self.config.zapret_src_dir}"
            )

        lines = [
            "@echo off",
            "chcp 65001 >nul",
            "REM Auto-generated winws2 startup script (Zapret2)",
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
            '    echo Stopping existing winws2 process...',
            '    "%BINARIES%\\killall.exe" -TERM winws2 2>nul',
            '    timeout /t 2 /nobreak >nul',
            '    del /F /Q "%PID_FILE%" 2>nul',
            ')',
            "",
            'echo Starting winws2...',
            "",
            "REM Start winws2",
            'start "WinWS2" /B "%BINARIES%\\winws2.exe" ^',
        ]

        # Добавляем аргументы
        args = self.generate_nfqs_args()
        for i, arg in enumerate(args):
            if arg:
                suffix = " ^" if i < len(args) - 1 else ""
                lines.append(f'  {arg}{suffix}')

        lines.extend([
            "",
            'echo WinWS2 started',
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
        Валидация параметров zapret (поддержка обоих форматов)

        Args:
            params: Параметры для проверки

        Returns:
            (valid, error_message)
        """
        if not params or not params.strip():
            return False, "Empty parameters"

        # Zapret2: проверяем наличие --lua-desync или --dpi-desync
        has_lua_desync = "--lua-desync" in params
        has_dpi_desync = "--dpi-desync" in params

        if not has_lua_desync and not has_dpi_desync:
            return False, "Missing required --lua-desync or --dpi-desync parameter"

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