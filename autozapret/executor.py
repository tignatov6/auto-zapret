"""
Executor - модуль применения стратегий
Управление hostlist файлами и отправка SIGHUP nfqws
"""

import asyncio
import os
import signal
import time
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import logging

from .config import Config, get_config
from .helpers import normalize_domain
from .utils.profiler import get_profiler
profiler = get_profiler("executor")

logger = logging.getLogger(__name__)

# Пути к winws и файлам фейков (для Windows)
BASE_DIR = Path(__file__).parent.parent.resolve()
WINWS_PATH = BASE_DIR / "bin" / "winws.exe"
FAKE_QUIC_PATH = BASE_DIR / "bin" / "blockcheck" / "zapret" / "files" / "fake" / "quic_initial_www_google_com.bin"
FAKE_TLS_PATH = BASE_DIR / "bin" / "blockcheck" / "zapret" / "files" / "fake" / "tls_clienthello_www_google_com.bin"

# Время ожидания после запуска winws (оптимизировано на основе тестов)
# Формула: max(измеренное) × 1.33 = оптимальное (запас 33%)
# Измерено 2026-03-23: max_start=367ms → (367-50) × 1.33 = 0.42s
# УМЕНЬШЕНО ДО 0.3с как minsleep в blockcheck.sh для ускорения брутфорса
INIT_WAIT = 0.5


class ExecutorError(Exception):
    """Ошибка Executor"""
    pass


class Executor:
    """Применение стратегий к доменам"""

    @profiler
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._last_signal_time: float = 0
        self._signal_lock = asyncio.Lock()

        # Файловые lock'и для предотвращения гонок
        self._file_locks: Dict[str, asyncio.Lock] = {}

        # Debounce для HUP сигналов
        self._hup_pending = False
        self._hup_debounce_task: Optional[asyncio.Task] = None
        self._hup_debounce_delay = 0.5  # Секунды задержки перед отправкой

        # Управление процессом winws для brute-force
        self._winws_process: Optional[subprocess.Popen] = None
        self._startup_time: Optional[float] = None  # Измеренное время запуска winws
        self._process_lock = asyncio.Lock()
        self._full_restart_lock = asyncio.Lock()  # Защита от одновременного рестарта

        # Обязательно для работы fooling=ts в Windows!
        if sys.platform == 'win32':
            try:
                subprocess.run(["netsh", "interface", "tcp", "set", "global", "timestamps=enabled"], capture_output=True)
                logger.info("Enabled TCP timestamps for Windows (required for 'ts' fooling)")
            except Exception as e:
                logger.warning(f"Failed to enable TCP timestamps: {e}")
    
    @profiler
    async def add_domain_to_hostlist(self, filename: str, domain: str) -> Tuple[bool, str]:
        """
        Добавление домена в hostlist файл (асинхронная версия с lock)

        Args:
            filename: Имя файла (полный путь или относительный)
            domain: Домен для добавления

        Returns:
            (success, message)
        """
        # Нормализуем домен
        domain = normalize_domain(domain)
        
        # Определяем полный путь
        if not os.path.isabs(filename):
            filepath = os.path.join(self.config.hostlists_dir, filename)
        else:
            filepath = filename

        # Получаем lock для файла
        if filepath not in self._file_locks:
            self._file_locks[filepath] = asyncio.Lock()
        
        async with self._file_locks[filepath]:
            try:
                # Создаём директорию если не существует
                Path(filepath).parent.mkdir(parents=True, exist_ok=True)

                # Проверяем на дубликат (асинхронная версия)
                exists = await asyncio.to_thread(self._domain_exists_in_file, filepath, domain)
                if exists:
                    return True, f"Domain {domain} already exists in {filename}"  # Возвращаем True как success

                # Добавляем домен
                await asyncio.to_thread(self._write_domain_to_file, filepath, domain)

                logger.info(f"Added domain '{domain}' to {filename}")
                return True, f"Domain {domain} added to {filename}"

            except PermissionError as e:
                logger.error(f"Permission denied writing to {filename}: {e}")
                return False, f"Permission denied: {e}"
            except OSError as e:
                logger.error(f"OS error writing to {filename}: {e}")
                return False, f"OS error: {e}"
            except Exception as e:
                logger.error(f"Unexpected error writing to {filename}: {e}")
                return False, f"Unexpected error: {e}"

    @profiler
    def _write_domain_to_file(self, filepath: str, domain: str) -> None:
        """Синхронная запись домена в файл (для asyncio.to_thread)"""
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(f"{domain}\n")
    
    @profiler
    def _domain_exists_in_file(self, filepath: str, domain: str) -> bool:
        """Проверка наличия домена в файле"""
        if not os.path.exists(filepath):
            return False
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        # Проверяем точное совпадение и совпадение поддоменов
                        if line == domain.lower():
                            return True
                        # Проверяем если домен уже есть как поддомен
                        if domain.lower().endswith("." + line):
                            return True
        except (OSError, UnicodeDecodeError):
            return False
        
        return False

    @profiler
    async def remove_domain_from_hostlist(self, filename: str, domain: str) -> Tuple[bool, str]:
        """
        Удаление домена из hostlist файла (асинхронная версия с lock)

        Args:
            filename: Имя файла
            domain: Домен для удаления

        Returns:
            (success, message) - идемпотентно: True если домен не найден (уже удалён)
        """
        # Нормализуем домен
        domain = normalize_domain(domain)

        if not os.path.isabs(filename):
            filepath = os.path.join(self.config.hostlists_dir, filename)
        else:
            filepath = filename

        if not os.path.exists(filepath):
            return True, f"File {filename} does not exist"  # Идемпотентно: файла нет - домен точно удалён

        # Получаем lock для файла
        if filepath not in self._file_locks:
            self._file_locks[filepath] = asyncio.Lock()

        async with self._file_locks[filepath]:
            try:
                # Читаем все строки
                lines = await asyncio.to_thread(self._read_file_lines, filepath)

                # Фильтруем удаляемый домен
                new_lines = []
                removed = False
                for line in lines:
                    stripped = line.strip().lower()
                    if stripped == domain.lower():
                        removed = True
                        continue
                    new_lines.append(line)

                if not removed:
                    # Идемпотентно: домен уже удалён
                    return True, f"Domain {domain} not present in {filename}"

                # Записываем обратно
                await asyncio.to_thread(self._write_file_lines, filepath, new_lines)

                logger.info(f"Removed domain '{domain}' from {filename}")
                return True, f"Domain {domain} removed from {filename}"

            except Exception as e:
                logger.error(f"Error removing domain from {filename}: {e}")
                return False, f"Error: {e}"

    @profiler
    def _read_file_lines(self, filepath: str) -> List[str]:
        """Синхронное чтение строк из файла (для asyncio.to_thread)"""
        with open(filepath, "r", encoding="utf-8") as f:
            return f.readlines()

    @profiler
    def _write_file_lines(self, filepath: str, lines: List[str]) -> None:
        """Синхронная запись строк в файл (для asyncio.to_thread)"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
    
    @profiler
    async def send_hup_to_nfqws(self) -> Tuple[bool, str]:
        """
        Отправка SIGHUP процессу nfqws с debounce

        Returns:
            (success, message)
        """
        import time
        
        # Устанавливаем pending флаг
        self._hup_pending = True
        
        # Отменяем предыдущую задачу если есть
        if self._hup_debounce_task and not self._hup_debounce_task.done():
            self._hup_debounce_task.cancel()
        
        # Создаём новую задачу с задержкой
        self._hup_debounce_task = asyncio.create_task(self._send_hup_delayed())
        
        return True, "SIGHUP scheduled (debounced)"
    
    @profiler
    async def _send_hup_delayed(self) -> Tuple[bool, str]:
        """Отложенная отправка SIGHUP с debounce"""
        import time
        
        # Ждём debounce delay
        await asyncio.sleep(self._hup_debounce_delay)
        
        async with self._signal_lock:
            # Сбрасываем pending
            self._hup_pending = False
            
            # Проверяем cooldown
            current_time = time.time()
            if current_time - self._last_signal_time < self.config.signal_cooldown_seconds:
                logger.debug("SIGHUP cooldown active, skipping")
                return False, "SIGHUP cooldown active"

            try:
                pid = self._find_nfqws_pid()
                if pid is None:
                    return False, "nfqws process not found"

                # Отправляем SIGHUP (только Unix, на Windows не поддерживается)
                import sys
                if sys.platform == 'win32':
                    # Windows: SIGHUP не поддерживается, используем альтернативу
                    # nfqws на Windows автоматически перечитывает hostlist файлы
                    logger.debug(f"Windows: SIGHUP not supported, hostlist files updated for PID {pid}")
                    self._last_signal_time = current_time
                    return True, f"Hostlist updated (Windows, PID: {pid})"
                else:
                    # Unix: отправляем SIGHUP
                    os.kill(pid, signal.SIGHUP)
                    self._last_signal_time = current_time

                    logger.info(f"Sent SIGHUP to nfqws (PID: {pid})")
                    return True, f"SIGHUP sent to nfqws (PID: {pid})"

            except PermissionError:
                logger.error("Permission denied sending SIGHUP to nfqws")
                return False, "Permission denied"
            except ProcessLookupError:
                logger.error("nfqws process not found")
                return False, "Process not found"
            except Exception as e:
                logger.error(f"Error sending SIGHUP: {e}")
                return False, f"Error: {e}"
    
    @profiler
    def _find_nfqws_pid(self) -> Optional[int]:
        """Поиск PID процесса nfqws"""
        # Пробуем прочитать из PID файла
        pid_file = self.config.nfqws_pid_file
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    pid = int(f.read().strip())
                    # Проверяем что процесс существует
                    os.kill(pid, 0)  # Signal 0 проверяет существование
                    return pid
            except (ValueError, OSError):
                pass
        
        # Пробуем найти через pgrep (Unix)
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-x", "nfqws"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split()[0])
        except (subprocess.SubprocessError, ValueError, FileNotFoundError):
            pass
        
        # Пробуем найти winws (Windows)
        try:
            import subprocess
            result = subprocess.run(
                ["wmic", "process", "where", "name='winws.exe'", "get", "processid"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:]:  # Пропускаем заголовок
                    pid_str = line.strip()
                    if pid_str.isdigit():
                        return int(pid_str)
        except (subprocess.SubprocessError, ValueError, FileNotFoundError):
            pass
        
        return None
    
    @profiler
    async def apply_strategy(self, domain: str, strategy_name: str) -> Tuple[bool, str]:
        """
        Применение стратегии к домену

        Args:
            domain: Домен
            strategy_name: Имя стратегии

        Returns:
            (success, message)
        """
        # Получаем файл стратегии
        filename = self.config.get_strategy_file(strategy_name)

        # Добавляем домен в файл (асинхронная версия)
        success, msg = await self.add_domain_to_hostlist(filename, domain)
        if not success:
            return success, msg

        # Отправляем SIGHUP
        hup_success, hup_msg = await self.send_hup_to_nfqws()
        if not hup_success:
            logger.warning(f"SIGHUP failed but domain was added: {hup_msg}")
            # Возвращаем успех так как домен добавлен

        return True, f"Strategy '{strategy_name}' applied to {domain}"

    @profiler
    async def reassign_domain(self, domain: str, old_strategy_name: str, new_strategy_name: str) -> Tuple[bool, str]:
        """
        Перенос домена из одной стратегии в другую с rollback при ошибке

        Args:
            domain: Домен
            old_strategy_name: Имя старой стратегии
            new_strategy_name: Имя новой стратегии

        Returns:
            (success, message)
        """
        # Нормализуем домен
        domain = normalize_domain(domain)

        # Проверяем был ли домен в старом файле (асинхронная проверка через to_thread)
        old_file = self.config.get_strategy_file(old_strategy_name)
        domain_was_in_old = await asyncio.to_thread(self._domain_exists_in_file, old_file, domain)

        # Удаляем из старой стратегии (идемпотентно)
        success, msg = await self.remove_domain_from_hostlist(old_file, domain)
        if not success:
            return False, f"Failed to remove from old strategy: {msg}"

        # Добавляем в новую стратегию
        new_file = self.config.get_strategy_file(new_strategy_name)
        success, msg = await self.add_domain_to_hostlist(new_file, domain)

        if not success:
            # ROLLBACK - возвращаем домен в старый файл если он там был
            if domain_was_in_old:
                rollback_success, rollback_msg = await self.add_domain_to_hostlist(old_file, domain)
                if not rollback_success:
                    logger.error(f"ROLLBACK FAILED: Could not add {domain} back to {old_strategy_name}: {rollback_msg}")
            return False, f"Failed to add to new strategy: {msg}"

        # Отправляем SIGHUP
        hup_success, hup_msg = await self.send_hup_to_nfqws()
        if not hup_success:
            logger.warning(f"SIGHUP failed but domain was reassigned: {hup_msg}")

        return True, f"Domain '{domain}' reassigned from '{old_strategy_name}' to '{new_strategy_name}'"

    @profiler
    async def remove_domain(self, domain: str, strategy_name: str) -> Tuple[bool, str]:
        """
        Удаление домена из стратегии
        
        Args:
            domain: Домен
            strategy_name: Имя стратегии
            
        Returns:
            (success, message)
        """
        filename = self.config.get_strategy_file(strategy_name)
        success, msg = await self.remove_domain_from_hostlist(filename, domain)
        
        if success:
            # Отправляем SIGHUP
            hup_success, hup_msg = await self.send_hup_to_nfqws()
            if not hup_success:
                logger.warning(f"SIGHUP failed but domain was removed: {hup_msg}")
        
        return success, msg
    
    @profiler
    def get_strategy_file_content(self, strategy_name: str) -> List[str]:
        """Получение содержимого файла стратегии"""
        filename = self.config.get_strategy_file(strategy_name)
        
        if not os.path.exists(filename):
            return []
        
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError:
            return []
    
    @profiler
    def list_strategy_files(self) -> List[str]:
        """Список файлов стратегий"""
        if not os.path.exists(self.config.hostlists_dir):
            return []

        files = []
        for f in os.listdir(self.config.hostlists_dir):
            if f.startswith(self.config.strategy_prefix) and f.endswith(".txt"):
                files.append(f)

        return sorted(files)
    
    @profiler
    async def flush_pending_hup(self, timeout: float = 2.0) -> Tuple[bool, str]:
        """
        Принудительная отправка pending HUP сигнала (если есть отложенные)
        
        Args:
            timeout: Максимальное время ожидания в секундах
            
        Returns:
            (success, message)
        """
        if not self._hup_pending:
            return True, "No pending SIGHUP"
        
        # Ждём завершения debounce задачи
        if self._hup_debounce_task and not self._hup_debounce_task.done():
            try:
                await asyncio.wait_for(self._hup_debounce_task, timeout=timeout)
                return True, "Pending SIGHUP sent"
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for pending SIGHUP")
                return False, "Timeout waiting for pending SIGHUP"
            except Exception as e:
                logger.error(f"Error waiting for pending SIGHUP: {e}")
                return False, f"Error: {e}"
        
        return True, "No pending SIGHUP"
    
    # ══════════════════════════════════════════════════════════
    #         УПРАВЛЕНИЕ WINWS ДЛЯ BRUTE-FORCE
    # ══════════════════════════════════════════════════════════
    
    @profiler
    def _find_fake_files(self) -> Tuple[Optional[Path], Optional[Path], Optional[Path], Optional[Path]]:
        """
        Поиск файлов фейков для QUIC, TLS, HTTP и syndata
        
        Returns:
            (fake_quic, fake_tls, fake_http, fake_syndata)
        """
        possible_paths = [
            BASE_DIR / "bin" / "blockcheck" / "zapret" / "files" / "fake",
            BASE_DIR / "bin" / "blockcheck" / "files" / "fake",
            BASE_DIR / "bin" / "files" / "fake",
            BASE_DIR / "files" / "fake",
            BASE_DIR / "zapret" / "files" / "fake",
        ]
        
        for i, path in enumerate(possible_paths):
            if path.exists() and path.is_dir():
                bins = list(path.glob("*.bin"))
                if bins:
                    logger.info(f"[fake_files] Found {len(bins)} .bin files in {path}")
                    
                    # Ищем по ключевым словам
                    quic_match = [f for f in bins if 'quic' in f.name.lower()]
                    tls_match = [f for f in bins if 'tls' in f.name.lower() and ('hello' in f.name.lower() or 'client' in f.name.lower())]
                    http_match = [f for f in bins if 'http' in f.name.lower()]
                    syndata_match = [f for f in bins if 'syndata' in f.name.lower()]
                    
                    quic = quic_match[0] if quic_match else None
                    tls = tls_match[0] if tls_match else None
                    http = http_match[0] if http_match else None
                    syndata = syndata_match[0] if syndata_match else None
                    
                    # Fallback для TLS
                    if not tls:
                        tls_any = [f for f in bins if 'tls' in f.name.lower()]
                        tls = tls_any[0] if tls_any else None
                    
                    # Fallback для quic если не найден
                    if not quic and bins:
                        quic = bins[0]
                    
                    logger.info(f"[fake_files] Selected: quic={quic.name if quic else None}, tls={tls.name if tls else None}, http={http.name if http else None}, syndata={syndata.name if syndata else None}")
                    
                    return quic, tls, http, syndata
        
        logger.warning("[fake_files] No fake files found in any path!")
        return None, None, None, None
    
    @profiler
    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Резолвинг домена во ВСЕ доступные IP адреса с кэшированием"""
        import socket
        import time
        
        now = time.time()
        # Инициализируем кэш, если его нет
        if not hasattr(self, '_dns_cache'):
            self._dns_cache = {}
            
        # Проверяем кэш (TTL 1 час - на время всего теста IP не должны меняться)
        if domain in self._dns_cache:
            cache_time, cached_ips = self._dns_cache[domain]
            if now - cache_time < 3600:
                return cached_ips

        ips =[]
        try:
            # Собираем IPv4
            result = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            for info in result:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass

        try:
            # Собираем IPv6
            result = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
            for info in result:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass

        if ips:
            self._dns_cache[domain] = (now, ips)

        return ips
    
    @profiler
    def _kill_winws(self) -> None:
        """
        Жёстко убить все процессы winws.exe

        Вызывается ПЕРЕД каждой новой стратегией чтобы гарантировать чистый старт.
        """
        # Сбрасываем ссылку на процесс (ВАЖНО! иначе NoneType.poll() ошибка)
        self._winws_process = None

        try:
            subprocess.run(
                ['taskkill', '/F', '/IM', 'winws.exe'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

    @profiler
    def build_cmd(self, strat: Dict[str, Any], domain: Optional[str] = None, is_quic: bool = False) -> List[str]:
        """
        Построение команды запуска winws из dict стратегии

        Структура команды соответствует smart_tuner.py и blockcheck.sh:
        1. WinDivert фильтры
        2. Файлы фейков (если есть)
        3. UDP профиль (для QUIC)
        4. TCP профиль (тестируемая стратегия)

        Args:
            strat: Dict стратегии
            domain: Домен для тестирования (опционально)
            is_quic: Если True - только QUIC/UDP профиль (без TCP)

        Returns:
            Список аргументов для subprocess
        """
        # Если передали объект с атрибутами - конвертируем в dict
        if not isinstance(strat, dict):
            strat = {k: v for k, v in vars(strat).items() if not k.startswith('_')}

        cmd = [str(WINWS_PATH)]

        # Режим стратегии
        mode = strat.get('mode', 'multisplit')
        
        # Определяем если это QUIC/UDP стратегия
        is_udp_strategy = 'ipfrag' in mode or 'hopbyhop' in mode or 'destopt' in mode

        # Базовые фильтры WinDivert
        # ПЕРЕХВАТ ВСЕГО ТРАФИКА (все порты)
        # ВАЖНО: Перехват ≠ модификация!
        # WinDivert перехватывает все пакеты, но DPI модификации применяются
        # ТОЛЬКО к IP/доменам из --hostlist файлов (или --ipset при тестировании).
        # Остальной трафик пропускается БЕЗ изменений.
        if is_quic or is_udp_strategy:
            # Все UDP для QUIC стратегий
            cmd.append("--wf-udp=*")
        else:
            # Все TCP для обычных стратегий
            cmd.append("--wf-tcp=*")

        # Файлы фейков (если найдены)
        fake_quic, fake_tls, fake_http, fake_syndata = self._find_fake_files()
        has_fake_files = fake_quic is not None and fake_tls is not None

        if fake_quic:
            cmd.append(f"--dpi-desync-fake-quic={fake_quic}")
        if fake_tls:
            cmd.append(f"--dpi-desync-fake-tls={fake_tls}")
        if fake_http:
            cmd.append(f"--dpi-desync-fake-http={fake_http}")
        if fake_syndata:
            cmd.append(f"--dpi-desync-fake-syndata={fake_syndata}")

        # UDP профиль (для QUIC) - как в blockcheck.sh
        cmd.append("--filter-udp=443")
        if is_udp_strategy or is_quic:
            # QUIC стратегия - применяем к UDP
            cmd.append(f"--dpi-desync={mode}")
            if strat.get("ipfrag_pos_udp"):
                cmd.append(f"--dpi-desync-ipfrag-pos-udp={strat['ipfrag_pos_udp']}")
            if strat.get("rep"):
                cmd.append(f"--dpi-desync-repeats={strat['rep']}")
            if strat.get("ttl"):
                cmd.append(f"--dpi-desync-ttl={strat['ttl']}")
            if strat.get("fool"):
                cmd.append(f"--dpi-desync-fooling={strat['fool']}")
        elif has_fake_files:
            cmd.append("--dpi-desync=fake")
            udp_repeats = strat.get("rep", 2) + 2
            cmd.append(f"--dpi-desync-repeats={udp_repeats}")
        else:
            cmd.append("--dpi-desync=multisplit")
            cmd.append("--dpi-desync-repeats=2")

        # TCP профиль - только если не QUIC
        if not is_quic and not is_udp_strategy:
            cmd.append("--new")
            cmd.append("--filter-tcp=443")

            # Основной параметр стратегии
            cmd.append(f"--dpi-desync={mode}")

        # Опциональные параметры
        if strat.get("pos"):
            cmd.append(f"--dpi-desync-split-pos={strat['pos']}")

        if strat.get("fool"):
            cmd.append(f"--dpi-desync-fooling={strat['fool']}")

        if strat.get("rep"):
            cmd.append(f"--dpi-desync-repeats={strat['rep']}")

        if strat.get("wssize"):
            cmd.append(f"--wssize={strat['wssize']}")

        if strat.get("ttl"):
            cmd.append(f"--dpi-desync-ttl={strat['ttl']}")

        if strat.get("autottl"):
            cmd.append(f"--dpi-desync-autottl={strat['autottl']}")

        if strat.get("seqovl"):
            cmd.append(f"--dpi-desync-split-seqovl={strat['seqovl']}")

        if strat.get("seqovl_pattern"):
            cmd.append(f"--dpi-desync-split-seqovl-pattern={strat['seqovl_pattern']}")

        if strat.get("fake_tls_mod"):
            cmd.append(f"--dpi-desync-fake-tls-mod={strat['fake_tls_mod']}")

        if strat.get("fake_tcp_mod"):
            cmd.append(f"--dpi-desync-fake-tcp-mod={strat['fake_tcp_mod']}")

        if strat.get("fakedsplit_mod"):
            cmd.append(f"--dpi-desync-fakedsplit-mod={strat['fakedsplit_mod']}")

        if strat.get("hostfakesplit_mod"):
            cmd.append(f"--dpi-desync-hostfakesplit-mod={strat['hostfakesplit_mod']}")

        if strat.get("hostfakesplit_midhost"):
            cmd.append(f"--dpi-desync-hostfakesplit-midhost={strat['hostfakesplit_midhost']}")

        # Orig параметры
        if strat.get("orig_ttl"):
            cmd.append(f"--orig-ttl={strat['orig_ttl']}")

        if strat.get("orig_mod_start"):
            cmd.append(f"--orig-mod-start={strat['orig_mod_start']}")

        if strat.get("orig_mod_cutoff"):
            cmd.append(f"--orig-mod-cutoff={strat['orig_mod_cutoff']}")

        if strat.get("orig_autottl"):
            cmd.append(f"--orig-autottl={strat['orig_autottl']}")

        # Dup параметры
        if strat.get("dup"):
            cmd.append(f"--dup={strat['dup']}")

        if strat.get("dup_cutoff"):
            cmd.append(f"--dup-cutoff={strat['dup_cutoff']}")

        if strat.get("dup_fooling"):
            cmd.append(f"--dup-fooling={strat['dup_fooling']}")

        if strat.get("dup_ttl"):
            cmd.append(f"--dup-ttl={strat['dup_ttl']}")

        if strat.get("dup_autottl"):
            cmd.append(f"--dup-autottl={strat['dup_autottl']}")

        # BadSeq
        if strat.get("badseq_increment") is not None:
            cmd.append(f"--dpi-desync-badseq-increment={strat['badseq_increment']}")

        # HTTP модификаторы
        if strat.get("hostcase"):
            cmd.append("--hostcase")

        if strat.get("hostspell"):
            cmd.append(f"--hostspell={strat['hostspell']}")

        if strat.get("hostnospace"):
            cmd.append("--hostnospace")

        if strat.get("domcase"):
            cmd.append("--domcase")

        if strat.get("methodeol"):
            cmd.append("--methodeol")

        if strat.get("extra"):
            cmd.extend(strat["extra"])

        # Если указан домен, резолвим ВСЕ IP и используем --ipset
        if domain:
            ips = self._resolve_domain_ips(domain)
            if ips:
                temp_ipset = BASE_DIR / "data" / "temp_test_ipset.txt"
                temp_ipset.parent.mkdir(parents=True, exist_ok=True)
                with open(temp_ipset, "w", encoding="utf-8") as f:
                    for ip in ips:
                        f.write(f"{ip}\n")
                cmd.append(f"--ipset={temp_ipset}")
                logger.debug(f"Resolved {domain} to {len(ips)} IPs, using --ipset")
            else:
                logger.warning(f"Could not resolve {domain}, falling back to --hostlist")
                temp_hostlist = BASE_DIR / "data" / "temp_test_hostlist.txt"
                temp_hostlist.parent.mkdir(parents=True, exist_ok=True)
                with open(temp_hostlist, "w", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
                cmd.append(f"--hostlist={temp_hostlist}")

        return cmd

    @profiler
    def _build_winws_cmd(self, strategy_params: str, domain: Optional[str] = None, is_quic: bool = False) -> List[str]:
        """
        Построение команды запуска winws с параметрами стратегии

        ВАЖНО: Используем --ipset вместо --hostlist (как в blockcheck.sh)
        WinDivert работает с IP адресами, не с доменами!

        Args:
            strategy_params: Параметры стратегии (например, "--dpi-desync=fake --dpi-desync-fooling=md5sig")
            domain: Домен для тестирования (опционально)
            is_quic: Если True - только QUIC/UDP профиль (без TCP)

        Returns:
            Список аргументов для subprocess
        """
        # Парсим строку параметров в dict
        strat = self._parse_strategy_params(strategy_params)
        return self.build_cmd(strat, domain, is_quic=is_quic)

    @profiler
    def _parse_strategy_params(self, strategy_params: str) -> Dict[str, Any]:
        """
        Парсинг строки параметров стратегии в dict

        Args:
            strategy_params: Строка параметров (например, "--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig")

        Returns:
            Dict с распарсенными параметрами
        """
        strat: Dict[str, Any] = {
            "mode": "multisplit",  # default
            "pos": None,
            "fool": None,
            "rep": 2,
            "wssize": None,
            "ttl": None,
            "autottl": None,
            "seqovl": None,
            "seqovl_pattern": None,
            "fake_tls_mod": None,
            "fake_tcp_mod": None,
            "fakedsplit_mod": None,
            "hostfakesplit_mod": None,
            "hostfakesplit_midhost": None,
            "orig_ttl": None,
            "orig_mod_start": None,
            "orig_mod_cutoff": None,
            "orig_autottl": None,
            "dup": None,
            "dup_cutoff": None,
            "dup_fooling": None,
            "dup_ttl": None,
            "dup_autottl": None,
            "badseq_increment": None,
            "ipfrag_pos_udp": None,
            "hostcase": False,
            "hostspell": None,
            "hostnospace": False,
            "domcase": False,
            "methodeol": False,
            "extra": []
        }

        if not strategy_params:
            return strat

        # Разбираем параметры
        parts = strategy_params.split()
        i = 0
        while i < len(parts):
            part = parts[i]

            if part.startswith("--dpi-desync="):
                strat["mode"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-split-pos="):
                strat["pos"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-fooling="):
                strat["fool"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-repeats="):
                try:
                    strat["rep"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--wssize="):
                strat["wssize"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-ttl="):
                try:
                    strat["ttl"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--dpi-desync-autottl="):
                strat["autottl"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-split-seqovl="):
                try:
                    strat["seqovl"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--dpi-desync-split-seqovl-pattern="):
                strat["seqovl_pattern"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-fake-tls-mod="):
                strat["fake_tls_mod"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-fake-tcp-mod="):
                strat["fake_tcp_mod"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-fakedsplit-mod="):
                strat["fakedsplit_mod"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-hostfakesplit-mod="):
                strat["hostfakesplit_mod"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-hostfakesplit-midhost="):
                strat["hostfakesplit_midhost"] = part.split("=", 1)[1]
            elif part.startswith("--orig-ttl="):
                try:
                    strat["orig_ttl"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--orig-mod-start="):
                strat["orig_mod_start"] = part.split("=", 1)[1]
            elif part.startswith("--orig-mod-cutoff="):
                strat["orig_mod_cutoff"] = part.split("=", 1)[1]
            elif part.startswith("--orig-autottl="):
                strat["orig_autottl"] = part.split("=", 1)[1]
            elif part.startswith("--dup="):
                try:
                    strat["dup"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--dup-cutoff="):
                strat["dup_cutoff"] = part.split("=", 1)[1]
            elif part.startswith("--dup-fooling="):
                strat["dup_fooling"] = part.split("=", 1)[1]
            elif part.startswith("--dup-ttl="):
                try:
                    strat["dup_ttl"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--dup-autottl="):
                strat["dup_autottl"] = part.split("=", 1)[1]
            elif part.startswith("--dpi-desync-badseq-increment="):
                try:
                    strat["badseq_increment"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part.startswith("--dpi-desync-ipfrag-pos-udp="):
                try:
                    strat["ipfrag_pos_udp"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part == "--hostcase":
                strat["hostcase"] = True
            elif part.startswith("--hostspell="):
                strat["hostspell"] = part.split("=", 1)[1]
            elif part == "--hostnospace":
                strat["hostnospace"] = True
            elif part == "--domcase":
                strat["domcase"] = True
            elif part == "--methodeol":
                strat["methodeol"] = True
            elif part.startswith("--"):
                # Остальные параметры добавляем как extra
                strat["extra"].append(part)

            i += 1

        return strat
    
    @profiler
    async def stop_winws(self) -> Tuple[bool, str]:
        """
        Остановка процесса winws

        Returns:
            (success, message)
        """
        async with self._process_lock:
            # Сначала останавливаем наш процесс если есть
            if self._winws_process is not None:
                try:
                    self._winws_process.terminate()
                    self._winws_process.wait(timeout=3)
                except Exception as e:
                    logger.warning(f"Failed to terminate winws: {e}, trying kill...")
                    try:
                        self._winws_process.kill()
                    except Exception:
                        pass
                self._winws_process = None

            # Убиваем все процессы winws через taskkill (Windows)
            if sys.platform == 'win32':
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/IM', 'winws.exe'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                except Exception:
                    pass

            # Даём время на завершение
            await asyncio.sleep(0.3)

            return True, "winws stopped"
    
    @profiler
    async def start_winws_with_strategy(
        self,
        strategy_params: str,
        domain: Optional[str] = None,
        measure_startup: bool = False,
        is_quic: bool = False
    ) -> Tuple[bool, str, float]:
        """
        Запуск winws с параметрами стратегии

        Args:
            strategy_params: Параметры стратегии
            domain: Домен для тестирования
            measure_startup: Измерять время запуска
            is_quic: Если True - запускать только UDP профиль (для QUIC стратегий)

        Returns:
            (success, message, startup_time)
        """
        logger.info(f"[executor] Starting winws with strategy: {strategy_params[:60]}...")
        
        async with self._process_lock:
            # УБИВАЕМ winws ПЕРЕД запуском новой стратегии (как в инструкции)
            self._kill_winws()

            # Даём время на завершение процессов
            await asyncio.sleep(0.3)

            # Строим команду
            cmd = self._build_winws_cmd(strategy_params, domain, is_quic=is_quic)

            start_time = time.time()

            try:
                # CREATE_NO_WINDOW = 0x08000000 для Windows
                creationflags = 0x08000000 if sys.platform == 'win32' else 0

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
                # Сохраняем в self._winws_process (после успешного создания!)
                self._winws_process = process
                logger.debug(f"[executor] winws started with pid={process.pid}")
                
            except FileNotFoundError:
                logger.error(f"[executor] winws.exe not found at {WINWS_PATH}")
                return False, f"winws.exe not found at {WINWS_PATH}", 0.0
            except Exception as e:
                logger.error(f"[executor] Failed to start winws: {e}")
                return False, f"Failed to start winws: {e}", 0.0

            startup_time = time.time() - start_time
            logger.debug(f"[executor] winws startup time: {startup_time*1000:.1f}ms")

            # Ждём INIT_WAIT (4.0 сек) как в инструкции
            # Это критически важно для инициализации WinDivert фильтра
            logger.debug(f"[executor] Waiting {INIT_WAIT}s for WinDivert initialization...")
            await asyncio.sleep(INIT_WAIT)

            # Если нужно измерить время запуска, проверяем что процесс жив (локальная переменная!)
            if measure_startup:
                poll = process.poll()
                if poll is not None:
                    # Процесс упал
                    logger.warning(f"[executor] winws crashed with code {poll}")
                    stderr = ""
                    try:
                        _, stderr_bytes = process.communicate(timeout=1)
                        stderr = stderr_bytes.decode('utf-8', errors='replace').strip()
                    except Exception:
                        pass
                    self._winws_process = None
                    return False, f"winws crashed (code {poll}): {stderr[:100]}", startup_time

                # Кэшируем измеренное время если ещё нет
                if self._startup_time is None:
                    self._startup_time = startup_time
                    logger.info(f"[executor] Measured winws startup time: {startup_time*1000:.0f}ms")

            logger.info(f"[executor] winws started successfully")
            return True, f"winws started", startup_time
    
    @profiler
    def get_startup_wait_time(self) -> float:
        """
        Получить время ожидания после запуска winws
        
        ВАЖНО: Минимум 1 секунда, так как WinDivert требует время на инициализацию.
        В smart_tuner.py используется 4 секунды в INIT_WAIT.
        
        Returns:
            Время в секундах (minimum 1.0s)
        """
        MIN_WAIT = 1.0  # 1 секунда minimum (было 100ms - слишком мало!)
        
        if self._startup_time is not None:
            return max(MIN_WAIT, self._startup_time * 1.1)
        
        # Если время ещё не измерено, используем дефолт
        return 1.0  # 1 секунда default (было 150ms)
    
    @profiler
    async def is_winws_running(self) -> bool:
        """Проверка что winws процесс запущен и жив"""
        process = self._winws_process  # ← локальная копия ссылки
        if process is None:
            return False

        poll = process.poll()  # ← process не может стать None
        return poll is None  # None = процесс ещё работает
    
    @profiler
    async def get_winws_output(self, timeout: float = 0.5) -> Tuple[str, str]:
        """
        Получение вывода от winws процесса (если есть)

        Returns:
            (stdout, stderr)
        """
        if self._winws_process is None:
            return "", "No winws process"

        try:
            # Неблокирующее чтение
            import select
            stdout = ""
            stderr = ""

            # Проверяем есть ли данные для чтения
            if self._winws_process.stdout:
                readable, _, _ = select.select([self._winws_process.stdout], [], [], timeout)
                if readable:
                    stdout = self._winws_process.stdout.read(4096).decode('utf-8', errors='replace')

            if self._winws_process.stderr:
                readable, _, _ = select.select([self._winws_process.stderr], [], [], timeout)
                if readable:
                    stderr = self._winws_process.stderr.read(4096).decode('utf-8', errors='replace')

            return stdout, stderr
        except Exception:
            return "", ""

    @profiler
    async def restart_winws_full(self, nfqws_generator) -> Tuple[bool, str]:
        """Полный рестарт winws со ВСЕМИ стратегиями (как в батнике)"""

        # ЗАЩИТА ОТ ОДНОВРЕМЕННОГО РЕСТАРТА СРАЗУ НЕСКОЛЬКИМИ ДОМЕНАМИ
        async with self._full_restart_lock:
            logger.info("[executor] Полный рестарт winws со всеми профилями...")

            await self.stop_winws()  # убиваем всё

            # Получаем полный список аргументов из генератора
            full_args = nfqws_generator.generate_nfqs_args()

            # ЕСЛИ профилей нет — добавляем базовую стратегию
            if len(nfqws_generator._profiles) == 0:
                logger.warning("[executor] Нет профилей! Добавляю базовую стратегию...")
                # Базовая стратегия: fake + multisplit + md5sig (универсальная)
                full_args.extend([
                    "--new",
                    "--filter-tcp=443",
                    "--dpi-desync=fake,multisplit",
                    "--dpi-desync-fooling=md5sig",
                    "--dpi-desync-split-pos=method+2"
                ])

            cmd = [str(WINWS_PATH)] + full_args

            try:
                creationflags = 0x08000000 if sys.platform == 'win32' else 0

                # Защита самого процесса запуска
                async with self._process_lock:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                    )
                    # Сохраняем в self._winws_process (после успешного создания!)
                    self._winws_process = process

                    # Ждём инициализации WinDivert
                    await asyncio.sleep(INIT_WAIT)

                    # ПРОВЕРЯЕМ что процесс жив (используем локальную переменную!)
                    poll = process.poll()
                    if poll is not None:
                        # Процесс упал!
                        logger.error(f"[executor] winws crashed immediately with code {poll}")
                        self._winws_process = None
                        return False, f"winws crashed with code {poll}"

                logger.info(f"[executor] winws перезапущен с {len(full_args)} аргументами (все стратегии)")
                return True, "winws restarted with full config"
            except FileNotFoundError:
                logger.error(f"[executor] winws.exe not found at {WINWS_PATH}")
                return False, f"winws.exe not found at {WINWS_PATH}"
            except Exception as e:
                logger.error(f"[executor] Full restart failed: {e}", exc_info=True)
                return False, str(e)