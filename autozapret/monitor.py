"""
Monitor - модуль мониторинга логов nfqws
Парсинг событий autohostlist
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import AsyncGenerator, Callable, Dict, List, Optional, Pattern
import logging
import os

import aiofiles

from .config import Config, get_config
from .utils.profiler import get_profiler
profiler = get_profiler("monitor")

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Типы событий autohostlist"""
    FAIL_COUNTER = "fail_counter"      # Увеличение счётчика неудач
    DOMAIN_ADDED = "domain_added"       # Домен добавлен в список
    DOMAIN_NOT_ADDED = "domain_not_added"  # Домен не добавлен (дубликат)
    FAIL_RESET = "fail_reset"           # Сброс счётчика неудач
    UNKNOWN = "unknown"                 # Неизвестное событие
    # IP события (для приложений без SNI)
    IP_FAIL_COUNTER = "ip_fail_counter"      # IP fail counter
    IP_DOMAIN_ADDED = "ip_domain_added"      # IP добавлен в список
    IP_FAIL_RESET = "ip_fail_reset"          # IP fail reset


@dataclass
class AutoHostlistEvent:
    """Событие autohostlist"""
    event_type: EventType
    domain: str
    profile_id: int
    client: str  # IP:port клиента
    protocol: str  # HTTP, TLS, QUIC
    fail_counter: int = 0
    fail_threshold: int = 0
    strategy_file: str = ""
    timestamp: datetime = None
    
    @profiler
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    @profiler
    def __str__(self) -> str:
        base = f"[{self.event_type.value}] {self.domain} (profile {self.profile_id})"
        if self.event_type == EventType.FAIL_COUNTER:
            base += f" counter={self.fail_counter}/{self.fail_threshold}"
        elif self.event_type == EventType.DOMAIN_ADDED:
            base += f" added to {self.strategy_file}"
        return base


class LogParser:
    """Парсер логов autohostlist"""

    # Паттерн для парсинга строк лога
    # Пример: example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : fail counter 2/3
    # Также: 21.03.2026 01:18:18 : www.youtube.com : profile 1 : client ...
    FAIL_COUNTER_PATTERN: Pattern = re.compile(
        r'^(?:(?P<ts>[\d\.]+\s+[\d\:]+)\s*:\s*)?'  # Опциональный timestamp
        r'(?P<domain>[\w\.\-\*]+)\s*:\s*profile\s+(?P<profile>\d+)\s*:'
        r'\s*client\s+(?P<client>[\w\.\:]+)\s*:\s*proto\s+(?P<proto>\w+)\s*:'
        r'\s*fail counter\s+(?P<counter>\d+)/(?P<threshold>\d+)',
        re.IGNORECASE
    )

    # Пример: example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : adding to /path/to/file.txt
    DOMAIN_ADDED_PATTERN: Pattern = re.compile(
        r'^(?:(?P<ts>[\d\.]+\s+[\d\:]+)\s*:\s*)?'  # Опциональный таймстемп
        r'(?P<domain>[\w\.\-\*]+)\s*:\s*profile\s+(?P<profile>\d+)\s*:'
        r'\s*client\s+(?P<client>[\w\.\:]+)\s*:\s*proto\s+(?P<proto>\w+)\s*:'
        r'\s*adding to\s+(?P<file>[\w\/\.\-\\]+)',
        re.IGNORECASE
    )

    # Пример: example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : NOT adding, duplicate detected
    DOMAIN_NOT_ADDED_PATTERN: Pattern = re.compile(
        r'^(?:(?P<ts>[\d\.]+\s+[\d\:]+)\s*:\s*)?'  # Опциональный таймстемп
        r'(?P<domain>[\w\.\-\*]+)\s*:\s*profile\s+(?P<profile>\d+)\s*:'
        r'\s*client\s+(?P<client>[\w\.\:]+)\s*:\s*proto\s+(?P<proto>\w+)\s*:'
        r'\s*NOT adding',
        re.IGNORECASE
    )

    # Пример: example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : fail counter reset
    FAIL_RESET_PATTERN: Pattern = re.compile(
        r'^(?:(?P<ts>[\d\.]+\s+[\d\:]+)\s*:\s*)?'  # Опциональный таймстемп
        r'(?P<domain>[\w\.\-\*]+)\s*:\s*profile\s+(?P<profile>\d+)\s*:'
        r'\s*client\s+(?P<client>[\w\.\:]+)\s*:\s*proto\s+(?P<proto>\w+)\s*:'
        r'\s*fail counter reset',
        re.IGNORECASE
    )

    @profiler
    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Парсинг timestamp из строки"""
        if not ts_str:
            return None
        try:
            # Формат: "21.03.2026 01:18:18"
            return datetime.strptime(ts_str.strip(), "%d.%m.%Y %H:%M:%S")
        except ValueError:
            logger.warning(f"Failed to parse timestamp: {ts_str}")
            return None
    
    @profiler
    def parse_line(self, line: str) -> Optional[AutoHostlistEvent]:
        """
        Парсинг одной строки лога
        
        Args:
            line: Строка лога
            
        Returns:
            AutoHostlistEvent или None если строка не распознана
        """
        line = line.strip()
        if not line:
            return None
        
        # Пробуем разные паттерны
        event = self._try_parse_fail_counter(line)
        if event:
            return event
        
        event = self._try_parse_domain_added(line)
        if event:
            return event
        
        event = self._try_parse_domain_not_added(line)
        if event:
            return event
        
        event = self._try_parse_fail_reset(line)
        if event:
            return event
        
        logger.debug(f"Unrecognized log line: {line}")
        return None
    
    @profiler
    def _try_parse_fail_counter(self, line: str) -> Optional[AutoHostlistEvent]:
        """Парсинг события fail counter"""
        match = self.FAIL_COUNTER_PATTERN.match(line)
        if not match:
            return None

        return AutoHostlistEvent(
            event_type=EventType.FAIL_COUNTER,
            domain=match.group("domain"),
            profile_id=int(match.group("profile")),
            client=match.group("client"),
            protocol=match.group("proto"),
            fail_counter=int(match.group("counter")),
            fail_threshold=int(match.group("threshold")),
            timestamp=self._parse_timestamp(match.group("ts"))
        )

    @profiler
    def _try_parse_domain_added(self, line: str) -> Optional[AutoHostlistEvent]:
        """Парсинг события domain added"""
        match = self.DOMAIN_ADDED_PATTERN.match(line)
        if not match:
            return None

        return AutoHostlistEvent(
            event_type=EventType.DOMAIN_ADDED,
            domain=match.group("domain"),
            profile_id=int(match.group("profile")),
            client=match.group("client"),
            protocol=match.group("proto"),
            strategy_file=match.group("file"),
            timestamp=self._parse_timestamp(match.group("ts"))
        )

    @profiler
    def _try_parse_domain_not_added(self, line: str) -> Optional[AutoHostlistEvent]:
        """Парсинг события domain not added"""
        match = self.DOMAIN_NOT_ADDED_PATTERN.match(line)
        if not match:
            return None

        return AutoHostlistEvent(
            event_type=EventType.DOMAIN_NOT_ADDED,
            domain=match.group("domain"),
            profile_id=int(match.group("profile")),
            client=match.group("client"),
            protocol=match.group("proto"),
            timestamp=self._parse_timestamp(match.group("ts"))
        )

    @profiler
    def _try_parse_fail_reset(self, line: str) -> Optional[AutoHostlistEvent]:
        """Парсинг события fail reset"""
        match = self.FAIL_RESET_PATTERN.match(line)
        if not match:
            return None

        return AutoHostlistEvent(
            event_type=EventType.FAIL_RESET,
            domain=match.group("domain"),
            profile_id=int(match.group("profile")),
            client=match.group("client"),
            protocol=match.group("proto"),
            timestamp=self._parse_timestamp(match.group("ts"))
        )


class Monitor:
    """Мониторинг логов nfqws"""

    @profiler
    def __init__(self, config: Optional[Config] = None, replay_existing_logs: bool = False):
        self.config = config or get_config()
        self.parser = LogParser()
        self._running = False
        self._callbacks: List[Callable[[AutoHostlistEvent], None]] = []
        self._position = 0  # Позиция в файле для tail
        self._replay_existing_logs = replay_existing_logs  # Читать ли историю при старте
        
        # Для detect log rotation
        self._last_inode: Optional[int] = None
        self._last_size: int = 0

    @profiler
    def register_callback(self, callback: Callable[[AutoHostlistEvent], None]) -> None:
        """Регистрация callback для событий"""
        self._callbacks.append(callback)

    @profiler
    def unregister_callback(self, callback: Callable[[AutoHostlistEvent], None]) -> None:
        """Отписка callback"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    @profiler
    async def start(self) -> None:
        """
        Запуск мониторинга логов

        Args:
            replay_existing_logs: Читать ли историю при старте (по умолчанию False)
        """
        logger.info("Starting Monitor...")
        self._running = True

        try:
            # Опционально читаем существующие логи
            if self._replay_existing_logs:
                logger.info("Reading all existing log file...")
                events = await self.read_log_file()
                logger.info(f"Read {len(events)} historical events")

                # Отправляем ВСЕ исторические события
                for event in events:
                    await self._notify_callbacks(event)
            else:
                logger.info("Starting from end of log file (no replay)")

            # Запускаем tail (мониторинг новых событий)
            logger.info(f"Starting tail monitoring on {self.config.nfqws_log_file}")
            await self._run_tail_monitoring()

        except Exception as e:
            logger.error(f"Monitor error: {e}")
        finally:
            self._running = False
            logger.info("Monitor stopped")

    @profiler
    async def _run_tail_monitoring(self) -> None:
        """Запуск tail мониторинга (только новые события) с detect log rotation"""
        log_file = self.config.nfqws_log_file

        # Создаём файл если не существует
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else '.', exist_ok=True)
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                pass

        # Инициализируем inode и size
        try:
            stat_info = os.stat(log_file)
            self._last_inode = stat_info.st_ino
            self._last_size = stat_info.st_size
        except OSError:
            self._last_inode = None
            self._last_size = 0

        # Начинаем с КОНЦА файла (только новые события)
        self._position = self._last_size
        logger.info(f"Starting tail from position {self._position} (end of file, inode={self._last_inode})")

        while self._running:
            try:
                # Проверяем не произошла ли log rotation
                try:
                    stat_info = os.stat(log_file)
                    current_inode = stat_info.st_ino
                    current_size = stat_info.st_size
                    
                    # Если inode изменился - файл был ротирован
                    if self._last_inode is not None and current_inode != self._last_inode:
                        logger.info(f"Log rotation detected (inode changed from {self._last_inode} to {current_inode})")
                        self._last_inode = current_inode
                        self._position = 0  # Начинаем с начала нового файла
                    # Если размер уменьшился - файл был усечён
                    elif current_size < self._position:
                        logger.info(f"Log truncation detected (size {current_size} < position {self._position})")
                        self._position = 0
                    
                    self._last_size = current_size
                except OSError:
                    pass  # Файл недоступен, продолжаем
                
                async with aiofiles.open(log_file, 'r', encoding='utf-8') as f:
                    # Перемещаемся на последнюю известную позицию
                    await f.seek(self._position)

                    while self._running:
                        line = await f.readline()
                        if line:
                            self._position = await f.tell()
                            event = self.parser.parse_line(line)
                            if event:
                                logger.debug(f"Parsed event: {event}")
                                await self._notify_callbacks(event)
                        else:
                            # Нет новых строк - проверяем rotation перед ожиданием
                            try:
                                stat_info = os.stat(log_file)
                                current_inode = stat_info.st_ino
                                current_size = stat_info.st_size

                                # Если inode изменился - файл был ротирован
                                if self._last_inode is not None and current_inode != self._last_inode:
                                    logger.info(f"Log rotation detected during wait (inode changed)")
                                    break  # Выходим из внутреннего цикла на reopen
                                # Если размер уменьшился - файл был усечён
                                if current_size < self._position:
                                    logger.info(f"Log truncation detected during wait")
                                    self._position = 0
                                    await f.seek(0)
                            except OSError:
                                pass

                            # Нет новых строк, ждём
                            await asyncio.sleep(0.5)

            except FileNotFoundError:
                logger.warning(f"Log file {log_file} not found, waiting...")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Error reading log file: {e}")
                await asyncio.sleep(5)

    @profiler
    def stop(self) -> None:
        """Остановка мониторинга"""
        logger.info("Stopping Monitor...")
        self._running = False

    @profiler
    async def _notify_callbacks(self, event: AutoHostlistEvent) -> None:
        """Уведомление всех callback"""
        import inspect

        for callback in self._callbacks:
            try:
                if inspect.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    @profiler
    async def read_log_file(self) -> List[AutoHostlistEvent]:
        """
        Прочитать весь лог файл
        
        Returns:
            Список событий
        """
        log_file = self.config.nfqws_log_file
        events = []
        
        if not os.path.exists(log_file):
            return events
        
        try:
            async with aiofiles.open(log_file, 'r', encoding='utf-8') as f:
                content = await f.read()
                for line in content.splitlines():
                    event = self.parser.parse_line(line)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
        
        return events


class LogSimulator:
    """Симулятор логов для тестирования"""
    
    @profiler
    def __init__(self, log_file: str):
        self.log_file = log_file
        self._lock = asyncio.Lock()
    
    @profiler
    async def write_event(self, event: AutoHostlistEvent) -> None:
        """Запись события в лог"""
        async with self._lock:
            async with aiofiles.open(self.log_file, 'a', encoding='utf-8') as f:
                line = self._format_event(event)
                await f.write(line + "\n")
                await f.flush()
    
    @profiler
    def _format_event(self, event: AutoHostlistEvent) -> str:
        """Форматирование события в строку лога"""
        if event.event_type == EventType.FAIL_COUNTER:
            return (f"{event.domain} : profile {event.profile_id} : "
                    f"client {event.client} : proto {event.protocol} : "
                    f"fail counter {event.fail_counter}/{event.fail_threshold}")
        elif event.event_type == EventType.DOMAIN_ADDED:
            return (f"{event.domain} : profile {event.profile_id} : "
                    f"client {event.client} : proto {event.protocol} : "
                    f"adding to {event.strategy_file}")
        elif event.event_type == EventType.DOMAIN_NOT_ADDED:
            return (f"{event.domain} : profile {event.profile_id} : "
                    f"client {event.client} : proto {event.protocol} : "
                    f"NOT adding, duplicate detected")
        elif event.event_type == EventType.FAIL_RESET:
            return (f"{event.domain} : profile {event.profile_id} : "
                    f"client {event.client} : proto {event.protocol} : "
                    f"fail counter reset")
        return ""
    
    @profiler
    async def clear(self) -> None:
        """Очистка лога"""
        async with self._lock:
            async with aiofiles.open(self.log_file, 'w', encoding='utf-8') as f:
                await f.write("")
