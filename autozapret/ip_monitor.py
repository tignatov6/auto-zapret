"""
IP Monitor - модуль мониторинга IP-соединений для приложений без SNI

Обнаруживает проблемы с соединениями (retransmissions, timeouts) для
приложений типа Discord которые не используют SNI/HTTP Host header.
"""

import asyncio
import ctypes
import ctypes.wintypes
import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .config import Config, get_config
from .helpers import is_ip_address, normalize_domain
from .utils.profiler import get_profiler

profiler = get_profiler("ip_monitor")

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════
# Windows TCP API константы
# ═══════════════════════════════════════════════════════

# TCP states
MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_SYN_SENT = 2
MIB_TCP_STATE_TIME_WAIT = 11
MIB_TCP_STATE_CLOSE_WAIT = 8
MIB_TCP_STATE_LAST_ACK = 9

# TCP table classes
TCP_TABLE_OWNER_PID_CONNECTIONS = 4

# ═══════════════════════════════════════════════════════
# Windows API структуры
# ═══════════════════════════════════════════════════════


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    """TCP connection entry with owner PID"""
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    """TCP table with owner PIDs"""
    _fields_ = [
        ("dwNumEntries", ctypes.wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


# ═══════════════════════════════════════════════════════
# Типы событий
# ═══════════════════════════════════════════════════════


class IPEventType(Enum):
    """Типы IP событий"""
    FAIL_COUNTER = "ip_fail_counter"      # Увеличение счётчика неудач
    DOMAIN_ADDED = "ip_domain_added"      # IP добавлен в список
    FAIL_RESET = "ip_fail_reset"          # Сброс счётчика неудач


@dataclass
class IPEvent:
    """IP событие (аналог AutoHostlistEvent)"""
    event_type: IPEventType
    ip: str  # IP адрес
    port: int  # Порт
    protocol: str  # "tcp" или "udp"
    app: str  # Имя приложения (discord, etc)
    fail_counter: int = 0
    fail_threshold: int = 0
    pid: Optional[int] = None  # PID процесса
    timestamp: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════
# Windows API обёртки
# ═══════════════════════════════════════════════════════

@profiler
def get_tcp_connections() -> List[Dict[str, Any]]:
    """
    Получить все активные TCP соединения через GetExtendedTcpTable
    
    Returns:
        Список dict с информацией о соединениях
    """
    if os.name != 'nt':
        return []
    
    try:
        # Первый вызов для определения размера буфера
        tcp_lib = ctypes.windll.iphlpapi
        size = ctypes.wintypes.ULONG(0)
        
        # Получаем необходимый размер
        result = tcp_lib.GetExtendedTcpTable(
            None,
            ctypes.byref(size),
            False,
            socket.AF_INET,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0
        )
        
        # Выделяем буфер
        buffer = ctypes.create_string_buffer(size.value)
        
        # Второй вызов для получения данных
        result = tcp_lib.GetExtendedTcpTable(
            buffer,
            ctypes.byref(size),
            False,
            socket.AF_INET,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0
        )
        
        if result != 0:
            logger.error(f"GetExtendedTcpTable failed with error {result}")
            return []
        
        # Парсим данные
        table = ctypes.cast(buffer, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
        connections = []
        
        for i in range(table.dwNumEntries):
            row = table.table[i]
            
            # Конвертируем IP и порт
            local_ip = socket.inet_ntoa(struct.pack('<I', row.dwLocalAddr))
            remote_ip = socket.inet_ntoa(struct.pack('<I', row.dwRemoteAddr))
            local_port = socket.ntohs(row.dwLocalPort)
            remote_port = socket.ntohs(row.dwRemotePort)
            
            connections.append({
                'state': row.dwState,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'pid': row.dwOwningPid,
            })
        
        return connections
        
    except Exception as e:
        logger.error(f"Failed to get TCP connections: {e}")
        return []


@profiler
def get_tcp_statistics() -> Dict[str, int]:
    """
    Получить TCP статистику через GetTcpStatistics
    
    Returns:
        Dict с dwRetransSegs, dwAttemptFails, и т.д.
    """
    if os.name != 'nt':
        return {}
    
    try:
        # MIB_TCPSTATS структура
        class MIB_TCPSTATS(ctypes.Structure):
            _fields_ = [
                ("dwRtoAlgorithm", ctypes.wintypes.DWORD),
                ("dwRtoMin", ctypes.wintypes.DWORD),
                ("dwRtoMax", ctypes.wintypes.DWORD),
                ("dwMaxConn", ctypes.wintypes.DWORD),
                ("dwActiveOpens", ctypes.wintypes.DWORD),
                ("dwPassiveOpens", ctypes.wintypes.DWORD),
                ("dwAttemptFails", ctypes.wintypes.DWORD),
                ("dwEstabResets", ctypes.wintypes.DWORD),
                ("dwCurrEstab", ctypes.wintypes.DWORD),
                ("dwInSegs", ctypes.wintypes.DWORD),
                ("dwOutSegs", ctypes.wintypes.DWORD),
                ("dwRetransSegs", ctypes.wintypes.DWORD),
                ("dwInErrs", ctypes.wintypes.DWORD),
                ("dwOutRsts", ctypes.wintypes.DWORD),
                ("dwNumConns", ctypes.wintypes.DWORD),
            ]
        
        stats = MIB_TCPSTATS()
        tcp_lib = ctypes.windll.iphlpapi
        
        result = tcp_lib.GetTcpStatistics(ctypes.byref(stats))
        if result != 0:
            logger.error(f"GetTcpStatistics failed with error {result}")
            return {}
        
        return {
            'retrans_segs': stats.dwRetransSegs,
            'attempt_fails': stats.dwAttemptFails,
            'active_opens': stats.dwActiveOpens,
            'curr_estab': stats.dwCurrEstab,
        }
        
    except Exception as e:
        logger.error(f"Failed to get TCP statistics: {e}")
        return {}


# ═══════════════════════════════════════════════════════
# IP Monitor
# ═══════════════════════════════════════════════════════


@dataclass
class IPFailCounter:
    """Счётчик неудач для IP"""
    ip: str
    port: int
    protocol: str
    app: str
    counter: int = 0
    last_fail_time: float = 0
    first_fail_time: Optional[float] = None


class IPMonitor:
    """
    Мониторинг IP-соединений для приложений без SNI
    
    Обнаруживает проблемы:
    1. SYN_SENT соединения (DPI блокирует handshake)
    2. TCP retransmissions (признак DPI interference)
    3. Connection failures
    
    При обнаружении проблем посылает IPEvent в callbacks.
    """
    
    @profiler
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._running = False
        self._callbacks: List[Callable[[IPEvent], None]] = []
        
        # Счётчики неудач по IP
        self._fail_counters: Dict[str, IPFailCounter] = {}
        
        # Предыдущая TCP статистика (для вычисления дельты)
        self._prev_tcp_stats: Dict[str, int] = {}
        
        # Отслеживаемые IP (для оптимизации)
        self._watched_ips: Set[str] = set()
        
        # Кэш reverse DNS
        self._dns_cache: Dict[str, str] = {}
        
        logger.info(f"IPMonitor initialized (enabled={self.config.ip_monitor_enabled})")
        logger.info(f"Watching {len(self.config.ip_targets)} IP targets")
    
    @profiler
    def register_callback(self, callback: Callable[[IPEvent], None]) -> None:
        """Регистрация callback для событий"""
        self._callbacks.append(callback)
        logger.debug(f"Registered IP event callback")
    
    @profiler
    async def start(self) -> None:
        """Запуск IP мониторинга"""
        if not self.config.ip_monitor_enabled:
            logger.info("IP Monitor disabled (ip_monitor_enabled=False)")
            return
        
        logger.info("Starting IP Monitor...")
        self._running = True
        
        # Инициализируем watched IPs
        self._update_watched_ips()
        
        # Инициализируем TCP статистику
        self._prev_tcp_stats = get_tcp_statistics()
        
        try:
            await self._run_monitoring()
        except Exception as e:
            logger.error(f"IP Monitor error: {e}")
        finally:
            self._running = False
            logger.info("IP Monitor stopped")
    
    @profiler
    def stop(self) -> None:
        """Остановка IP мониторинга"""
        logger.info("Stopping IP Monitor...")
        self._running = False
    
    @profiler
    async def _run_monitoring(self) -> None:
        """Основной цикл мониторинга"""
        logger.info("IP Monitor loop started")
        
        while self._running:
            try:
                # 1. Проверяем активные TCP соединения
                await self._check_active_connections()
                
                # 2. Проверяем TCP статистику (retransmissions)
                await self._check_tcp_statistics()
                
                # 3. Обновляем watched IPs (targets могли измениться)
                self._update_watched_ips()
                
                # Ждём следующий цикл
                await asyncio.sleep(self.config.ip_monitor_interval)
                
            except asyncio.CancelledError:
                logger.info("IP Monitor loop cancelled")
                break
            except Exception as e:
                logger.error(f"IP Monitor loop error: {e}")
                await asyncio.sleep(5)
    
    @profiler
    async def _check_active_connections(self) -> None:
        """Проверка активных TCP соединений на проблемы"""
        connections = get_tcp_connections()
        if not connections:
            return
        
        # Группируем соединения по remote IP:port
        ip_connections: Dict[str, List[Dict]] = {}
        for conn in connections:
            if conn['state'] == MIB_TCP_STATE_ESTAB or conn['state'] == MIB_TCP_STATE_SYN_SENT:
                key = f"{conn['remote_ip']}:{conn['remote_port']}"
                if key not in ip_connections:
                    ip_connections[key] = []
                ip_connections[key].append(conn)
        
        # Проверяем только watched IPs
        for ip_port_str, conns in ip_connections.items():
            ip, port = ip_port_str.rsplit(':', 1)
            port = int(port)
            
            # Проверяем входит ли IP в watched
            if not self._is_ip_watched(ip, port):
                continue
            
            # Ищем приложения для этого IP
            apps = self._get_apps_for_ip(ip, port)
            if not apps:
                continue
            
            for app in apps:
                # Проверяем SYN_SENT (DPI блокирует)
                syn_sent_count = sum(1 for c in conns if c['state'] == MIB_TCP_STATE_SYN_SENT)
                if syn_sent_count > 0:
                    logger.debug(f"IP {ip}:{port} ({app}) has {syn_sent_count} SYN_SENT connections")
                    await self._record_fail(ip, port, 'tcp', app, syn_sent_count)
    
    @profiler
    async def _check_tcp_statistics(self) -> None:
        """Проверка TCP статистики на retransmissions"""
        stats = get_tcp_statistics()
        if not stats:
            return
        
        # Вычисляем дельту retransmissions
        prev_retrans = self._prev_tcp_stats.get('retrans_segs', 0)
        curr_retrans = stats.get('retrans_segs', 0)
        
        delta_retrans = curr_retrans - prev_retrans
        
        # Сохраняем текущую статистику
        self._prev_tcp_stats = stats
        
        # Если слишком много retransmissions за интервал
        if delta_retrans >= self.config.ip_monitor_retrans_threshold:
            logger.warning(f"High retransmissions detected: {delta_retrans} in {self.config.ip_monitor_interval}s")
            
            # Записываем fail для всех watched IPs
            for target in self.config.ip_targets:
                ip = target['ip']
                port = target['port']
                proto = target['proto']
                app = target['app']
                
                if isinstance(port, str) and '-' in str(port):
                    # Range портов - пропускаем для статистики
                    continue
                
                await self._record_fail(ip, int(port), proto, app, delta_retrans)
    
    @profiler
    async def _record_fail(self, ip: str, port: int, protocol: str, app: str, count: int) -> None:
        """Записать неудачу для IP"""
        key = f"{ip}:{port}:{protocol}:{app}"
        
        now = time.time()
        
        if key not in self._fail_counters:
            self._fail_counters[key] = IPFailCounter(
                ip=ip,
                port=port,
                protocol=protocol,
                app=app,
            )
        
        counter = self._fail_counters[key]
        
        # Проверяем cooldown (если прошло много времени - сбрасываем)
        if counter.last_fail_time > 0 and (now - counter.last_fail_time) > 60:
            counter.counter = 0
            counter.first_fail_time = None
        
        counter.counter += count
        counter.last_fail_time = now
        
        if counter.first_fail_time is None:
            counter.first_fail_time = now
        
        logger.debug(f"IP {ip}:{port} ({app}) fail counter: {counter.counter}")
        
        # Проверяем порог
        if counter.counter >= self.config.ip_monitor_fail_threshold:
            logger.info(f"IP {ip}:{port} ({app}) reached fail threshold: {counter.counter}")
            
            # Посылаем событие
            event = IPEvent(
                event_type=IPEventType.FAIL_COUNTER,
                ip=ip,
                port=port,
                protocol=protocol.upper(),
                app=app,
                fail_counter=counter.counter,
                fail_threshold=self.config.ip_monitor_fail_threshold,
            )
            
            await self._notify_callbacks(event)
            
            # Сбрасываем счётчик после триггера
            counter.counter = 0
            counter.first_fail_time = None
    
    @profiler
    async def _notify_callbacks(self, event: IPEvent) -> None:
        """Уведомление всех callback"""
        import inspect
        
        for callback in self._callbacks:
            try:
                if inspect.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"IP event callback error: {e}")
    
    @profiler
    def _update_watched_ips(self) -> None:
        """Обновить список watched IPs из config"""
        self._watched_ips.clear()
        
        for target in self.config.ip_targets:
            ip = target['ip']
            port = target['port']
            
            # Проверяем CIDR
            if '/' in ip:
                try:
                    network = ipaddress.IPv4Network(ip, strict=False)
                    for addr in network.hosts():
                        self._watched_ips.add(f"{str(addr)}:{port}")
                except ValueError:
                    logger.warning(f"Invalid CIDR in ip_targets: {ip}")
            else:
                self._watched_ips.add(f"{ip}:{port}")
        
        logger.debug(f"Updated watched IPs: {len(self._watched_ips)} entries")
    
    @profiler
    def _is_ip_watched(self, ip: str, port: int) -> bool:
        """Проверить входит ли IP в watched"""
        key = f"{ip}:{port}"
        return key in self._watched_ips
    
    @profiler
    def _get_apps_for_ip(self, ip: str, port: int) -> List[str]:
        """Получить список приложений для IP"""
        apps = []
        
        for target in self.config.ip_targets:
            target_ip = target['ip']
            target_port = target['port']
            app = target['app']
            
            # Проверяем CIDR
            if '/' in target_ip:
                try:
                    network = ipaddress.IPv4Network(target_ip, strict=False)
                    if ipaddress.IPv4Address(ip) in network:
                        # Проверяем порт
                        if isinstance(target_port, int) and port == target_port:
                            apps.append(app)
                        elif isinstance(target_port, str) and '-' in target_port:
                            start, end = map(int, target_port.split('-'))
                            if start <= port <= end:
                                apps.append(app)
                except ValueError:
                    pass
            else:
                if ip == target_ip:
                    if isinstance(target_port, int) and port == target_port:
                        apps.append(app)
                    elif isinstance(target_port, str) and '-' in target_port:
                        start, end = map(int, target_port.split('-'))
                        if start <= port <= end:
                            apps.append(app)
        
        return apps
    
    @profiler
    def reverse_dns(self, ip: str) -> Optional[str]:
        """
        Reverse DNS lookup для IP → домен
        
        Args:
            ip: IP адрес
            
        Returns:
            Доменное имя или None
        """
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._dns_cache[ip] = hostname
            logger.debug(f"Reverse DNS for {ip}: {hostname}")
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            logger.debug(f"No reverse DNS for {ip}")
            return None


# ═══════════════════════════════════════════════════════
# Глобальный экземпляр
# ═══════════════════════════════════════════════════════

_monitor: Optional[IPMonitor] = None


@profiler
def get_monitor(config: Optional[Config] = None) -> IPMonitor:
    """Получить глобальный экземпляр IP Monitor"""
    global _monitor
    
    if _monitor is None:
        _monitor = IPMonitor(config or get_config())
    
    return _monitor
