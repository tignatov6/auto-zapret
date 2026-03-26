"""
Strategy Tester - Реальное тестирование стратегий DPI обхода

Отличия от analyzer._test_strategy():
1. Реальное HTTPS тестирование с применением параметров
2. Динамическая калибровка таймаутов на основе измерения RTT
3. Параллельное тестирование нескольких стратегий
4. Интеграция с existing executor/storage
"""

import re
import asyncio
import aiohttp
import time
import statistics
import logging
from typing import Callable, Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from .config import Config, get_config
from .executor import Executor
from .storage import Storage
from .utils.profiler import get_profiler
profiler = get_profiler("strategy_tester")

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════
#                 КОНСТАНТЫ И НАСТРОЙКИ
# ══════════════════════════════════════════════════════════

# Оптимальные таймауты (расчитаны по формуле: max × 1.33)
# Измерено в тестах 2026-03-23 (15 тестов):
#   max_start=367ms, max_test=283ms, max_kill=102ms
#   WINWS_INIT_WAIT = (367-50) × 1.33 / 1000 = 0.42s
#   TOTAL_TEST_TIMEOUT = 283 × 1.33 / 1000 = 0.38s
#   CONNECT_TIMEOUT = 283 × 0.33 × 1.33 / 1000 = 0.12s
#   TLS_TIMEOUT = 283 × 0.50 × 1.33 / 1000 = 0.19s
#   HTTP_TIMEOUT = 283 × 0.17 × 1.33 / 1000 = 0.06s
#   WINWS_KILL_WAIT = 102 × 1.33 / 1000 = 0.135s

# ══════════════════════════════════════════════════════════
#                 AGGRESSIVE MODE FLAG
# ══════════════════════════════════════════════════════════

AGGRESSIVE_TIMEOUT = True  # Включить агрессивные тайминги (×5-10 ускорение)
                           # Если False - используются консервативные таймауты

# Сайты для калибровки (только ДОСТУПНЫЕ сайты!)
# НЕ включаем заблокированные - они дают timeout и искажают средний RTT
CALIBRATION_SITES = [
    # Русские (ожидаем быстрый отклик)
    ("ya.ru", 443),
    ("vk.com", 443),
    ("mail.ru", 443),
    ("yandex.ru", 443),
    ("ozon.ru", 443),
    # Международные
    ("google.com", 443),
    ("cloudflare.com", 443),
    ("github.com", 443),
    ("microsoft.com", 443),
]

# ══════════════════════════════════════════════════════════
#                 QUIC DOMAIN DETECTION
# ══════════════════════════════════════════════════════════

# Кэш для результатов проверки QUIC (TTL 5 минут)
_quic_cache: Dict[str, Tuple[bool, float]] = {}
_QUIC_CACHE_TTL = 300  # секунд


async def check_quic_support(domain: str, timeout: float = 3.0) -> bool:
    """
    Проверяет поддерживает ли домен QUIC/HTTP3 через Alt-Svc заголовок.

    Как это работает:
    1. Делаем HTTP запрос к домену
    2. Проверяем заголовок Alt-Svc в ответе
    3. Если есть h3 или quic - домен поддерживает HTTP/3

    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса

    Returns:
        True если домен поддерживает QUIC/HTTP3
    """
    import socket
    import ssl
    import time

    # Проверяем кэш
    now = time.time()
    if domain in _quic_cache:
        cached_result, cached_time = _quic_cache[domain]
        if now - cached_time < _QUIC_CACHE_TTL:
            logger.debug(f"[quic_check] Cache hit for {domain}: {cached_result}")
            return cached_result

    logger.debug(f"[quic_check] Checking QUIC support for {domain}...")

    def _check_alt_svc() -> bool:
        """Синхронная проверка Alt-Svc заголовка"""
        try:
            # Создаём TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Резолвим домен
            addr_info = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                sock.close()
                return False

            # Подключаемся
            sock.connect(addr_info[0][4])

            # TLS handshake
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(sock, server_hostname=domain)

            # Отправляем HTTP/1.1 запрос
            request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            ssock.send(request.encode())

            # Читаем заголовки ответа
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk

            ssock.close()

            # Парсим заголовки
            headers = response.decode('utf-8', errors='ignore').lower()

            # Ищем Alt-Svc заголовок
            # Примеры: Alt-Svc: h3=":443", Alt-Svc: quic=":443"
            for line in headers.split('\r\n'):
                if line.startswith('alt-svc:'):
                    alt_svc = line.split(':', 1)[1]
                    # Проверяем наличие h3 или quic
                    if 'h3=' in alt_svc or 'quic=' in alt_svc or 'h3-' in alt_svc:
                        logger.debug(f"[quic_check] Found Alt-Svc: {alt_svc.strip()}")
                        return True

            logger.debug(f"[quic_check] No QUIC Alt-Svc header found for {domain}")
            return False

        except socket.timeout:
            logger.debug(f"[quic_check] Timeout for {domain}")
            return False
        except Exception as e:
            logger.debug(f"[quic_check] Error for {domain}: {e}")
            return False

    # Запускаем в executor
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _check_alt_svc),
            timeout=timeout + 1
        )
    except asyncio.TimeoutError:
        result = False

    # Кэшируем результат
    _quic_cache[domain] = (result, now)

    return result


def is_quic_domain_heuristic(domain: str) -> bool:
    """
    Эвристическая проверка - известные QUIC домены.
    Используется как fallback если проверка Alt-Svc не удалась.

    Args:
        domain: Домен для проверки

    Returns:
        True если домен вероятно использует QUIC
    """
    domain_lower = domain.lower()

    # Убираем www. префикс
    if domain_lower.startswith("www."):
        domain_lower = domain_lower[4:]

    # Известные QUIC-ориентированные сервисы
    quic_heuristics = [
        "googlevideo",
        "youtube",
        "ytimg",
        "google.",
        "googleusercontent",
        "gstatic",
        "ggpht",
        "yt.be",
        "facebook",
        "fbcdn",
        "instagram",
        "cdninstagram",
        "cloudflare",
        "cloudfront",
    ]

    for pattern in quic_heuristics:
        if pattern in domain_lower:
            return True

    return False

# Тестовые сайты для проверки стратегий
# Используем тот же домен который тестируем - это правильно!
# TEST_SITES больше не нужен - тестируем напрямую domain

# Базовые коэффициенты
TIMEOUT_MULTIPLIER = 1.5  # +50% к среднему RTT (как просил пользователь)

# Минимальные таймауты - зависят от AGGRESSIVE_MODE
if AGGRESSIVE_TIMEOUT:
    # Агрессивный режим - быстрые тесты
    MIN_TIMEOUT = 1
    MIN_TEST_TIMEOUT = 1
else:
    # Консервативные тайминги (как --max-time 2 в blockcheck.sh)
    MIN_TIMEOUT = 2.0
    MIN_TEST_TIMEOUT = 2.0

MAX_TIMEOUT = 10.0  # Максимальный таймаут

# Параллелизм - ОДИН домен за раз (winws не поддерживает параллельные стратегии)
MAX_CONCURRENT_TESTS = 1


class StrategyTestStatus(Enum):
    WORKS = "works"
    FAILS = "fails"
    TIMEOUT = "timeout"
    DNS_BLOCKED = "dns_blocked"
    NO_DPI = "no_dpi"
    ERROR = "error"


@dataclass
class CalibrationResult:
    """Результат калибровки таймаутов"""
    mean_rtt_ms: float = 0.0
    std_rtt_ms: float = 0.0
    fast_sites_rtt: float = 0.0  # Средний RTT до русских сайтов
    slow_sites_rtt: float = 0.0  # Средний RTT до международных
    timeout_base: float = 2.0  # Базовый таймаут для HTTPS теста
    timeout_extended: float = 5.0  # Расширенный таймаут для сложных тестов
    success_rate: float = 0.0  # Процент успешных соединений без DPI


@dataclass
class StrategyTestResult:
    """Результат тестирования стратегии"""
    status: StrategyTestStatus
    domain: str
    strategy_params: str
    response_time_ms: float = 0.0
    speed_mbps: float = 0.0
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class StrategyTester:
    """
    Реальное тестирование стратегий DPI обхода
    
    Использует:
    - Executor для применения параметров к nfqws
    - aiohttp для HTTPS тестирования
    - Динамические таймауты на основе калибровки
    """

    @profiler
    def __init__(self, storage: Storage, executor: Executor, config: Optional[Config] = None):
        self.storage = storage
        self.executor = executor
        self.config = config or get_config()
        
        # Результаты калибровки
        self._calibration: Optional[CalibrationResult] = None
        self._calibration_time: Optional[float] = None
        self._calibration_ttl = 300  # Перекалибровка каждые 5 минут
        
        # Semaphore для ограничения параллелизма
        self._test_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        
        # HTTP сессия
        self._session: Optional[aiohttp.ClientSession] = None

    @profiler
    async def _get_session(self) -> aiohttp.ClientSession:
        """Получение HTTP сессии (singleton)"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=10,
                connect=5,
                sock_connect=2,
                sock_read=5
            )
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    @profiler
    async def close(self):
        """Закрытие ресурсов"""
        if self._session and not self._session.closed:
            await self._session.close()

    # ══════════════════════════════════════════════════════════
    #                 КАЛИБРОВКА ТАЙМАУТОВ
    # ══════════════════════════════════════════════════════════

    @profiler
    async def calibrate(self, force: bool = False) -> CalibrationResult:
        """
        Калибровка таймаутов на основе измерения RTT до тестовых сайтов

        Args:
            force: Принудительная перекалибровка

        Returns:
            CalibrationResult с рассчитанными таймаутами
        """
        now = time.time()

        # Проверяем актуальность калибровки
        if not force and self._calibration and self._calibration_time:
            if now - self._calibration_time < self._calibration_ttl:
                logger.debug(f"Using cached calibration (age={now - self._calibration_time:.0f}s)")
                return self._calibration

        logger.info("[calibrate] Starting timeout calibration...")
        logger.info(f"[calibrate] Measuring RTT to {len(CALIBRATION_SITES)} sites...")
        start_time = time.time()
        
        results = {
            "fast": [],  # Русские сайты
            "slow": [],  # Международные
            "all": [],   # Все сайты
        }
        
        session = await self._get_session()
        
        # Параллельно измеряем RTT до всех сайтов
        @profiler
        async def measure_rtt(host: str, port: int) -> Tuple[str, Optional[float], Optional[str]]:
            """Измерение RTT до сайта"""
            try:
                conn = aiohttp.TCPConnector(
                    ssl=True,
                    server_hostname=host,
                    limit=1,
                )
                temp_session = aiohttp.ClientSession(connector=conn)
                
                test_start = time.time()
                # Короткий timeout для калибровки - быстрые сайты ответят за 1 сек
                async with temp_session.get(f"https://{host}/", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    rtt_ms = (time.time() - test_start) * 1000
                    await resp.read()
                    await temp_session.close()
                    
                    if host in ["ya.ru", "vk.com", "mail.ru"]:
                        results["fast"].append(rtt_ms)
                    else:
                        results["slow"].append(rtt_ms)
                    
                    results["all"].append(rtt_ms)
                    return host, rtt_ms, None
                    
            except asyncio.TimeoutError:
                try:
                    await temp_session.close()
                except:
                    pass
                return host, None, "timeout"
            except Exception as e:
                try:
                    await temp_session.close()
                except:
                    pass
                return host, None, str(e)
        
        # Запускаем все измерения параллельно
        tasks = [measure_rtt(host, port) for host, port in CALIBRATION_SITES]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Обрабатываем результаты
        successful = sum(1 for r in results_list if isinstance(r, tuple) and r[1] is not None)
        total = len(results_list)
        
        # Рассчитываем статистику
        all_rtt = [r[1] for r in results_list if isinstance(r, tuple) and r[1] is not None]
        
        # Логируем результаты измерений
        for r in results_list:
            if isinstance(r, tuple):
                host, rtt, error = r
                if rtt is not None:
                    logger.debug(f"[calibrate] {host}: {rtt:.1f}ms")
                else:
                    logger.debug(f"[calibrate] {host}: failed ({error})")
            else:
                logger.debug(f"[calibrate] Exception: {r}")

        if all_rtt:
            mean_rtt = statistics.mean(all_rtt)
            std_rtt = statistics.stdev(all_rtt) if len(all_rtt) > 1 else 0

            fast_rtt = statistics.mean(results["fast"]) if results["fast"] else mean_rtt
            slow_rtt = statistics.mean(results["slow"]) if results["slow"] else mean_rtt
            
            logger.info(f"[calibrate] RTT stats: mean={mean_rtt:.1f}ms, std={std_rtt:.1f}ms, fast={fast_rtt:.1f}ms, slow={slow_rtt:.1f}ms")

            # Рассчитываем таймауты: средний RTT + 50%
            # Но минимум 2 секунды (как в smart_tuner.py TCP_TIMEOUT=1 + запас)
            timeout_base = max(
                MIN_TIMEOUT,  # Минимум 2 секунды!
                min(MAX_TIMEOUT, (mean_rtt / 1000) * TIMEOUT_MULTIPLIER)
            )

            # Расширенный таймаут для сложных случаев
            timeout_extended = max(
                MIN_TIMEOUT,
                min(MAX_TIMEOUT, timeout_base * 2.5)
            )
            
            logger.info(f"[calibrate] Calculated timeouts: base={timeout_base:.2f}s, extended={timeout_extended:.2f}s")

            self._calibration = CalibrationResult(
                mean_rtt_ms=mean_rtt,
                std_rtt_ms=std_rtt,
                fast_sites_rtt=fast_rtt,
                slow_sites_rtt=slow_rtt,
                timeout_base=timeout_base,
                timeout_extended=timeout_extended,
                success_rate=successful / total if total > 0 else 0
            )

            self._calibration_time = time.time()

            logger.info(
                f"[calibrate] Complete: mean_rtt={mean_rtt:.0f}ms, "
                f"timeout_base={timeout_base:.2f}s, success_rate={successful}/{total}"
            )
        else:
            # Калибровка не удалась - используем дефолтные значения
            logger.warning("[calibrate] Failed, using default timeouts")
            self._calibration = CalibrationResult(
                mean_rtt_ms=100,
                std_rtt_ms=50,
                fast_sites_rtt=50,
                slow_sites_rtt=150,
                timeout_base=2.0,
                timeout_extended=5.0,
                success_rate=0
            )
            self._calibration_time = time.time()

        return self._calibration

    # ══════════════════════════════════════════════════════════
    #                 ТЕСТИРОВАНИЕ СТРАТЕГИЙ
    # ══════════════════════════════════════════════════════════

    @profiler
    async def test_strategy(
        self,
        domain: str,
        strategy_params: str,
        timeout: Optional[float] = None,
        is_quic: bool = False
    ) -> StrategyTestResult:
        """
        Реальное тестирование стратегии с применением параметров
        
        Args:
            domain: Домен для тестирования
            strategy_params: Параметры Zapret для тестирования
            timeout: Таймаут (если None, используется откалиброванный)
            is_quic: Если True - тестируем QUIC стратегию (только UDP)
            
        Returns:
            StrategyTestResult со статусом теста
        """
        async with self._test_semaphore:
            return await self._test_strategy_impl(domain, strategy_params, timeout, is_quic)

    @profiler
    async def _test_strategy_impl(
        self,
        domain: str,
        strategy_params: str,
        timeout: Optional[float] = None,
        is_quic: bool = False
    ) -> StrategyTestResult:
        """Реализация тестирования стратегии с ПЕРЕЗАПУСКОМ winws"""
        start_time = time.time()
        timings = {}  # Детальное логирование времени

        logger.info(f"[test_strategy] Testing: {domain} with params: {strategy_params[:80]}...")

        # Получаем калибровку если нужно
        calibrate_start = time.time()
        if timeout is None:
            calibration = await self.calibrate()
            # Используем timeout_base (mean_rtt + 33%), НЕ timeout_extended
            timeout = calibration.timeout_base
            logger.debug(f"[test_strategy] Using calibrated timeout: {timeout:.2f}s")
        timings['calibrate'] = time.time() - calibrate_start

        # ═══════════════════════════════════════════════════════
        # ШАГ 1: Останавливаем winws и запускаем с НОВОЙ стратегией
        # ═══════════════════════════════════════════════════════

        # Останавливаем текущий winws
        logger.debug(f"[test_strategy] Stopping winws...")
        stop_start = time.time()
        await self.executor.stop_winws()
        timings['stop_winws'] = time.time() - stop_start
        logger.debug(f"[test_strategy] winws stopped ({timings['stop_winws']:.3f}s)")

        # Запускаем winws с параметрами тестируемой стратегии
        logger.debug(f"[test_strategy] Starting winws with strategy...")
        start_winws_begin = time.time()
        is_first_run = self.executor._startup_time is None
        
        # ═══════════════════════════════════════════════════════════════════════
        # ОПРЕДЕЛЕНИЕ QUIC: учитываем И параметры стратегии, И возможности домена
        # ═══════════════════════════════════════════════════════════════════════
        
        # Определяем QUIC возможности домена (для выбора метода тестирования)
        # Сначала проверяем эвристику (быстро), потом Alt-Svc (точно)
        domain_is_quic = is_quic_domain_heuristic(domain)
        if not domain_is_quic:
            # Если эвристика не сработала, проверяем Alt-Svc
            domain_is_quic = await check_quic_support(domain, timeout=3.0)
        
        # Определяем тип стратегии по параметрам
        # ВАЖНО: UDP-only стратегии из blockcheck.sh: ipfrag, hopbyhop, destopt
        # Эти параметры работают ТОЛЬКО с UDP (IPv6 и QUIC специфичные)
        strategy_is_udp_only = (
            'ipfrag' in strategy_params.lower() or 
            'hopbyhop' in strategy_params.lower() or 
            'destopt' in strategy_params.lower()
        )
        
        # Если передан is_quic=True извне или это UDP-only стратегия - тестируем через UDP
        is_quic_strategy = is_quic or strategy_is_udp_only
        
        # Если домен поддерживает QUIC - используем UDP тестирование
        # Это критически важно для Google Video, YouTube и других QUIC-ориентированных сервисов!
        use_quic_test = domain_is_quic or is_quic_strategy
        
        if is_quic_strategy:
            logger.info(f"[test_strategy] UDP-only strategy detected, using UDP-only profile")
        elif domain_is_quic:
            logger.info(f"[test_strategy] Domain {domain} supports QUIC/HTTP3")
        
        success, msg, startup_time = await self.executor.start_winws_with_strategy(
            strategy_params,
            domain=domain,
            measure_startup=is_first_run,
            is_quic=is_quic_strategy
        )
        timings['start_winws'] = time.time() - start_winws_begin
        
        if success:
            logger.debug(f"[test_strategy] winws started ({timings['start_winws']:.3f}s), startup_time={startup_time:.3f}s")
        else:
            logger.warning(f"[test_strategy] Failed to start winws: {msg}")
            return StrategyTestResult(
                status=StrategyTestStatus.ERROR,
                domain=domain,
                strategy_params=strategy_params,
                error=f"winws start error: {msg}"
            )
        
        # Ждём время = max(100ms, startup_time * 1.1)
        #wait_time = self.executor.get_startup_wait_time()
        #logger.debug(f"Waiting {wait_time*1000:.0f}ms for winws to initialize...")
        #await asyncio.sleep(wait_time)
        #timings['wait_init'] = wait_time

        # ═══════════════════════════════════════════════════════
        # ШАГ 2: Реальное HTTPS/QUIC тестирование
        # ═══════════════════════════════════════════════════════

        # Берем таймаут из калибровки, но не позволяем ему упасть ниже 2 секунд
        test_timeout = max(MIN_TEST_TIMEOUT, timeout if timeout else 2.0)

        # ═══════════════════════════════════════════════════════
        # ВЫБОР МЕТОДА ТЕСТИРОВАНИЯ: TCP или UDP
        # ═══════════════════════════════════════════════════════
        
        # Используем QUIC тестирование если:
        # 1. Это UDP-only стратегия (ipfrag, hopbyhop, destopt)
        # 2. Домен поддерживает QUIC/HTTP3
        # Это критически важно для Google Video, YouTube и других
        if use_quic_test:
            logger.info(f"[test_strategy] Using UDP/QUIC test for {domain}")
            socket_result = await self._test_strategy_quic(domain, strategy_params, test_timeout, start_time)
        else:
            # Обычный домен - TCP тестирование
            logger.debug(f"[test_strategy] Domain {domain} - using TCP test")
            socket_result = await self._test_strategy_socket(domain, strategy_params, test_timeout, start_time)

        self.executor._kill_winws()
        return socket_result

    @profiler
    async def _test_strategy_aiohttp(
        self,
        domain: str,
        strategy_params: str,
        timeout: float,
        start_time: float
    ) -> StrategyTestResult:
        """Fallback тестирование через aiohttp (если curl не доступен)"""
        max_retries = 2
        last_error = None
        
        for retry in range(max_retries):
            if retry > 0:
                await asyncio.sleep(0.5)
            
            test_start = time.time()
            temp_session = None

            try:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                
                conn = aiohttp.TCPConnector(ssl=ssl_context, limit=1)
                temp_session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=timeout))

                async with temp_session.get(
                    f"https://{domain}/",
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers={'Host': domain}
                ) as resp:
                    rtt_ms = (time.time() - test_start) * 1000
                    await resp.read()
                    status_ok = resp.status == 200
                    await temp_session.close()

                    if status_ok:
                        return StrategyTestResult(
                            status=StrategyTestStatus.WORKS,
                            domain=domain,
                            strategy_params=strategy_params,
                            response_time_ms=rtt_ms,
                            details={"method": "aiohttp", "attempt": retry + 1}
                        )
                    else:
                        last_error = f"HTTP {resp.status}"

            except asyncio.TimeoutError:
                last_error = "timeout"
            except Exception as e:
                last_error = str(e)
            finally:
                if temp_session and not temp_session.closed:
                    await temp_session.close()
        
        return StrategyTestResult(
            status=StrategyTestStatus.FAILS,
            domain=domain,
            strategy_params=strategy_params,
            response_time_ms=(time.time() - start_time) * 1000,
            error=last_error or "All aiohttp attempts failed"
        )

    @profiler
    async def _test_strategy_socket(
        self,
        domain: str,
        strategy_params: str,
        timeout: float,
        start_time: float
    ) -> StrategyTestResult:
        """
        curl-based тестирование (точно как в blockcheck.sh)

        Используем curl вместо socket для полного соответствия с оригинальным blockcheck.sh:
        - TCP → TLS → HTTP Request → HTTP Response → Проверка статуса
        - Детекция фейковых пакетов (HTTP 400)
        - Таймаут на весь цикл, а не только на handshake
        """
        import subprocess
        import re

        loop = asyncio.get_event_loop()

        @profiler
        def test_https_curl() -> tuple:
            """
            Синхронное HTTPS тестирование через curl (как в blockcheck.sh)
            
            Возвращает: (success: bool, rtt_ms: float, error: str)
            """
            test_start = time.time()

            try:
                # curl параметры (точно как в blockcheck.sh строка 696):
                # curl_probe $1 $2 $HTTPS_PORT "$3" -ISs -A "$USER_AGENT" --max-time $CURL_MAX_TIME
                #   --tlsv1.2 $TLSMAX12 "https://$2" -o /dev/null
                
                # Получаем IP-адреса для логирования (curl сам резолвит)
                ips = self.executor._resolve_domain_ips(domain)
                if not ips:
                    return False, (time.time() - test_start) * 1000, 'dns_failed'

                # Формируем команду curl (TLS 1.2 как в blockcheck.sh)
                cmd = [
                    "curl",
                    "-ISs",                    # I=HEAD, S=show errors, s=silent
                    "-A", "curl/7.88.1",       # User-Agent как в blockcheck
                    "--max-time", str(timeout), # Таймаут на ВЕСЬ цикл (2 секунды)
                    "--tlsv1.2",               # TLS 1.2 (не 1.3 для отладки)
                    "--http1.1",               # Force HTTP/1.1
                    "-o", "NUL",               # Windows: отбрасываем вывод
                    f"https://{domain}"
                ]

                # Запускаем curl
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 0.5  # Небольшой запас на случай оверхеда
                )

                rtt_ms = (time.time() - test_start) * 1000

                # Анализируем результат
                if result.returncode == 0:
                    # curl успешен - HTTPS сайт доступен
                    return True, rtt_ms, None

                # curl вернул ошибку - анализируем тип
                stderr = result.stderr.lower()
                stdout = result.stdout.lower()

                # Таймаут
                if result.returncode == 28 or 'timed out' in stderr:
                    return False, rtt_ms, 'curl_timeout'

                # SSL/TLS ошибка (сертификат, handshake)
                if 'ssl' in stderr or 'certificate' in stderr:
                    return False, rtt_ms, f'ssl_error: {stderr[:100]}'

                # DNS ошибка
                if 'could not resolve' in stderr or result.returncode == 6:
                    return False, rtt_ms, 'dns_failed'

                # Соединение не установлено
                if 'failed to connect' in stderr or result.returncode == 7:
                    return False, rtt_ms, 'connection_failed'

                # HTTP ошибка (4xx, 5xx) - но curl получил ответ!
                if result.returncode == 22:
                    # HTTP код 4xx/5xx - сервер ответил, но это не 200/30x
                    # Пробуем извлечь HTTP код из stdout
                    match = re.search(r'(\d{3})', stdout)
                    if match:
                        http_code = int(match.group(1))
                        if http_code == 400:
                            # Сервер получил фейковые пакеты!
                            return False, rtt_ms, 'fake_detected_400'
                        elif http_code >= 500:
                            return False, rtt_ms, f'http_{http_code}'
                        elif http_code >= 400:
                            return False, rtt_ms, f'http_{http_code}'

                # Неизвестная ошибка
                return False, rtt_ms, f'curl_error_{result.returncode}: {stderr[:80]}'

            except subprocess.TimeoutExpired:
                return False, (time.time() - test_start) * 1000, 'curl_timeout_expired'
            except FileNotFoundError:
                return False, (time.time() - test_start) * 1000, 'curl_not_found'
            except Exception as e:
                return False, (time.time() - test_start) * 1000, str(e)

        # Запускаем в executor (синхронный код)
        success, rtt_ms, error = await loop.run_in_executor(None, test_https_curl)

        # Логируем результат для отладки
        if not success:
            logger.debug(f"[curl_test] {domain}: FAILED ({error}) after {rtt_ms:.0f}ms, timeout={timeout:.1f}s")
        else:
            logger.debug(f"[curl_test] {domain}: SUCCESS in {rtt_ms:.0f}ms")

        if success:
            return StrategyTestResult(
                status=StrategyTestStatus.WORKS,
                domain=domain,
                strategy_params=strategy_params,
                response_time_ms=rtt_ms,
                details={"method": "curl", "timeout": timeout}
            )
        else:
            return StrategyTestResult(
                status=StrategyTestStatus.FAILS,
                domain=domain,
                strategy_params=strategy_params,
                response_time_ms=(time.time() - start_time) * 1000,
                error=error or "curl test failed"
            )

    def _find_http3_curl(self) -> str:
        """
        Найти curl с поддержкой HTTP/3.
        
        Проверяем пути в порядке приоритета:
        1. C:\\curl\\bin\\curl.exe (специально установленный curl)
        2. curl в PATH (через where.exe)
        3. C:\\Windows\\System32\\curl.exe (fallback)
        
        Returns:
            Путь к curl с HTTP/3 поддержкой или fallback
        """
        import subprocess
        import os
        
        # Известные пути к curl с HTTP/3
        known_paths = [
            r"C:\curl\bin\curl.exe",
            r"C:\Program Files\curl\bin\curl.exe",
        ]
        
        # Проверяем известные пути
        for path in known_paths:
            if os.path.exists(path):
                try:
                    result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=1)
                    if "HTTP3" in result.stdout or "http3" in result.stdout.lower():
                        logger.debug(f"[curl] Found HTTP/3 curl at {path}")
                        return path
                except:
                    pass
        
        # Проверяем curl в PATH через where.exe
        try:
            result = subprocess.run(["where", "curl"], capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                paths = result.stdout.strip().split('\n')
                for path in paths:
                    path = path.strip()
                    if path:
                        try:
                            check = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=1)
                            if "HTTP3" in check.stdout or "http3" in check.stdout.lower():
                                logger.debug(f"[curl] Found HTTP/3 curl in PATH: {path}")
                                return path
                        except:
                            pass
        except:
            pass
        
        # Fallback на curl из PATH
        return "curl"

    @profiler
    async def _test_strategy_quic(
        self,
        domain: str,
        strategy_params: str,
        timeout: float,
        start_time: float
    ) -> StrategyTestResult:
        """
        QUIC/UDP тестирование через curl --http3 (как в blockcheck.sh)

        Для QUIC доменов (googlevideo.com, youtube.com и т.д.) нужно тестировать
        через UDP 443, а не TCP.

        Используем curl --http3-only для надежного тестирования QUIC.
        """
        import subprocess

        loop = asyncio.get_event_loop()

        @profiler
        def test_quic_curl() -> tuple:
            """
            Тестирование QUIC через curl --http3-only

            Возвращает: (success: bool, rtt_ms: float, error: str)
            """
            test_start = time.time()

            try:
                # curl параметры для QUIC (как в blockcheck.sh строка 714):
                # curl_with_dig $1 $2 $QUIC_PORT -ISs -A "$USER_AGENT"
                #   --max-time $CURL_MAX_TIME_QUIC --http3-only ... "https://$2"

                # Определяем путь к curl с HTTP/3 поддержкой
                curl_path = self._find_http3_curl()

                # Проверяем поддержку HTTP/3 в curl
                try:
                    result = subprocess.run(
                        [curl_path, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=1
                    )
                    has_http3 = "HTTP3" in result.stdout or "http3" in result.stdout.lower()
                except:
                    has_http3 = False

                if not has_http3:
                    # Fallback на TCP тест если curl не поддерживает HTTP/3
                    logger.warning(f"[quic_test] curl does not support HTTP/3, using TCP fallback")
                    return self._test_quic_tcp_fallback(domain, timeout, test_start)

                # Формируем команду curl для QUIC
                cmd = [
                    curl_path,
                    "-ISs",                    # I=HEAD, S=show errors, s=silent
                    "-A", "curl/7.88.1",       # User-Agent
                    "--max-time", str(timeout), # Таймаут на ВЕСЬ цикл
                    "--http3-only",            # ТОЛЬКО HTTP/3 (QUIC)
                    "--http3",                 # Включаем поддержку HTTP/3
                    "-o", "NUL",               # Windows: отбрасываем вывод
                    f"https://{domain}"
                ]

                # Запускаем curl
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 0.5
                )

                rtt_ms = (time.time() - test_start) * 1000

                # Анализируем результат
                if result.returncode == 0:
                    # curl успешен - QUIC сайт доступен
                    return True, rtt_ms, None

                # curl вернул ошибку - анализируем тип
                stderr = result.stderr.lower()
                stdout = result.stdout.lower()

                # Таймаут
                if result.returncode == 28 or 'timed out' in stderr:
                    return False, rtt_ms, 'quic_timeout'

                # QUIC ошибка (сервер не поддерживает QUIC)
                if 'http/3' in stderr or 'quic' in stderr or 'alt-svc' in stderr:
                    return False, rtt_ms, 'quic_not_supported'

                # SSL/TLS ошибка
                if 'ssl' in stderr or 'certificate' in stderr:
                    return False, rtt_ms, f'ssl_error: {stderr[:100]}'

                # DNS ошибка
                if 'could not resolve' in stderr or result.returncode == 6:
                    return False, rtt_ms, 'dns_failed'

                # Соединение не установлено
                if 'failed to connect' in stderr or result.returncode == 7:
                    return False, rtt_ms, 'connection_failed'

                # HTTP ошибка (4xx, 5xx)
                if result.returncode == 22:
                    match = re.search(r'(\d{3})', stdout)
                    if match:
                        http_code = int(match.group(1))
                        if http_code == 400:
                            return False, rtt_ms, 'fake_detected_400'
                        elif http_code >= 500:
                            return False, rtt_ms, f'http_{http_code}'
                        elif http_code >= 400:
                            return False, rtt_ms, f'http_{http_code}'

                # Неизвестная ошибка
                return False, rtt_ms, f'quic_error_{result.returncode}: {stderr[:80]}'

            except subprocess.TimeoutExpired:
                return False, (time.time() - test_start) * 1000, 'quic_timeout_expired'
            except FileNotFoundError:
                return False, (time.time() - test_start) * 1000, 'curl_not_found'
            except Exception as e:
                return False, (time.time() - test_start) * 1000, str(e)

        # Запускаем в executor (синхронный код)
        success, rtt_ms, error = await loop.run_in_executor(None, test_quic_curl)

        # Логируем результат
        if not success:
            logger.debug(f"[quic_test] {domain}: FAILED ({error}) after {rtt_ms:.0f}ms")
        else:
            logger.debug(f"[quic_test] {domain}: SUCCESS in {rtt_ms:.0f}ms")

        if success:
            return StrategyTestResult(
                status=StrategyTestStatus.WORKS,
                domain=domain,
                strategy_params=strategy_params,
                response_time_ms=rtt_ms,
                details={"method": "curl_http3", "timeout": timeout}
            )
        else:
            return StrategyTestResult(
                status=StrategyTestStatus.FAILS,
                domain=domain,
                strategy_params=strategy_params,
                response_time_ms=(time.time() - start_time) * 1000,
                error=error or "QUIC test failed"
            )

    def _test_quic_tcp_fallback(self, domain: str, timeout: float, test_start: float) -> tuple:
        """
        Fallback на TCP тест если curl не поддерживает HTTP/3
        
        Некоторые QUIC сервера также работают по TCP.
        """
        import socket
        import ssl
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Пробуем подключиться по TCP
            addr_info = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                sock.close()
                return False, (time.time() - test_start) * 1000, 'dns_failed'
            
            server_addr = addr_info[0][4]
            sock.connect(server_addr)
            
            # TLS handshake
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(sock, server_hostname=domain)
            
            # Отправляем HTTP запрос
            request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            ssock.send(request.encode())
            
            # Получаем ответ
            ssock.settimeout(0.5)
            data = ssock.recv(256)
            
            rtt_ms = (time.time() - test_start) * 1000
            ssock.close()
            
            if data and (b'200' in data or b'301' in data or b'302' in data):
                return True, rtt_ms, None
            else:
                return False, rtt_ms, 'tcp_fallback_failed'

        except Exception as e:
            return False, (time.time() - test_start) * 1000, f'tcp_fallback: {e}'

    @profiler
    async def test_strategies_parallel(
        self,
        domain: str,
        strategies: List[Dict[str, str]]
    ) -> List[StrategyTestResult]:
        """
        ПОСЛЕДОВАТЕЛЬНОЕ тестирование стратегий (с перезапуском winws для каждой)
        
        ВНИМАНИЕ: Параллельное тестирование невозможно, так как winws нужно 
        перезапускать с новыми параметрами для каждой стратегии.
        
        Args:
            domain: Домен для тестирования
            strategies: Список стратегий [{"name": "...", "params": "..."}]
            
        Returns:
            Список результатов тестирования
        """
        logger.info(f"Starting brute-force for {domain}: {len(strategies)} strategies")
        results = []
        
        # Останавливаем winws перед началом
        await self.executor.stop_winws()
        
        for idx, strat in enumerate(strategies):
            name = strat.get("name", str(idx))
            params = strat.get("params", "")
            
            logger.info(f"[{idx+1}/{len(strategies)}] Testing: {name[:50]}...")
            
            result = await self.test_strategy(domain, params)
            result.details["strategy_name"] = name
            result.details["test_index"] = idx + 1
            result.details["total_strategies"] = len(strategies)
            results.append(result)
            
            # Если стратегия сработала - сохраняем и возвращаем
            if result.status == StrategyTestStatus.WORKS:
                logger.info(f"✓ Found working strategy for {domain}: {name}")
                # Не останавливаем winws - оставляем рабочую стратегию
                return results
            
            # Небольшая пауза между тестами
            await asyncio.sleep(0.1)
        
        # Все стратегии перепробованы, ничего не сработало
        # Останавливаем winws
        await self.executor.stop_winws()
        
        return results
    
    @profiler
    async def bruteforce_strategy(
        self,
        domain: str,
        strategies: List[Dict[str, str]],
        stop_on_success: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> Tuple[Optional[Dict[str, str]], List[StrategyTestResult]]:
        """
        Brute-force поиск рабочей стратегии для домена
        
        Args:
            domain: Домен для тестирования
            strategies: Список стратегий [{"name": "...", "params": "..."}]
            stop_on_success: Остановиться после первой успешной стратегии
            progress_callback: Callback для прогресса (idx, total, result)
            
        Returns:
            (working_strategy, all_results)
        """
        logger.info(f"Brute-force for {domain}: {len(strategies)} strategies")
        
        results = []
        working_strategy = None
        
        # Останавливаем winws перед началом
        await self.executor.stop_winws()
        
        for idx, strat in enumerate(strategies):
            name = strat.get("name", str(idx))
            params = strat.get("params", "")
            
            logger.debug(f"[{idx+1}/{len(strategies)}] Testing: {name[:50]}...")
            
            result = await self.test_strategy(domain, params)
            result.details["strategy_name"] = name
            results.append(result)
            
            # Callback прогресса
            if progress_callback:
                try:
                    progress_callback(idx + 1, len(strategies), result)
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")
            
            # Если стратегия сработала
            if result.status == StrategyTestStatus.WORKS:
                working_strategy = strat
                logger.info(f"✓ Found working strategy for {domain}: {name}")
                
                if stop_on_success:
                    return working_strategy, results
        
        # Останавливаем winws если ничего не сработало
        if working_strategy is None:
            await self.executor.stop_winws()
        
        return working_strategy, results

    # ══════════════════════════════════════════════════════════
    #                 БЫСТРАЯ ПРОВЕРКА DPI
    # ══════════════════════════════════════════════════════════

    @profiler
    async def check_dpi_present(self, domain: str) -> bool:
        """
        Быстрая проверка есть ли DPI блокировка
        
        Returns:
            True если DPI обнаружен, False если нет
        """
        session = await self._get_session()
        
        try:
            # Пробуем подключиться напрямую (без стратегии)
            async with session.get(f"https://{domain}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    logger.debug(f"No DPI detected for {domain}")
                    return False  # DPI нет
                else:
                    logger.debug(f"HTTP error for {domain}: {resp.status}")
                    return True  # Возможно DPI
        except asyncio.TimeoutError:
            logger.debug(f"Timeout for {domain} - DPI likely present")
            return True
        except aiohttp.ClientError as e:
            logger.debug(f"Client error for {domain}: {e} - DPI likely present")
            return True
        except Exception as e:
            logger.warning(f"Check error for {domain}: {e}")
            return True


# ══════════════════════════════════════════════════════════
#                     SINGLETON
# ══════════════════════════════════════════════════════════

_tester: Optional[StrategyTester] = None


@profiler
def get_tester(
    storage: Storage,
    executor: Executor,
    config: Optional[Config] = None
) -> StrategyTester:
    """Получение singleton экземпляра StrategyTester"""
    global _tester
    if _tester is None:
        _tester = StrategyTester(storage, executor, config)
    return _tester