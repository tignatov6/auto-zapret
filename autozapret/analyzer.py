"""
Analyzer - модуль анализа событий и подбора стратегий

Логика работы:
1. При обнаружении проблемного домена → проверяем существующие стратегии
2. Если найдена рабочая (success_rate > 70%) → добавляем домен к ней
3. Если нет → запускаем подбор параметров (blockcheck-style)
4. Если подобрана → создаём новую стратегию
5. Если ничего не работает → cooldown на N минут
"""

import asyncio
import aiofiles
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging

from .config import Config, get_config
from .storage import Storage, Strategy, StatEvent
from .monitor import AutoHostlistEvent, EventType
from .executor import Executor
from .dpi_detector import DPIDetector, DPIStatus, get_detector
from .helpers import normalize_domain, canonicalize_params
from .strategy_tester import StrategyTester, StrategyTestStatus as TesterStatus, get_tester as get_strategy_tester
from .strategy_generator import StrategyGenerator, get_generator as get_strategy_generator
from .blockcheck_selector import (
    BlockcheckStrategySelector, SelectorState, ProtocolType, ScanLevel,
    update_selector_state
)
from .blockcheck_selector import get_selector as get_blockcheck_selector
from .nfqws_config import get_generator as get_nfqws_generator
from .utils.profiler import get_profiler
profiler = get_profiler("analyzer")

logger = logging.getLogger(__name__)

# Базовая директория проекта
BASE_DIR = Path(__file__).parent.parent.resolve()


class StrategyTestStatus(Enum):
    """Статус тестирования стратегии"""
    WORKS = "works"  # Стратегия работает
    FAILS = "fails"  # Стратегия не работает
    NO_DPI = "no_dpi"  # DPI не обнаружен, стратегия не нужна
    DNS_BLOCKED = "dns_blocked"  # DNS блокировка
    IP_BLOCKED = "ip_blocked"  # IP блокировка
    ERROR = "error"  # Ошибка теста


class BruteForceStatus(Enum):
    """Статус подбора стратегии brute-force"""
    FOUND = "found"
    NO_DPI = "no_dpi"
    NOT_FOUND = "not_found"


@dataclass
class StrategyTestResult:
    """Результат тестирования стратегии"""
    status: StrategyTestStatus
    domain: str
    strategy_params: str
    success_rate: float = 0.0  # Насколько хорошо работает (0-1)
    response_time: float = 0.0  # Время ответа в секундах
    error: str = ""

    @profiler
    def is_success(self) -> bool:
        return self.status == StrategyTestStatus.WORKS


@dataclass
class BruteForceResult:
    """Результат brute-force подбора стратегии"""
    status: BruteForceStatus
    params: Optional[str] = None
    description: Optional[str] = None

# Глобальная очередь для real-time логов
from asyncio import Queue
from collections import deque
log_queue: Queue = Queue()  # Без ограничения чтобы избежать блокировок
log_history = deque(maxlen=1000)  # Последние 1000 записей

# Прогресс подбора стратегий
brute_force_progress: Dict[str, Dict[str, Any]] = {}

# TTL для записей прогрресса (5 минут)
BRUTE_FORCE_PROGRESS_TTL = 300  # секунд


@profiler
def _cleanup_brute_force_progress() -> None:
    """Очистка старых записей прогресса по TTL"""
    now = datetime.now()
    to_remove = []
    
    for domain, progress in brute_force_progress.items():
        completed = progress.get("completed")
        if completed:
            try:
                completed_time = datetime.fromisoformat(completed)
                if (now - completed_time).total_seconds() > BRUTE_FORCE_PROGRESS_TTL:
                    to_remove.append(domain)
            except (ValueError, TypeError):
                pass
    
    for domain in to_remove:
        del brute_force_progress[domain]


@profiler
async def add_log_entry(entry: Dict[str, Any]) -> None:
    """Добавление записи лога"""
    entry['timestamp'] = datetime.now().isoformat()
    log_history.append(entry)
    
    # Используем put_nowait чтобы избежать блокировки если очередь полна
    try:
        log_queue.put_nowait(entry)
    except asyncio.QueueFull:
        # Тихо игнорируем переполнение очереди - лог всё равно сохранён в log_history
        pass

    # Периодически чистим прогресс (каждые 100 записей)
    if len(log_history) % 100 == 0:
        _cleanup_brute_force_progress()


@profiler
def get_log_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Получение истории логов"""
    return list(log_history)[-limit:]

# Порог срабатывания (должен совпадать с hostlist-auto-fail-threshold в nfqws)
DEFAULT_FAIL_THRESHOLD = 3

# Параметры для перебора (blockcheck-style)
BRUTE_FORCE_STRATEGIES = [
    # Простые
    {"params": "--dpi-desync=fake", "description": "Fake packets"},
    {"params": "--dpi-desync=split", "description": "Split only"},
    {"params": "--dpi-desync=disorder", "description": "Disorder only"},
    
    # Комбинированные
    {"params": "--dpi-desync=fake,split", "description": "Fake + Split"},
    {"params": "--dpi-desync=fake,disorder", "description": "Fake + Disorder"},
    {"params": "--dpi-desync=fake,multisplit", "description": "Fake + Multisplit"},
    {"params": "--dpi-desync=fake,multidisorder", "description": "Fake + Multidisorder"},
    
    # С позициями
    {"params": "--dpi-desync=fake --dpi-desync-split-pos=method+2", "description": "Fake method+2"},
    {"params": "--dpi-desync=split --dpi-desync-split-pos=1,midsld", "description": "Split midsld"},
    {"params": "--dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2", "description": "Fake multisplit method+2"},
    {"params": "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld", "description": "Fake multidisorder midsld"},
    
    # С fooling
    {"params": "--dpi-desync=fake --dpi-desync-fooling=md5sig", "description": "Fake md5sig"},
    {"params": "--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig", "description": "Fake multisplit md5sig"},
    {"params": "--dpi-desync=fake,multidisorder --dpi-desync-fooling=badseq,md5sig", "description": "Fake multidisorder badseq"},
]


class Analyzer:
    """Анализ событий и подбор стратегий"""

    @profiler
    def __init__(self, storage: Storage, executor: Executor,
                 config: Optional[Config] = None):
        self.storage = storage
        self.executor = executor
        self.config = config or get_config()

        # Инициализация DPI детектора
        self.dpi_detector = get_detector(
            zapret_src_dir=getattr(self.config, 'zapret_src_dir', './zapret-src'),
            blockcheck_path=getattr(self.config, 'blockcheck_path', ''),
            use_sudo=getattr(self.config, 'use_sudo_for_blockcheck', False)
        )

        # Инициализация Strategy Tester для реального тестирования стратегий
        self.strategy_tester = get_strategy_tester(storage, executor, self.config)

        # Инициализация Strategy Generator для генерации 500+ стратегий (brute-force)
        has_fake_files = self._check_fake_files()
        ultimate_path = str(BASE_DIR / "config" / "ultimate_strategies.json")
        self.strategy_generator = get_strategy_generator(has_fake_files, ultimate_path)
        
        # Nfqws Generator для управления профилями winws (singleton, инициализирован в api.py)
        self.nfqws_generator = get_nfqws_generator(config)
        # Устанавливаем storage для синхронизации profiles
        self.nfqws_generator._storage = storage

        # Кэш активных неудач
        self._active_fails: Dict[str, int] = defaultdict(int)

        # Background tasks для анализа
        self._analysis_tasks: Dict[str, asyncio.Task] = {}
        self._domain_locks: Dict[str, asyncio.Lock] = {}
        self._running = True

        # Semaphore для ограничения параллелизма анализа
        self._analysis_semaphore = asyncio.Semaphore(self.config.analysis_max_parallel)
        
        # Глобальная блокировка для brute-force - ОДИН домен за раз
        # (winws не поддерживает параллельные стратегии)
        self._bruteforce_lock = asyncio.Lock()
        self._bruteforce_queue: List[str] = []  # Очередь доменов
        self._current_bruteforce_domain: Optional[str] = None

    @profiler
    async def shutdown(self) -> None:
        """Корректное завершение работы - отмена всех background tasks"""
        logger.info("Shutting down Analyzer...")
        self._running = False

        # Отменяем все задачи анализа
        logger.info(f"Cancelling {len(self._analysis_tasks)} analysis tasks...")
        for task in self._analysis_tasks.values():
            if not task.done():
                task.cancel()

        # Ждём завершения
        if self._analysis_tasks:
            await asyncio.gather(*self._analysis_tasks.values(), return_exceptions=True)

        logger.info("Analyzer shutdown complete")

    @profiler
    async def handle_event(self, event: AutoHostlistEvent) -> None:
        """
        Обработка события от Monitor

        Args:
            event: Событие autohostlist
        """
        if event.event_type == EventType.FAIL_COUNTER:
            await self._handle_fail_counter(event)
        elif event.event_type == EventType.DOMAIN_ADDED:
            await self._handle_domain_added(event)
        elif event.event_type == EventType.FAIL_RESET:
            await self._handle_fail_reset(event)
        elif event.event_type == EventType.DOMAIN_NOT_ADDED:
            logger.debug(f"Domain {event.domain} not added (duplicate)")

    @profiler
    async def _handle_fail_counter(self, event: AutoHostlistEvent) -> None:
        """Обработка увеличения счётчика неудач"""
        domain = normalize_domain(event.domain)
        counter = event.fail_counter
        threshold = event.fail_threshold

        logger.info(f"Domain {domain}: fail counter {counter}/{threshold}")

        # Добавляем в real-time лог
        await add_log_entry({
            "type": "fail_counter",
            "domain": domain,
            "counter": counter,
            "threshold": threshold,
            "message": f"Fail counter: {counter}/{threshold} ({event.protocol})",
            "client": event.client,
            "profile": event.profile_id
        })

        # Записываем fail в БД (абсолютный счётчик из лога)
        domain_info = await self.storage.get_domain(domain)
        await self.storage.set_fail_count(domain, counter)
        await self.storage.log_event(StatEvent(
            domain=domain,
            event_type="fail",
            strategy_id=domain_info.strategy_id if domain_info else 0,
            details=f"Fail counter {counter}/{threshold}"
        ))

        # Очищаем autohostlist после каждого события
        # Файл должен быть всегда пустым - winws добавляет туда домены, мы сразу очищаем
        await self._clear_autohostlist()

        # Если порог достигнут - запускаем анализ в фоне
        if counter >= threshold:
            logger.info(f"Domain {domain}: threshold {threshold} reached, starting strategy selection")
            await add_log_entry({
                "type": "threshold_reached",
                "domain": domain,
                "message": f"Threshold reached ({threshold}), starting strategy selection",
                "protocol": event.protocol
            })

            # Запускаем background task если ещё не запущен
            await self._start_background_analysis(domain, event.protocol)

    @profiler
    async def _start_background_analysis(self, domain: str, protocol: str) -> None:
        """Запуск анализа в фоне"""
        logger.debug(f"Starting background analysis for {domain} (protocol={protocol})")
        
        # Получаем lock для домена
        if domain not in self._domain_locks:
            self._domain_locks[domain] = asyncio.Lock()

        async with self._domain_locks[domain]:
            # Проверяем не запущен ли уже анализ
            if domain in self._analysis_tasks and not self._analysis_tasks[domain].done():
                logger.debug(f"Analysis already running for {domain}")
                return

            # Создаём новую задачу
            logger.info(f"Creating analysis task for {domain}")
            self._analysis_tasks[domain] = asyncio.create_task(
                self._apply_strategy_to_domain(domain, protocol)
            )

            # Очищаем completed tasks периодически
            self._analysis_tasks = {
                d: t for d, t in self._analysis_tasks.items()
                if not t.done()
            }

    @profiler
    async def _handle_domain_added(self, event: AutoHostlistEvent) -> None:
        """Обработка добавления домена в autohostlist"""
        domain = normalize_domain(event.domain)

        # Записываем в базу
        domain_info = await self.storage.get_domain(domain)
        if domain_info:
            await self.storage.log_event(StatEvent(
                domain=domain,
                event_type="applied",
                strategy_id=domain_info.strategy_id,
                details="Added by nfqws autohostlist"
            ))

        logger.info(f"Domain {domain} added to autohostlist by nfqws")

    @profiler
    async def _handle_fail_reset(self, event: AutoHostlistEvent) -> None:
        """Обработка сброса счётчика неудач"""
        domain = normalize_domain(event.domain)
        logger.debug(f"Handling fail reset for {domain}")

        # Сбрасываем локальный кэш
        self._active_fails[domain] = 0

        # Сбрасываем в базе
        await self.storage.reset_fail_count(domain)
        await self.storage.clear_strategy_cooldown(domain)

        # Логируем успех
        domain_info = await self.storage.get_domain(domain)
        if domain_info:
            await self.storage.log_event(StatEvent(
                domain=domain,
                event_type="success",
                strategy_id=domain_info.strategy_id,
                details="Website is working"
            ))

            # Обновляем статистику стратегии
            await self.storage.update_strategy_stats(domain_info.strategy_id, success=True)

        logger.info(f"Domain {domain}: fail counter reset (website working)")

    @profiler
    async def _apply_strategy_to_domain(self, domain: str, protocol: str = "unknown") -> None:
        """
        Применение стратегии к домену

        Логика:
        1. Проверяем cooldown
        2. Если домен уже имеет стратегию - проверяем её первой
        3. Проверяем существующие стратегии (включая untested)
        4. Если не найдено - подбор (blockcheck-style)
        5. Если ничего - cooldown
        """
        from uuid import uuid4

        # Нормализуем домен СРАЗУ
        domain = normalize_domain(domain)

        async with self._analysis_semaphore:
            try:
                await self._apply_strategy_to_domain_impl(domain, protocol)
            except asyncio.CancelledError:
                logger.info(f"Analysis cancelled for {domain}")
                raise
            except Exception as e:
                logger.exception(f"Error in background analysis for {domain}: {e}")
                await add_log_entry({
                    "type": "analysis_error",
                    "domain": domain,
                    "error": str(e),
                    "message": f"❌ Analysis error: {e}"
                })

    @profiler
    async def _apply_strategy_to_domain_impl(self, domain: str, protocol: str = "unknown") -> None:
        """
        Реализация применения стратегии к домену (вызывается внутри semaphore)
        """
        from uuid import uuid4

        logger.info(f"[_apply_strategy_to_domain_impl] Starting analysis for {domain} (protocol={protocol})")

        # Проверяем cooldown
        cooldown_until = await self.storage.get_strategy_cooldown(domain)
        if cooldown_until:
            logger.info(f"Domain {domain} in cooldown until {cooldown_until}")
            await add_log_entry({
                "type": "cooldown",
                "domain": domain,
                "until": cooldown_until,
                "message": f"Domain in cooldown until {cooldown_until}"
            })
            return

        # Проверяем есть ли уже стратегия у домена
        existing_domain = await self.storage.get_domain(domain)
        current_strategy = None
        if existing_domain and existing_domain.is_active:
            current_strategy = await self.storage.get_strategy_by_id(existing_domain.strategy_id)
            logger.info(f"Domain {domain} already has strategy: {current_strategy.name if current_strategy else 'unknown'}")

        # ═══════════════════════════════════════════════════════
        # ШАГ 1: Проверяем ВСЕ существующие стратегии
        # ═══════════════════════════════════════════════════════
        logger.info(f"Checking all existing strategies for {domain} ({protocol})")
        await add_log_entry({
            "type": "checking_existing",
            "domain": domain,
            "protocol": protocol,
            "message": f"🔍 Testing all existing strategies for {domain}..."
        })

        # Получаем все стратегии (включая untested с total_checks=0)
        strategies = await self.storage.get_strategies_by_priority(min_success_rate=0.0)
        logger.info(f"Found {len(strategies)} strategies to check")
        
        working_strategies = []  # Список результатов для работающих стратегий

        # Если есть текущая стратегия - проверяем её первой
        if current_strategy:
            logger.debug(f"Testing current strategy {current_strategy.name} first")
            await add_log_entry({
                "type": "testing_strategy",
                "domain": domain,
                "strategy": current_strategy.name,
                "message": f"🧪 Testing current: {current_strategy.name}"
            })
            
            result = await self._test_strategy(domain, current_strategy.zapret_params)

            if result.status == StrategyTestStatus.WORKS:
                logger.info(f"✅ Current strategy {current_strategy.name} WORKS (RTT: {result.response_time:.3f}s)")
                working_strategies.append((current_strategy, result))
                await self.storage.update_strategy_stats(current_strategy.id, success=True)
            elif result.status == StrategyTestStatus.NO_DPI:
                logger.info(f"No DPI detected for {domain}, strategy not needed")
                await add_log_entry({
                    "type": "no_dpi",
                    "domain": domain,
                    "message": f"ℹ️ No DPI detected, strategy not needed"
                })
                await self.storage.reset_fail_count(domain)
                await self.storage.clear_strategy_cooldown(domain)
                return
            else:
                logger.warning(f"❌ Current strategy {current_strategy.name} failed")
                await self.storage.update_strategy_stats(current_strategy.id, success=False)
                await add_log_entry({
                    "type": "strategy_failed",
                    "domain": domain,
                    "strategy": current_strategy.name,
                    "message": f"❌ Current strategy failed: {current_strategy.name}"
                })

        # Проверяем остальные стратегии
        for strategy in strategies:
            # Пропускаем текущую стратегию (уже проверили)
            if current_strategy and strategy.id == current_strategy.id:
                continue

            logger.debug(f"Testing strategy {strategy.name} (success_rate={strategy.success_rate:.2f}, checks={strategy.total_checks})")
            await add_log_entry({
                "type": "testing_strategy",
                "domain": domain,
                "strategy": strategy.name,
                "message": f"🧪 Testing {strategy.name} (success_rate={strategy.success_rate:.2f})"
            })
            
            # Тестируем стратегию
            result = await self._test_strategy(domain, strategy.zapret_params)

            if result.status == StrategyTestStatus.WORKS:
                logger.info(f"✅ Strategy {strategy.name} WORKS (RTT: {result.response_time:.3f}s)")
                working_strategies.append((strategy, result))
                # Обновляем общую статистику стратегии в БД (успех)
                await self.storage.update_strategy_stats(strategy.id, success=True)
            else:
                # Обновляем общую статистику стратегии в БД (неудача)
                await self.storage.update_strategy_stats(strategy.id, success=False)

        # ═══════════════════════════════════════════════════════
        # Если нашли хотя бы одну рабочую среди существующих
        # ═══════════════════════════════════════════════════════
        if working_strategies:
            # Сортируем по времени ответа (RTT) и выбираем самую быструю
            working_strategies.sort(key=lambda x: x[1].response_time)
            best_strategy, best_result = working_strategies[0]
            
            logger.info(f"🏆 Best existing strategy for {domain}: {best_strategy.name} (RTT: {best_result.response_time:.3f}s)")
            
            await add_log_entry({
                "type": "strategy_found",
                "domain": domain,
                "strategy": best_strategy.name,
                "method": "existing_best",
                "message": f"✅ Picked BEST existing strategy: {best_strategy.name} (RTT: {best_result.response_time:.3f}s)"
            })

            # Применяем лучшую стратегию
            if current_strategy and current_strategy.id != best_strategy.id:
                success, msg = await self.executor.reassign_domain(domain, current_strategy.name, best_strategy.name)
            else:
                success, msg = await self.executor.apply_strategy(domain, best_strategy.name)

            if success:
                await self.storage.assign_domain(domain, best_strategy.id)
                await self.storage.reset_fail_count(domain)
                await self.storage.log_event(StatEvent(
                    domain=domain,
                    event_type="applied",
                    strategy_id=best_strategy.id,
                    details=f"Best existing strategy: {best_strategy.name} (RTT: {best_result.response_time:.3f}s)"
                ))
                
                # ═══════════════════════════════════════════════════════
                # ПОЛНЫЙ РЕСТАРТ WINWS СО ВСЕМИ СТРАТЕГИЯМИ
                # ═══════════════════════════════════════════════════════
                logger.info(f"[analyzer] Strategy applied → full winws restart...")

                # 1. Синхронизируем profiles из БД
                await self.nfqws_generator.sync_from_storage()

                # 2. Обновляем стратегию в nfqws-генераторе
                strategy_obj = await self.storage.get_strategy_by_id(best_strategy.id)
                if strategy_obj:
                    await self.nfqws_generator.update_profile(strategy_obj)

                # 3. Перегенерируем батник
                script_path = os.path.join(self.config.data_dir, "start-nfqws-auto.cmd")
                self.nfqws_generator.generate_windows_batch(script_path)

                # 4. Полный рестарт winws
                success, msg = await self.executor.restart_winws_full(self.nfqws_generator)

                if success:
                    await add_log_entry({
                        "type": "winws_full_restart",
                        "domain": domain,
                        "strategy": best_strategy.name,
                        "message": "✅ winws перезапущен с лучшей стратегией"
                    })
                    await self._clear_autohostlist()
                else:
                    await add_log_entry({
                        "type": "winws_restart_failed",
                        "message": f"❌ Restart failed: {msg}"
                    })
                # ═══════════════════════════════════════════════════════
                
                return  # ВЫХОДИМ, брутфорс не нужен

        # ═══════════════════════════════════════════════════════
        # ШАГ 2: Подбор новой стратегии (Brute Force)
        # Ни одна существующая стратегия не сработала
        # ═══════════════════════════════════════════════════════
        logger.info(f"No existing strategy found, starting brute force for {domain}")
        await add_log_entry({
            "type": "brute_force_start",
            "domain": domain,
            "message": f"🔍 Starting brute force strategy selection for {domain}"
        })

        bf_result = await self._brute_force_strategies(domain)
        logger.info(f"[analyzer] Brute force completed: status={bf_result.status}")

        if bf_result.status == BruteForceStatus.FOUND and bf_result.params:
            # Проверяем нет ли уже стратегии с такими параметрами
            existing_strategy = await self.storage.get_strategy_by_params(bf_result.params)

            if existing_strategy:
                # Используем существующую стратегию
                logger.info(f"Found existing strategy with same params: {existing_strategy.name}")
                strategy_name = existing_strategy.name
                strategy_id = existing_strategy.id

                await add_log_entry({
                    "type": "strategy_found",
                    "domain": domain,
                    "strategy": strategy_name,
                    "method": "by_params",
                    "message": f"✅ Found strategy by params: {strategy_name}"
                })
            else:
                # Создаём новую стратегию с уникальным именем
                strategy_name = f"strategy_{uuid4().hex[:12]}"
                strategy_id, was_created = await self.storage.create_strategy(
                    name=strategy_name,
                    params=bf_result.params,
                    description=bf_result.description or "Auto-created strategy"
                )

                logger.info(f"Created new strategy {strategy_name} for {domain}")

                await add_log_entry({
                    "type": "strategy_created",
                    "domain": domain,
                    "strategy": strategy_name,
                    "params": bf_result.params,
                    "message": f"✅ Created new strategy: {strategy_name}"
                })

            # Применяем стратегию с учётом возможной старой стратегии
            if current_strategy and current_strategy.id != strategy_id:
                # Переносим домен из старой стратегии в новую
                old_strategy_name = current_strategy.name
                success, msg = await self.executor.reassign_domain(
                    domain, old_strategy_name, strategy_name
                )
            else:
                # Домен не был на стратегии или та же стратегия
                success, msg = await self.executor.apply_strategy(domain, strategy_name)

            if success:
                # Добавляем домен к стратегии в БД
                await self.storage.assign_domain(domain, strategy_id)
                await self.storage.update_strategy_stats(strategy_id, success=True)
                await self.storage.log_event(StatEvent(
                    domain=domain,
                    event_type="applied",
                    strategy_id=strategy_id,
                    details=f"Created/matched strategy {bf_result.params}"
                ))
                logger.info(f"Strategy {strategy_name} applied to {domain}")

                # ═══════════════════════════════════════════════════════
                # АВТОМАТИЧЕСКИЙ ПОЛНЫЙ РЕСТАРТ WINWS СО ВСЕМИ СТРАТЕГИЯМИ
                # ═══════════════════════════════════════════════════════
                logger.info(f"[analyzer] Strategy applied → full winws restart...")

                # 1. Синхронизируем profiles из БД
                await self.nfqws_generator.sync_from_storage()

                # 2. Обновляем стратегию в nfqws-генераторе
                strategy_obj = await self.storage.get_strategy_by_id(strategy_id)
                if strategy_obj:
                    await self.nfqws_generator.update_profile(strategy_obj)

                # 3. Перегенерируем батник
                script_path = os.path.join(self.config.data_dir, "start-nfqws-auto.cmd")
                self.nfqws_generator.generate_windows_batch(script_path)

                # 4. Полный рестарт winws
                success, msg = await self.executor.restart_winws_full(self.nfqws_generator)

                if success:
                    await add_log_entry({
                        "type": "winws_full_restart",
                        "domain": domain,
                        "strategy": strategy_name,
                        "message": "✅ winws перезапущен с лучшей стратегией"
                    })
                    await self._clear_autohostlist()
                else:
                    await add_log_entry({
                        "type": "winws_restart_failed",
                        "message": f"❌ Restart failed: {msg}"
                    })
                # ═══════════════════════════════════════════════════════
            else:
                logger.warning(f"Executor failed to apply {strategy_name}: {msg}")
                await add_log_entry({
                    "type": "strategy_apply_failed",
                    "domain": domain,
                    "strategy": strategy_name,
                    "message": f"❌ Failed to apply strategy: {msg}"
                })
            
            # ═══════════════════════════════════════════════════════
            # ПЕРЕЗАПУСК WINWS В ЛЮБОМ СЛУЧАЕ
            # Даже если применение стратегии не удалось, winws должен работать
            # ═══════════════════════════════════════════════════════
            logger.info(f"[analyzer] Restarting winws with existing strategies...")
            
            # 1. Синхронизируем profiles из БД
            await self.nfqws_generator.sync_from_storage()
            
            # 2. Перегенерируем батник
            script_path = os.path.join(self.config.data_dir, "start-nfqws-auto.cmd")
            self.nfqws_generator.generate_windows_batch(script_path)
            
            # 3. Полный рестарт winws
            success, msg = await self.executor.restart_winws_full(self.nfqws_generator)
            
            if success:
                await add_log_entry({
                    "type": "winws_restarted",
                    "domain": domain,
                    "message": "✅ winws перезапущен"
                })
                await self._clear_autohostlist()
            else:
                await add_log_entry({
                    "type": "winws_restart_failed",
                    "message": f"❌ Restart failed: {msg}"
                })
            # ═══════════════════════════════════════════════════════
            
            return
        elif bf_result.status == BruteForceStatus.NO_DPI:
            logger.info(f"No DPI detected for {domain}, no strategy needed")
            await add_log_entry({
                "type": "no_dpi",
                "domain": domain,
                "message": f"ℹ️ No DPI detected during brute force"
            })
            # Завершаем без cooldown
            await self.storage.reset_fail_count(domain)
            await self.storage.clear_strategy_cooldown(domain)
            
            # ═══════════════════════════════════════════════════════
            # ПЕРЕЗАПУСК WINWS
            # Даже если DPI не обнаружен, winws должен работать для других доменов
            # ═══════════════════════════════════════════════════════
            logger.info(f"[analyzer] Restarting winws with existing strategies...")
            
            # 1. Синхронизируем profiles из БД
            await self.nfqws_generator.sync_from_storage()
            
            # 2. Перегенерируем батник
            script_path = os.path.join(self.config.data_dir, "start-nfqws-auto.cmd")
            self.nfqws_generator.generate_windows_batch(script_path)
            
            # 3. Полный рестарт winws
            success, msg = await self.executor.restart_winws_full(self.nfqws_generator)
            
            if success:
                await add_log_entry({
                    "type": "winws_restarted",
                    "domain": domain,
                    "message": "✅ winws перезапущен"
                })
                await self._clear_autohostlist()
            else:
                await add_log_entry({
                    "type": "winws_restart_failed",
                    "message": f"❌ Restart failed: {msg}"
                })
            # ═══════════════════════════════════════════════════════
            
            return

        # ШАГ 3: Ничего не найдено - cooldown + перезапуск winws с существующими стратегиями
        cooldown_minutes = self.config.strategy_cooldown_minutes
        logger.warning(f"No strategy found for {domain}, setting cooldown {cooldown_minutes} min")
        await add_log_entry({
            "type": "cooldown_set",
            "domain": domain,
            "duration": cooldown_minutes,
            "message": f"⏰ No strategy found, cooldown {cooldown_minutes} minutes"
        })
        await self.storage.set_strategy_cooldown(domain, cooldown_minutes, "No working strategy found")

        # ═══════════════════════════════════════════════════════
        # ПЕРЕЗАПУСК WINWS С СУЩЕСТВУЮЩИМИ СТРАТЕГИЯМИ
        # Даже если для данного домена стратегия не найдена, winws должен работать
        # с другими стратегиями для других доменов
        # ═══════════════════════════════════════════════════════
        logger.info(f"[analyzer] Brute force failed → restarting winws with existing strategies...")

        # 1. Синхронизируем profiles из БД (загружаем ВСЕ существующие стратегии)
        await self.nfqws_generator.sync_from_storage()

        # 2. Перегенерируем батник
        script_path = os.path.join(self.config.data_dir, "start-nfqws-auto.cmd")
        self.nfqws_generator.generate_windows_batch(script_path)

        # 3. Проверяем есть ли активные стратегии
        all_strategies = await self.storage.get_strategies_by_priority(min_success_rate=0.0)

        if all_strategies:
            # Есть стратегии - перезапускаем winws
            success, msg = await self.executor.restart_winws_full(self.nfqws_generator)

            if success:
                await add_log_entry({
                    "type": "winws_restarted_after_fail",
                    "domain": domain,
                    "message": "✅ winws перезапущен с существующими стратегиями (brute force не удался)"
                })
                # 4. Очищаем autohostlist
                await self._clear_autohostlist()
            else:
                await add_log_entry({
                    "type": "winws_restart_failed",
                    "message": f"❌ Restart after brute force failed: {msg}"
                })
        else:
            logger.warning("No strategies in DB, cannot restart winws")
            await add_log_entry({
                "type": "winws_no_strategies",
                "message": "⚠️ No strategies in database, winws not started"
            })
        # ═══════════════════════════════════════════════════════

    @profiler
    async def _clear_autohostlist(self) -> None:
        """
        Очистка файла autohostlist после применения стратегии
        
        ВАЖНО: Файл должен быть всегда пустым после обработки!
        Winws будет добавлять туда домены при детекции проблем,
        а Auto-Zapret будет их обрабатывать и очищать файл.
        """
        try:
            autohostlist_path = self.config.get_auto_hostlist_path()
            async with aiofiles.open(autohostlist_path, 'w', encoding='utf-8') as f:
                await f.write("")
            logger.debug("Cleared autohostlist file")
        except Exception as e:
            logger.debug(f"Failed to clear autohostlist: {e}")

    @profiler
    async def _test_strategy(self, domain: str, params: str) -> StrategyTestResult:
        """
        Тестирование стратегии на домене через Strategy Tester

        Использует реальное HTTPS тестирование с применением параметров через executor

        Args:
            domain: Домен для проверки
            params: Параметры zapret для тестирования

        Returns:
            StrategyTestResult со статусом теста
        """
        # Используем strategy_tester с АВТОМАТИЧЕСКИМ timeout из калибровки
        result = await self.strategy_tester.test_strategy(
            domain=domain,
            strategy_params=params,
            timeout=None  # Авто timeout из калибровки (mean_rtt + 33%)
        )
        
        # Конвертируем результат в старый формат для совместимости
        return StrategyTestResult(
            status=StrategyTestStatus(result.status.value),
            domain=result.domain,
            strategy_params=result.strategy_params,
            response_time=result.response_time_ms / 1000,  # Конвертируем в секунды
            error=result.error
        )

    @profiler
    def _check_fake_files(self) -> bool:
        """Проверка наличия файлов фейков (.bin)"""
        import os
        from pathlib import Path
        
        base_dir = Path(__file__).parent.parent
        fake_dirs = [
            base_dir / "bin" / "blockcheck" / "zapret" / "files" / "fake",
            base_dir / "bin" / "blockcheck" / "files" / "fake",
            base_dir / "bin" / "files" / "fake",
            base_dir / "files" / "fake",
        ]
        
        for fake_dir in fake_dirs:
            if fake_dir.exists():
                bins = list(fake_dir.glob("*.bin"))
                if bins:
                    logger.info(f"Found fake files in {fake_dir}: {len(bins)} files")
                    return True
        
        logger.debug("No fake .bin files found")
        return False

    @profiler
    async def _brute_force_strategies(self, domain: str) -> BruteForceResult:
        """
        Подбор стратегии перебором (blockcheck-style)

        Использует Strategy Generator для генерации 500+ стратегий
        и Strategy Tester для тестирования

        ВАЖНО: Только ОДИН brute-force за раз (winws не поддерживает параллельные стратегии)

        Returns:
            BruteForceResult со статусом и параметрами
        """
        logger.info(f"[brute_force] Starting brute force selection for {domain}")
        
        # Глобальная блокировка - только один brute-force за раз
        async with self._bruteforce_lock:
            self._current_bruteforce_domain = domain
            self._bruteforce_queue.append(domain)

            queue_pos = len(self._bruteforce_queue)
            if queue_pos > 1:
                logger.info(f"Domain {domain} is #{queue_pos} in brute-force queue")
                await add_log_entry({
                    "type": "brute_force_queued",
                    "domain": domain,
                    "queue_position": queue_pos,
                    "message": f"⏳ Domain queued for brute-force (position #{queue_pos})"
                })
            else:
                logger.info(f"Domain {domain} is first in brute-force queue, starting immediately")

            try:
                return await self._brute_force_strategies_impl(domain)
            finally:
                self._current_bruteforce_domain = None
                if domain in self._bruteforce_queue:
                    self._bruteforce_queue.remove(domain)
    
    @profiler
    async def _brute_force_strategies_impl(self, domain: str) -> BruteForceResult:
        """
        Реализация brute-force в стиле blockcheck.sh

        Использует BlockcheckStrategySelector для ленивой генерации стратегий
        в правильном порядке как в blockcheck.sh.

        Режимы работы (настраивается в config):
        - first_working: выход при первой найденной рабочей стратегии (быстрее)
        - all_best: тестирование всех стратегий, выбор лучшей по скорости (медленнее, но оптимальнее)

        Преимущества:
        - Стратегии генерируются в порядке blockcheck.sh (быстрее находит рабочую)
        - Адаптивный skip (пропускает ненужные тесты)
        - Ранний выход при успехе (quick mode)
        - FALLBACK: Если TLS12 не работает, пробуем QUIC и TLS13

        ВАЖНО: Telegram и многие современные сервисы используют QUIC (HTTP/3).
        Если блокировка на уровне QUIC - TLS стратегии не помогут!
        """
        logger.info(f"[brute_force_impl] Starting blockcheck-style brute force for {domain}")
        
        # Определяем режим работы
        brute_force_mode = self.config.brute_force_mode  # "first_working" или "all_best"
        logger.info(f"[brute_force_impl] Brute force mode: {brute_force_mode}")

        # ═══════════════════════════════════════════════════════
        # ПРОВЕРКА IP БЛОКИРОВКИ
        # Если IP заблокирован - DPI стратегии бесполезны!
        # ═══════════════════════════════════════════════════════
        ip_blocked, ip_reason = await self._check_ip_block(domain)
        if ip_blocked:
            logger.warning(f"[brute_force_impl] IP BLOCK detected for {domain}: {ip_reason}")
            await add_log_entry({
                "type": "ip_block_detected",
                "domain": domain,
                "reason": ip_reason,
                "message": f"🚫 IP block detected: {ip_reason}"
            })
            # Возвращаем NOT_FOUND - DPI стратегии не помогут
            return BruteForceResult(
                status=BruteForceStatus.NOT_FOUND,
                params=None,
                description=f"IP blocked: {ip_reason}"
            )

        # Проверяем QUIC поддержку ДО тестирования TLS
        has_quic = await self._check_quic_support(domain)
        logger.info(f"[brute_force_impl] QUIC support for {domain}: {has_quic}")

        # Определяем тип протокола на основе портов/данных
        protocol = self._detect_protocol(domain)
        logger.info(f"[brute_force_impl] Initial protocol: {protocol.value}")

        # Создаём selector
        selector = get_blockcheck_selector(
            protocol=protocol,
            scan_level=ScanLevel.QUICK if brute_force_mode == "first_working" else ScanLevel.STANDARD,
            ipv6=False,  # TODO: определять IPv6
            zapret_base=str(BASE_DIR / "bin" / "blockcheck" / "zapret")
        )

        # Состояние для адаптивного тестирования
        state = SelectorState()

        # Подсчитываем реальное количество стратегий
        total_strategies = selector.count_strategies()
        logger.info(f"[brute_force_impl] Total strategies to test: ~{total_strategies}")

        # Инициализируем прогресс
        brute_force_progress[domain] = {
            "domain": domain,
            "total": total_strategies,  # Реальное количество
            "current": 0,
            "status": "in_progress",
            "started": datetime.now().isoformat(),
            "current_strategy": None,
            "current_phase": 0,
            "mode": brute_force_mode,
        }

        await add_log_entry({
            "type": "brute_force_start",
            "domain": domain,
            "protocol": protocol.value,
            "mode": brute_force_mode,
            "message": f"🔍 Starting blockcheck-style brute force for {domain} ({protocol.value}, mode={brute_force_mode})"
        })

        # Тестируем стратегии в порядке blockcheck.sh
        found_strategies = []  # Список всех работающих стратегий (для all_best)
        found_strategy = None  # Для first_working
        tested_count = 0
        last_phase = 0

        for strategy in selector.generate(state):
            tested_count += 1
            strategy_params = strategy.params

            # Проверяем не остановлен ли перебор пользователем
            if brute_force_progress.get(domain, {}).get("status") == "stopped_by_user":
                logger.info(f"[brute_force_impl] Brute force stopped by user at #{tested_count}")
                brute_force_progress[domain]["completed"] = datetime.now().isoformat()
                return BruteForceResult(status=BruteForceStatus.NOT_FOUND, description="Остановлено пользователем")

            # Логируем смену фазы
            if strategy.phase != last_phase:
                last_phase = strategy.phase
                logger.info(f"[brute_force_impl] === PHASE {strategy.phase}: {strategy.description} ===")
                brute_force_progress[domain]["current_phase"] = strategy.phase

            logger.debug(f"[brute_force_impl] Testing #{tested_count} (phase {strategy.phase}): {strategy_params[:60]}...")

            # Обновляем прогресс
            brute_force_progress[domain]["current"] = tested_count
            brute_force_progress[domain]["current_strategy"] = strategy_params

            # Тестируем стратегию
            result = await self.strategy_tester.test_strategy(
                domain=domain,
                strategy_params=strategy_params
            )

            # Проверяем результат
            if result.status == TesterStatus.WORKS:
                logger.info(f"[brute_force_impl] ✅ FOUND working strategy at #{tested_count} (phase {strategy.phase}): {strategy_params[:60]}")
                
                strategy_result = {
                    "result": result,
                    "strategy": strategy,
                    "phase": strategy.phase,
                    "response_time": result.response_time_ms
                }
                
                if brute_force_mode == "first_working":
                    # Немедленный выход при первой рабочей
                    found_strategy = result
                    found_strategy.details["strategy_name"] = strategy.name
                    found_strategy.details["phase"] = strategy.phase
                    break
                else:  # all_best
                    # Продолжаем тестирование для поиска лучшей
                    found_strategies.append(strategy_result)
                    logger.info(f"[brute_force_impl] Collected {len(found_strategies)} working strategies, continuing...")

            if result.status == TesterStatus.NO_DPI:
                # DPI не обнаружен - стратегия не нужна
                logger.info(f"[brute_force_impl] No DPI detected for {domain}, stopping brute force")
                brute_force_progress[domain]["status"] = "no_dpi"
                brute_force_progress[domain]["completed"] = datetime.now().isoformat()

                await add_log_entry({
                    "type": "brute_force_no_dpi",
                    "domain": domain,
                    "message": f"ℹ️ No DPI detected, strategy not needed"
                })

                return BruteForceResult(status=BruteForceStatus.NO_DPI)

            # Обновляем состояние для адаптивного skip
            update_selector_state(state, strategy, success=False)

            # Логируем прогресс каждые 10 стратегий
            if tested_count % 10 == 0:
                logger.info(f"[brute_force_impl] Progress: {tested_count} strategies tested (phase {strategy.phase})")

                await add_log_entry({
                    "type": "brute_force_progress",
                    "domain": domain,
                    "progress": tested_count,
                    "phase": strategy.phase,
                    "message": f"Brute force progress: {tested_count} tested (phase {strategy.phase})"
                })

        # Завершаем прогресс
        brute_force_progress[domain]["completed"] = datetime.now().isoformat()

        # ═══════════════════════════════════════════════════════
        # ОБРАБОТКА РЕЗУЛЬТАТОВ
        # ═══════════════════════════════════════════════════════
        
        if brute_force_mode == "first_working" and found_strategy:
            # Режим first_working: возвращаем первую найденную
            strategy_params = found_strategy.strategy_params
            phase = found_strategy.details.get("phase", "?")
            name = found_strategy.details.get("strategy_name", "unknown")

            logger.info(f"[brute_force_impl] ✅ Found working strategy: {strategy_params}")

            brute_force_progress[domain]["status"] = "success"
            brute_force_progress[domain]["current_strategy"] = strategy_params

            await add_log_entry({
                "type": "brute_force_success",
                "domain": domain,
                "params": strategy_params,
                "phase": phase,
                "tested_count": tested_count,
                "message": f"✅ Found working strategy at phase {phase} (tested {tested_count}): {strategy_params}"
            })

            return BruteForceResult(
                status=BruteForceStatus.FOUND,
                params=strategy_params,
                description=f"Phase {phase} strategy: {name}"
            )
        
        elif brute_force_mode == "all_best" and found_strategies:
            # Режим all_best: выбираем лучшую по скорости (min response_time)
            found_strategies.sort(key=lambda x: x["response_time"])
            best = found_strategies[0]
            
            strategy_params = best["result"].strategy_params
            phase = best["phase"]
            name = best["strategy"].name
            response_time = best["response_time"]
            
            logger.info(f"[brute_force_impl] 🏆 Best strategy from {len(found_strategies)} found: {strategy_params} (RTT: {response_time}ms)")
            
            brute_force_progress[domain]["status"] = "success"
            brute_force_progress[domain]["current_strategy"] = strategy_params
            brute_force_progress[domain]["total_tested"] = tested_count
            brute_force_progress[domain]["total_found"] = len(found_strategies)

            await add_log_entry({
                "type": "brute_force_success",
                "domain": domain,
                "params": strategy_params,
                "phase": phase,
                "tested_count": tested_count,
                "found_count": len(found_strategies),
                "response_time_ms": response_time,
                "message": f"🏆 Best strategy from {len(found_strategies)} found (phase {phase}, RTT: {response_time}ms): {strategy_params}"
            })

            return BruteForceResult(
                status=BruteForceStatus.FOUND,
                params=strategy_params,
                description=f"Best of {len(found_strategies)} strategies (phase {phase}, RTT: {response_time}ms): {name}"
            )

        # Ничего не найдено для TLS
        logger.warning(f"[brute_force_impl] No TLS strategy found after {tested_count} attempts for {domain}")

        # ═══════════════════════════════════════════════════════
        # FALLBACK QUIC — ТЕСТИРУЕМ ЧЕРЕЗ curl --http3
        # Если TLS не сработал, пробуем QUIC/HTTP3
        # ═══════════════════════════════════════════════════════
        if has_quic:
            logger.info(f"[brute_force_impl] Trying QUIC fallback for {domain}...")
            quic_result = await self._try_quic_fallback(domain, has_quic)
            if quic_result and quic_result.status == BruteForceStatus.FOUND:
                return quic_result

        brute_force_progress[domain]["status"] = "failed"
        brute_force_progress[domain]["completed"] = datetime.now().isoformat()

        await add_log_entry({
            "type": "brute_force_failed",
            "domain": domain,
            "total_attempts": tested_count,
            "message": f"❌ No working strategy found after {tested_count} TLS attempts"
        })

        return BruteForceResult(status=BruteForceStatus.NOT_FOUND)

    @profiler
    def _detect_protocol(self, domain: str) -> ProtocolType:
        """
        Определение типа протокола для домена
        
        По умолчанию возвращаем TLS12 как самый распространённый случай.
        QUIC определяется по наличию Alt-Svc заголовка (проверяется в strategy_tester).
        """
        # TODO: Добавить логику определения протокола
        # - QUIC: проверить Alt-Svc заголовок
        # - HTTP: если порт 80
        # - TLS13: если сервер поддерживает только TLS 1.3
        
        return ProtocolType.TLS12

    @profiler
    async def _check_quic_support(self, domain: str) -> bool:
        """
        Проверка поддержки QUIC для домена
        
        Проверяет:
        1. Alt-Svc заголовок в HTTPS ответе
        2. QUIC Initial на порту 443/UDP
        
        Returns:
            True если домен поддерживает QUIC/HTTP3
        """
        import socket
        import ssl
        
        try:
            # Быстрая проверка через Alt-Svc заголовок
            context = ssl.create_default_context()
            context.set_ciphers('DEFAULT')
            
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Простой HEAD запрос
                    ssock.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
                    response = ssock.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Ищем Alt-Svc с h3
                    if 'alt-svc:' in response.lower():
                        alt_svc_line = [line for line in response.split('\n') if 'alt-svc:' in line.lower()]
                        if alt_svc_line:
                            if 'h3=' in alt_svc_line[0] or 'h3-' in alt_svc_line[0]:
                                logger.info(f"[quic_check] {domain} advertises HTTP/3 via Alt-Svc")
                                return True
            
            logger.debug(f"[quic_check] {domain} does not advertise HTTP/3")
            return False
            
        except Exception as e:
            logger.debug(f"[quic_check] Failed to check QUIC for {domain}: {e}")
            # Если не можем проверить - предполагаем что QUIC есть (современные сайты)
            return True  # Безопасное предположение для современных сайтов

    @profiler
    async def _check_ip_block(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Проверка IP блокировки домена
        
        Если IP заблокирован на уровне провайдера - DPI стратегии не помогут!
        
        Returns:
            (is_blocked, reason) - (True если IP заблокирован, причина)
        """
        import socket
        
        try:
            # Резолвим домен
            addr_info = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                return True, "DNS failed - domain does not resolve"
            
            ip = addr_info[0][4][0]
            logger.info(f"[ip_check] {domain} resolves to {ip}")
            
            # Проверяем TCP соединение БЕЗ DPI обхода
            # Если соединение устанавливается - IP не заблокирован
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((ip, 443))
                sock.close()
                logger.info(f"[ip_check] {domain} ({ip}) - TCP connection OK, IP not blocked")
                return False, None  # IP доступен
            except socket.timeout:
                sock.close()
                logger.warning(f"[ip_check] {domain} ({ip}) - TCP timeout, possible IP block")
                return True, f"IP {ip} timeout - possible IP block"
            except ConnectionRefusedError:
                sock.close()
                return True, f"IP {ip} connection refused"
            except Exception as e:
                sock.close()
                return True, f"IP {ip} error: {e}"
                
        except socket.gaierror:
            return True, "DNS resolution failed"
        except Exception as e:
            logger.debug(f"[ip_check] Error checking {domain}: {e}")
            return False, None  # Не уверены, продолжаем тестирование

    @profiler
    async def _try_quic_fallback(self, domain: str, has_quic: bool) -> Optional[BruteForceResult]:
        """
        Fallback на QUIC стратегии если TLS не работает
        
        Telegram, YouTube, Google и многие современные сервисы используют QUIC.
        Если блокировка на уровне QUIC - TLS стратегии бесполезны.
        
        Args:
            domain: Домен для тестирования
            has_quic: Поддерживает ли домен QUIC
            
        Returns:
            BruteForceResult если найдена QUIC стратегия, иначе None
        """
        if not has_quic:
            logger.info(f"[quic_fallback] {domain} does not support QUIC, skipping")
            return None
        
        logger.info(f"[quic_fallback] Trying QUIC strategies for {domain}...")
        
        await add_log_entry({
            "type": "brute_force_start",
            "domain": domain,
            "protocol": "quic",
            "message": f"🔄 TLS failed, trying QUIC for {domain}"
        })
        
        # Создаём selector для QUIC
        selector = get_blockcheck_selector(
            protocol=ProtocolType.QUIC,
            scan_level=ScanLevel.QUICK,
            ipv6=False,
            zapret_base=str(BASE_DIR / "bin" / "blockcheck" / "zapret")
        )
        
        state = SelectorState()
        tested_count = 0
        last_phase = 0
        
        brute_force_progress[domain] = {
            "domain": domain,
            "total": "~50",
            "current": 0,
            "status": "in_progress",
            "started": datetime.now().isoformat(),
            "current_strategy": None,
            "current_phase": 0,
        }
        
        for strategy in selector.generate(state):
            tested_count += 1
            strategy_params = strategy.params
            
            if strategy.phase != last_phase:
                last_phase = strategy.phase
                logger.info(f"[quic_fallback] === PHASE {strategy.phase}: {strategy.description} ===")
            
            brute_force_progress[domain]["current"] = tested_count
            brute_force_progress[domain]["current_strategy"] = strategy_params
            
            # Тестируем QUIC стратегию (is_quic=True для UDP-only профиля)
            result = await self.strategy_tester.test_strategy(
                domain=domain,
                strategy_params=strategy_params,
                is_quic=True  # Важно: QUIC стратегии используют только UDP
            )
            
            if result.status == TesterStatus.WORKS:
                logger.info(f"[quic_fallback] ✅ FOUND QUIC strategy: {strategy_params}")
                
                brute_force_progress[domain]["status"] = "success"
                brute_force_progress[domain]["completed"] = datetime.now().isoformat()
                
                await add_log_entry({
                    "type": "brute_force_success",
                    "domain": domain,
                    "protocol": "quic",
                    "params": strategy_params,
                    "tested_count": tested_count,
                    "message": f"✅ Found QUIC strategy (tested {tested_count}): {strategy_params}"
                })
                
                return BruteForceResult(
                    status=BruteForceStatus.FOUND,
                    params=strategy_params,
                    description=f"QUIC strategy: {strategy.name}"
                )
            
            if tested_count % 10 == 0:
                await add_log_entry({
                    "type": "brute_force_progress",
                    "domain": domain,
                    "protocol": "quic",
                    "progress": tested_count,
                    "phase": strategy.phase,
                    "message": f"QUIC brute force: {tested_count} tested"
                })
        
        logger.warning(f"[quic_fallback] No QUIC strategy found for {domain}")
        brute_force_progress[domain]["status"] = "quic_failed"
        
        return None

    @profiler
    async def get_domain_status(self, domain: str) -> Dict[str, Any]:
        """Получение статуса домена"""
        domain = normalize_domain(domain)
        domain_info = await self.storage.get_domain(domain)
        cooldown = await self.storage.get_strategy_cooldown(domain)

        if domain_info:
            strategy = await self.storage.get_strategy_by_id(domain_info.strategy_id)
            return {
                "domain": domain,
                "has_strategy": True,
                "strategy": strategy.name if strategy else f"ID:{domain_info.strategy_id}",
                "fail_count": domain_info.fail_count,
                "is_active": bool(domain_info.is_active),
                "cooldown_until": None
            }
        elif cooldown:
            return {
                "domain": domain,
                "has_strategy": False,
                "cooldown_until": cooldown,
                "is_active": False
            }
        else:
            return {
                "domain": domain,
                "has_strategy": False,
                "is_active": False,
                "cooldown_until": None
            }