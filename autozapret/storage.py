"""
Модуль хранения данных (SQLite)
"""

import aiosqlite
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

from .helpers import normalize_domain, canonicalize_params
from .utils.profiler import get_profiler

profiler = get_profiler("storage")

logger = logging.getLogger(__name__)


@dataclass
class Strategy:
    """Стратегия обхода DPI"""
    id: Optional[int] = None
    name: str = ""  # "strategy_1", "strategy_2"...
    description: str = ""
    zapret_params: str = ""  # "--dpi-desync=fake,multisplit"
    params_canonical: str = ""  # Canonical форма параметров
    priority: int = 99  # Для сортировки при проверке
    created_at: Optional[str] = None
    # Статистика
    domains_count: int = 0  # Сколько доменов использует эту стратегию
    success_rate: float = 0.0  # 0.0 - 1.0
    total_checks: int = 0  # Сколько раз проверяли
    last_success: Optional[str] = None


@dataclass
class Domain:
    domain: str = ""
    strategy_id: int = 0
    added_at: Optional[str] = None
    fail_count: int = 0
    last_fail: Optional[str] = None
    is_active: bool = True


@dataclass
class StatEvent:
    id: Optional[int] = None
    domain: str = ""
    timestamp: Optional[str] = None
    event_type: str = ""  # 'fail', 'success', 'applied', 'removed'
    strategy_id: int = 0
    details: str = ""


class Storage:
    """SQLite хранилище для Auto-Zapret"""
    
    @profiler
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    @profiler
    async def connect(self) -> None:
        """Подключение к базе данных и создание таблиц"""
        # Создаём директорию если не существует
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        
        # Включаем foreign keys
        await self._db.execute("PRAGMA foreign_keys = ON")

        # Создаём таблицы
        await self._create_tables()

        # Затем добавляем новые колонки если их нет (для миграции)
        await self._migrate_tables()
    
    @profiler
    async def _migrate_tables(self) -> None:
        """Добавление новых колонок в существующие таблицы"""
        # Проверяем и добавляем колонки в strategies
        cursor = await self._db.execute("PRAGMA table_info(strategies)")
        columns = [row[1] for row in await cursor.fetchall()]

        new_columns = [
            ("domains_count", "INTEGER DEFAULT 0"),
            ("success_rate", "REAL DEFAULT 0.0"),
            ("total_checks", "INTEGER DEFAULT 0"),
            ("last_success", "TIMESTAMP"),
            ("params_canonical", "TEXT DEFAULT ''")
        ]

        for col_name, col_type in new_columns:
            if col_name not in columns:
                await self._db.execute(f"ALTER TABLE strategies ADD COLUMN {col_name} {col_type}")
                logger.info(f"Added column {col_name} to strategies table")

        # Создаём таблицу cooldowns если нет
        cursor = await self._db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='strategy_cooldowns'")
        if not await cursor.fetchone():
            await self._db.execute("""
                CREATE TABLE IF NOT EXISTS strategy_cooldowns (
                    domain TEXT PRIMARY KEY,
                    until TIMESTAMP NOT NULL,
                    reason TEXT DEFAULT ''
                )
            """)
            await self._db.execute("CREATE INDEX IF NOT EXISTS idx_cooldowns_until ON strategy_cooldowns(until)")
            logger.info("Created strategy_cooldowns table")

        # Создаём индекс для params_canonical если нет (partial index для непустых значений)
        cursor = await self._db.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_strategies_params_canonical'")
        if not await cursor.fetchone():
            await self._db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_strategies_params_canonical ON strategies(params_canonical) WHERE params_canonical != ''")
            logger.info("Created index idx_strategies_params_canonical")

        await self._db.commit()
    
    @profiler
    async def close(self) -> None:
        """Закрытие подключения"""
        if self._db:
            await self._db.close()
            self._db = None
    
    @profiler
    async def _create_tables(self) -> None:
        """Создание схемы базы данных (базовая версия без новых колонок)"""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS strategies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT DEFAULT '',
                zapret_params TEXT DEFAULT '',
                priority INTEGER DEFAULT 99,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                strategy_id INTEGER NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                fail_count INTEGER DEFAULT 0,
                last_fail TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (strategy_id) REFERENCES strategies(id)
            );

            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                strategy_id INTEGER DEFAULT 0,
                details TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS strategy_cooldowns (
                domain TEXT PRIMARY KEY,
                until TIMESTAMP NOT NULL,
                reason TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_stats_domain ON stats(domain);
            CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON stats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_domains_strategy ON domains(strategy_id);
            CREATE INDEX IF NOT EXISTS idx_cooldowns_until ON strategy_cooldowns(until);
        """)
        await self._db.commit()
    
    # ==================== Strategy CRUD ====================

    @profiler
    async def add_strategy(self, strategy: Strategy) -> Optional[int]:
        """Добавление стратегии (INSERT OR UPDATE без DELETE)"""
        async with self._lock:
            # Нормализуем параметры
            params_canonical = canonicalize_params(strategy.zapret_params)

            # Проверяем существует ли стратегия
            cursor = await self._db.execute(
                "SELECT id FROM strategies WHERE name = ?", (strategy.name,)
            )
            existing = await cursor.fetchone()

            if existing:
                # Обновляем существующую (не трогаем id, created_at, статистику)
                await self._db.execute(
                    """UPDATE strategies SET
                       description = ?, zapret_params = ?, params_canonical = ?, priority = ?
                       WHERE name = ?""",
                    (strategy.description, strategy.zapret_params, params_canonical,
                     strategy.priority, strategy.name)
                )
                await self._db.commit()
                return existing["id"]
            else:
                # Проверяем нет ли стратегии с такими же параметрами (conflict by params_canonical)
                if params_canonical:
                    cursor = await self._db.execute(
                        "SELECT id FROM strategies WHERE params_canonical = ? AND params_canonical != ''",
                        (params_canonical,)
                    )
                    existing_by_params = await cursor.fetchone()
                    if existing_by_params:
                        logger.warning(f"Strategy with same params already exists with ID {existing_by_params['id']}")
                        # Возвращаем ID существующей стратегии вместо создания дубликата
                        return existing_by_params["id"]

                # Создаём новую
                cursor = await self._db.execute(
                    """INSERT INTO strategies
                       (name, description, zapret_params, params_canonical, priority, created_at,
                        domains_count, success_rate, total_checks, last_success)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (strategy.name, strategy.description,
                     strategy.zapret_params, params_canonical, strategy.priority,
                     strategy.created_at or datetime.now().isoformat(),
                     strategy.domains_count, strategy.success_rate,
                     strategy.total_checks, strategy.last_success)
                )
                await self._db.commit()
                return cursor.lastrowid

    @profiler
    async def update_strategy(self, strategy: Strategy) -> bool:
        """Обновление существующей стратегии"""
        async with self._lock:
            params_canonical = canonicalize_params(strategy.zapret_params)
            
            # Проверяем нет ли другой стратегии с такими же параметрами
            if params_canonical:
                cursor = await self._db.execute(
                    """SELECT id FROM strategies 
                       WHERE params_canonical = ? AND params_canonical != '' AND name != ?""",
                    (params_canonical, strategy.name)
                )
                existing_by_params = await cursor.fetchone()
                if existing_by_params:
                    logger.warning(f"Cannot update {strategy.name}: another strategy already has these params")
                    return False
            
            cursor = await self._db.execute(
                """UPDATE strategies SET
                   description = ?, zapret_params = ?, params_canonical = ?, priority = ?
                   WHERE name = ?""",
                (strategy.description, strategy.zapret_params, params_canonical,
                 strategy.priority, strategy.name)
            )
            await self._db.commit()
            return cursor.rowcount > 0

    @profiler
    async def create_strategy(self, name: str, params: str, description: str = "") -> Tuple[int, bool]:
        """
        Создание новой стратегии с возвратом статуса
        
        Args:
            name: Имя стратегии
            params: Параметры zapret
            description: Описание
            
        Returns:
            Tuple[int, bool]: (strategy_id, was_created)
            - was_created=True: стратегия создана
            - was_created=False: стратегия уже существовала (по имени или params)
        """
        strategy = Strategy(
            name=name,
            description=description,
            zapret_params=params,
            priority=99,
            domains_count=0,
            success_rate=0.0,
            total_checks=0
        )
        
        async with self._lock:
            params_canonical = canonicalize_params(params)
            
            # Проверяем существует ли стратегия с таким именем
            cursor = await self._db.execute(
                "SELECT id FROM strategies WHERE name = ?", (name,)
            )
            existing_by_name = await cursor.fetchone()
            
            if existing_by_name:
                # Стратегия уже существует по имени
                logger.info(f"Strategy '{name}' already exists (id={existing_by_name['id']})")
                return existing_by_name["id"], False
            
            # Проверяем нет ли стратегии с такими же параметрами
            if params_canonical:
                cursor = await self._db.execute(
                    "SELECT id, name FROM strategies WHERE params_canonical = ? AND params_canonical != ''",
                    (params_canonical,)
                )
                existing_by_params = await cursor.fetchone()
                if existing_by_params:
                    # Стратегия уже существует по параметрам
                    logger.info(f"Strategy with same params already exists: '{existing_by_params['name']}' (id={existing_by_params['id']})")
                    return existing_by_params["id"], False
            
            # Создаём новую стратегию
            cursor = await self._db.execute(
                """INSERT INTO strategies
                   (name, description, zapret_params, params_canonical, priority, created_at,
                    domains_count, success_rate, total_checks, last_success)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, description, params, params_canonical, 99,
                 datetime.now().isoformat(), 0, 0.0, 0, None)
            )
            await self._db.commit()
            return cursor.lastrowid, True

    @profiler
    async def get_strategy(self, name: str) -> Optional[Strategy]:
        """Получение стратегии по имени"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM strategies WHERE name = ?", (name,)
            )
            row = await cursor.fetchone()
            return Strategy(**dict(row)) if row else None
    
    @profiler
    async def get_strategy_by_id(self, id: int) -> Optional[Strategy]:
        """Получение стратегии по ID"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM strategies WHERE id = ?", (id,)
            )
            row = await cursor.fetchone()
            return Strategy(**dict(row)) if row else None

    @profiler
    async def get_strategy_by_params(self, params: str) -> Optional[Strategy]:
        """Получение стратегии по параметрам zapret"""
        async with self._lock:
            # Используем canonical форму для поиска
            params_canonical = canonicalize_params(params)

            cursor = await self._db.execute(
                "SELECT * FROM strategies WHERE params_canonical = ?",
                (params_canonical,)
            )
            row = await cursor.fetchone()
            return Strategy(**dict(row)) if row else None

    @profiler
    async def list_strategies(self) -> List[Strategy]:
        """Список всех стратегий"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM strategies ORDER BY priority ASC"
            )
            rows = await cursor.fetchall()
            return [Strategy(**dict(row)) for row in rows]
    
    @profiler
    async def delete_strategy(self, name: str) -> bool:
        """Удаление стратегии"""
        async with self._lock:
            # Проверяем есть ли домены на этой стратегии
            cursor = await self._db.execute(
                "SELECT domain FROM domains WHERE strategy_id = (SELECT id FROM strategies WHERE name = ?) LIMIT 1",
                (name,)
            )
            has_domains = await cursor.fetchone() is not None

            if has_domains:
                # Нельзя удалить стратегию с доменами
                return False

            # Удаляем стратегию и проверяем реальный rowcount
            cursor = await self._db.execute(
                "DELETE FROM strategies WHERE name = ?", (name,)
            )
            await self._db.commit()
            return cursor.rowcount > 0
    
    # ==================== Domain CRUD ====================

    @profiler
    async def assign_domain(self, domain: str, strategy_id: int, preserve_history: bool = True) -> bool:
        """
        Привязка домена к стратегии

        Args:
            domain: Домен
            strategy_id: ID стратегии
            preserve_history: Сохранять историю (fail_count, last_fail)
        """
        async with self._lock:
            # Нормализуем домен через utils
            domain = normalize_domain(domain)

            # Проверяем существует ли стратегия
            cursor = await self._db.execute(
                "SELECT id FROM strategies WHERE id = ?", (strategy_id,)
            )
            if not await cursor.fetchone():
                logger.warning(f"Attempted to assign domain {domain} to non-existent strategy {strategy_id}")
                return False

            # Проверяем существует ли домен
            cursor = await self._db.execute(
                "SELECT strategy_id, fail_count, last_fail, is_active FROM domains WHERE domain = ?",
                (domain,)
            )
            existing = await cursor.fetchone()

            if existing:
                old_strategy_id = existing["strategy_id"]
                was_active = bool(existing["is_active"])

                # Если стратегия не изменилась
                if old_strategy_id == strategy_id:
                    if not was_active:
                        # Реактивируем домен
                        await self._db.execute(
                            "UPDATE domains SET is_active = 1 WHERE domain = ?",
                            (domain,)
                        )
                        # Увеличиваем domains_count только если был неактивен
                        await self._db.execute(
                            "UPDATE strategies SET domains_count = domains_count + 1 WHERE id = ?",
                            (strategy_id,)
                        )
                    await self._db.commit()
                    return True

                # Обновляем стратегию
                if preserve_history:
                    # Сохраняем fail_count и last_fail
                    await self._db.execute(
                        """UPDATE domains SET
                           strategy_id = ?, is_active = 1
                           WHERE domain = ?""",
                        (strategy_id, domain)
                    )
                else:
                    # Сбрасываем историю
                    await self._db.execute(
                        """UPDATE domains SET
                           strategy_id = ?, fail_count = 0, last_fail = NULL, is_active = 1
                           WHERE domain = ?""",
                        (strategy_id, domain)
                    )

                # Обновляем domains_count: уменьшаем у старой только если был активен
                if was_active:
                    await self._db.execute(
                        "UPDATE strategies SET domains_count = CASE WHEN domains_count > 0 THEN domains_count - 1 ELSE 0 END WHERE id = ?",
                        (old_strategy_id,)
                    )
                # Увеличиваем у новой
                await self._db.execute(
                    "UPDATE strategies SET domains_count = domains_count + 1 WHERE id = ?",
                    (strategy_id,)
                )
            else:
                # Новый домен
                await self._db.execute(
                    """INSERT INTO domains
                       (domain, strategy_id, added_at, fail_count, last_fail, is_active)
                       VALUES (?, ?, ?, 0, NULL, 1)""",
                    (domain, strategy_id, datetime.now().isoformat())
                )

                # Обновляем domains_count
                await self._db.execute(
                    "UPDATE strategies SET domains_count = domains_count + 1 WHERE id = ?",
                    (strategy_id,)
                )

            await self._db.commit()
            return True
    
    @profiler
    async def get_domain(self, domain: str) -> Optional[Domain]:
        """Получение информации о домене"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                "SELECT * FROM domains WHERE domain = ?", (domain,)
            )
            row = await cursor.fetchone()
            return Domain(**dict(row)) if row else None

    @profiler
    async def get_domain_strategy(self, domain: str) -> Optional[Strategy]:
        """Получение стратегии для домена (только если домен активен)"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                """SELECT s.* FROM domains d
                   JOIN strategies s ON d.strategy_id = s.id
                   WHERE d.domain = ? AND d.is_active = 1""", (domain,)
            )
            row = await cursor.fetchone()
            return Strategy(**dict(row)) if row else None
    
    @profiler
    async def list_domains(self, active_only: bool = True) -> List[Domain]:
        """Список всех доменов"""
        async with self._lock:
            if active_only:
                cursor = await self._db.execute(
                    "SELECT * FROM domains WHERE is_active = 1 ORDER BY domain"
                )
            else:
                cursor = await self._db.execute(
                    "SELECT * FROM domains ORDER BY domain"
                )
            rows = await cursor.fetchall()
            return [Domain(**dict(row)) for row in rows]

    @profiler
    async def list_domains_for_strategy(self, strategy_name: str) -> List[Domain]:
        """Список доменов для стратегии"""
        async with self._lock:
            cursor = await self._db.execute(
                """SELECT d.* FROM domains d
                   JOIN strategies s ON d.strategy_id = s.id
                   WHERE s.name = ? ORDER BY d.domain""",
                (strategy_name,)
            )
            rows = await cursor.fetchall()
            return [Domain(**dict(row)) for row in rows]

    @profiler
    async def set_fail_count(self, domain: str, fail_count: int, last_fail: Optional[str] = None) -> bool:
        """Установка абсолютного значения счётчика неудач домена"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                """UPDATE domains
                   SET fail_count = ?, last_fail = ?
                   WHERE domain = ?""",
                (fail_count, last_fail or datetime.now().isoformat(), domain)
            )
            await self._db.commit()
            return cursor.rowcount > 0

    @profiler
    async def increment_fail_count(self, domain: str) -> int:
        """Увеличение счётчика неудач домена"""
        async with self._lock:
            domain = normalize_domain(domain)
            await self._db.execute(
                """UPDATE domains
                   SET fail_count = fail_count + 1, last_fail = ?
                   WHERE domain = ?""",
                (datetime.now().isoformat(), domain)
            )
            await self._db.commit()

            # Получаем новое значение
            cursor = await self._db.execute(
                "SELECT fail_count FROM domains WHERE domain = ?", (domain,)
            )
            row = await cursor.fetchone()
            return row["fail_count"] if row else 0

    @profiler
    async def reset_fail_count(self, domain: str) -> bool:
        """Сброс счётчика неудач"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                "UPDATE domains SET fail_count = 0, last_fail = NULL WHERE domain = ?",
                (domain,)
            )
            await self._db.commit()
            return cursor.rowcount > 0

    @profiler
    async def remove_domain(self, domain: str) -> bool:
        """Удаление домена (деактивация)"""
        async with self._lock:
            domain = normalize_domain(domain)

            # Получаем текущий домен для обновления domains_count
            cursor = await self._db.execute(
                "SELECT strategy_id, is_active FROM domains WHERE domain = ?", (domain,)
            )
            row = await cursor.fetchone()

            if row and row["is_active"]:
                # Уменьшаем domains_count у стратегии (безопасно)
                await self._db.execute(
                    "UPDATE strategies SET domains_count = CASE WHEN domains_count > 0 THEN domains_count - 1 ELSE 0 END WHERE id = ?",
                    (row["strategy_id"],)
                )

            await self._db.execute(
                "UPDATE domains SET is_active = 0 WHERE domain = ?", (domain,)
            )
            await self._db.commit()
            return row is not None

    @profiler
    async def hard_remove_domain(self, domain: str) -> bool:
        """Полное удаление домена из базы"""
        async with self._lock:
            domain = normalize_domain(domain)

            # Получаем текущий домен для обновления domains_count
            cursor = await self._db.execute(
                "SELECT strategy_id, is_active FROM domains WHERE domain = ?", (domain,)
            )
            row = await cursor.fetchone()

            if row and row["is_active"]:
                # Уменьшаем domains_count у стратегии (безопасно)
                await self._db.execute(
                    "UPDATE strategies SET domains_count = CASE WHEN domains_count > 0 THEN domains_count - 1 ELSE 0 END WHERE id = ?",
                    (row["strategy_id"],)
                )

            await self._db.execute(
                "DELETE FROM domains WHERE domain = ?", (domain,)
            )
            await self._db.commit()
            return row is not None
    
    # ==================== Stats CRUD ====================
    
    @profiler
    async def log_event(self, event: StatEvent) -> Optional[int]:
        """Логирование события"""
        async with self._lock:
            # Нормализуем domain если есть
            if event.domain:
                event.domain = normalize_domain(event.domain)

            cursor = await self._db.execute(
                """INSERT INTO stats (domain, timestamp, event_type, strategy_id, details)
                   VALUES (?, ?, ?, ?, ?)""",
                (event.domain, event.timestamp or datetime.now().isoformat(),
                 event.event_type, event.strategy_id, event.details)
            )
            await self._db.commit()
            return cursor.lastrowid
    
    @profiler
    async def get_stats(self, domain: Optional[str] = None,
                        limit: int = 100) -> List[StatEvent]:
        """Получение статистики"""
        async with self._lock:
            if domain:
                domain = normalize_domain(domain)
                cursor = await self._db.execute(
                    """SELECT * FROM stats WHERE domain = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (domain, limit)
                )
            else:
                cursor = await self._db.execute(
                    "SELECT * FROM stats ORDER BY timestamp DESC LIMIT ?", (limit,)
                )
            rows = await cursor.fetchall()
            return [StatEvent(**dict(row)) for row in rows]
    
    @profiler
    async def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Статистика по домену"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                """SELECT
                   COUNT(*) as total_events,
                   COALESCE(SUM(CASE WHEN event_type = 'fail' THEN 1 ELSE 0 END), 0) as fails,
                   COALESCE(SUM(CASE WHEN event_type = 'success' THEN 1 ELSE 0 END), 0) as successes,
                   COALESCE(SUM(CASE WHEN event_type = 'applied' THEN 1 ELSE 0 END), 0) as applied
                   FROM stats WHERE domain = ?""",
                (domain,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else {}

    # ==================== Strategy Cooldowns ====================

    @profiler
    async def set_strategy_cooldown(self, domain: str, minutes: int, reason: str = "") -> None:
        """Установка cooldown для домена"""
        from datetime import datetime, timedelta
        until = (datetime.now() + timedelta(minutes=minutes)).isoformat()

        async with self._lock:
            domain = normalize_domain(domain)
            await self._db.execute(
                """INSERT OR REPLACE INTO strategy_cooldowns (domain, until, reason)
                   VALUES (?, ?, ?)""",
                (domain, until, reason)
            )
            await self._db.commit()

    @profiler
    async def get_strategy_cooldown(self, domain: str) -> Optional[str]:
        """Получение cooldown для домена. Возвращает until или None"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                "SELECT until FROM strategy_cooldowns WHERE domain = ? AND until > ?",
                (domain, datetime.now().isoformat())
            )
            row = await cursor.fetchone()
            return row["until"] if row else None

    @profiler
    async def clear_strategy_cooldown(self, domain: str) -> bool:
        """Очистка cooldown для домена"""
        async with self._lock:
            domain = normalize_domain(domain)
            cursor = await self._db.execute(
                "DELETE FROM strategy_cooldowns WHERE domain = ?",
                (domain,)
            )
            await self._db.commit()
            return cursor.rowcount > 0

    @profiler
    async def purge_expired_cooldowns(self) -> int:
        """Удаление истёкших cooldown. Возвращает количество удалённых"""
        async with self._lock:
            cursor = await self._db.execute(
                "DELETE FROM strategy_cooldowns WHERE until <= ?",
                (datetime.now().isoformat(),)
            )
            await self._db.commit()
            return cursor.rowcount

    # ==================== Strategy Statistics ====================

    @profiler
    async def update_strategy_stats(self, strategy_id: int, success: bool) -> None:
        """Обновление статистики стратегии (success_rate, total_checks, но не domains_count)"""
        async with self._lock:
            # Получаем текущую статистику
            cursor = await self._db.execute(
                "SELECT success_rate, total_checks, last_success FROM strategies WHERE id = ?",
                (strategy_id,)
            )
            row = await cursor.fetchone()

            if not row:
                return

            old_rate = row["success_rate"]
            old_checks = row["total_checks"]
            last_success = row["last_success"]

            # Обновляем с использованием скользящего среднего
            new_checks = old_checks + 1
            # Weighted average: новый вес = 1/total_checks
            weight = 1.0 / new_checks if new_checks > 0 else 0
            new_rate = old_rate * (1 - weight) + (1.0 if success else 0.0) * weight

            # Обновляем last_success только при успехе (не затираем при fail)
            if success:
                last_success = datetime.now().isoformat()

            await self._db.execute(
                """UPDATE strategies
                   SET success_rate = ?, total_checks = ?, last_success = ?
                   WHERE id = ?""",
                (new_rate, new_checks, last_success, strategy_id)
            )
            await self._db.commit()

    @profiler
    async def get_strategies_by_priority(self, min_success_rate: float = 0.0) -> List[Strategy]:
        """Получение стратегий отсортированных по приоритету и успешности (включая untested)"""
        async with self._lock:
            cursor = await self._db.execute(
                """SELECT * FROM strategies
                   WHERE success_rate >= ? OR total_checks = 0
                   ORDER BY priority ASC, success_rate DESC, domains_count DESC""",
                (min_success_rate,)
            )
            rows = await cursor.fetchall()
            return [Strategy(**dict(row)) for row in rows]

    # ==================== Utility ====================

    @profiler
    async def init_from_config(self, strategies: List[Dict[str, Any]]) -> None:
        """Инициализация базы стратегиями из конфигурации (создаёт только отсутствующие)"""
        async with self._lock:
            for strat_data in strategies:
                # Нормализуем параметры
                params_canonical = canonicalize_params(strat_data.get("zapret_params", ""))

                # Проверяем существует ли стратегия (прямой SQL без вызова get_strategy)
                cursor = await self._db.execute(
                    "SELECT id FROM strategies WHERE name = ?", (strat_data["name"],)
                )
                existing = await cursor.fetchone()

                if existing:
                    # Обновляем zapret_params, params_canonical, priority и description из конфига
                    await self._db.execute(
                        """UPDATE strategies SET
                           zapret_params = ?, params_canonical = ?, priority = ?, description = ?
                           WHERE name = ?""",
                        (strat_data.get("zapret_params", ""),
                         params_canonical,
                         strat_data.get("priority", 99),
                         strat_data.get("description", ""),
                         strat_data["name"])
                    )
                else:
                    # Проверяем нет ли стратегии с такими же параметрами (защита от дубликатов в конфиге)
                    if params_canonical:
                        cursor = await self._db.execute(
                            "SELECT id FROM strategies WHERE params_canonical = ? AND params_canonical != ''",
                            (params_canonical,)
                        )
                        existing_by_params = await cursor.fetchone()
                        if existing_by_params:
                            # Пропускаем создание - стратегия уже существует по параметрам
                            logger.warning(f"Skipping strategy '{strat_data['name']}': another strategy already has these params")
                            continue
                    
                    # Создаём новую (прямой SQL без вызова add_strategy)
                    try:
                        await self._db.execute(
                            """INSERT INTO strategies
                               (name, description, zapret_params, params_canonical, priority, created_at,
                                domains_count, success_rate, total_checks, last_success)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (strat_data["name"], strat_data.get("description", ""),
                             strat_data.get("zapret_params", ""), params_canonical,
                             strat_data.get("priority", 99),
                             datetime.now().isoformat(),
                             0, 0.0, 0, None)
                        )
                    except aiosqlite.IntegrityError as e:
                        # Ловим IntegrityError на случай race condition или unique violation
                        logger.warning(f"Cannot create strategy '{strat_data['name']}': {e}")
                        continue

            await self._db.commit()
    
    @profiler
    async def execute(self, query: str, params: tuple = ()) -> aiosqlite.Cursor:
        """Прямое выполнение SQL запроса (для отладки)"""
        async with self._lock:
            cursor = await self._db.execute(query, params)
            await self._db.commit()
            return cursor
