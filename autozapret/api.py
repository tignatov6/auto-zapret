"""
Web API и UI для Auto-Zapret
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .config import Config, get_config
from .storage import Storage, Strategy, Domain, StatEvent
from .executor import Executor
from .analyzer import Analyzer, get_log_history, brute_force_progress, BruteForceStatus
from .monitor import Monitor
from .nfqws_config import get_generator, NfqwsConfigGenerator
from .utils.profiler import get_profiler
profiler = get_profiler("api")

logger = logging.getLogger(__name__)


# ==================== Pydantic Models ====================

class StrategyCreate(BaseModel):
    name: str
    description: str = ""
    zapret_params: str
    priority: int = 99


class StrategyUpdate(BaseModel):
    description: Optional[str] = None
    zapret_params: Optional[str] = None
    priority: Optional[int] = None


class DomainCreate(BaseModel):
    domain: str
    strategy_name: str


class DomainBulkCreate(BaseModel):
    domains: List[str]
    strategy_name: str


class StatsResponse(BaseModel):
    total_strategies: int
    total_domains: int
    active_domains: int
    total_events: int
    events_by_type: dict
    recent_events: List[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    nfqws_log: str
    timestamp: str


# ==================== FastAPI App ====================

@profiler
def create_app(config: Config = None):
    """Создание FastAPI приложения"""
    
    if config is None:
        config = get_config()
    
    app = FastAPI(
        title="Auto-Zapret API",
        description="API для управления адаптивной мультистратегической маршрутизацией Zapret",
        version="0.1.0"
    )
    
    # Инициализация компонентов
    storage = Storage(config.database_path)
    executor = Executor(config)
    analyzer = Analyzer(storage, executor, config)
    monitor = Monitor(config, replay_existing_logs=config.monitor_replay_existing_logs)

    # Регистрируем callback для analyzer
    monitor.register_callback(analyzer.handle_event)

    # Templates и static files
    templates_dir = Path(__file__).parent.parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    # ==================== Startup/Shutdown ====================

    @app.on_event("startup")
    @profiler
    async def startup():
        logger.info("=" * 60)
        logger.info("Auto-Zapret API Startup")
        logger.info("=" * 60)
        logger.info(f"Database: {config.database_path}")
        logger.info(f"NFQWS log: {config.nfqws_log_file}")
        logger.info(f"Hostlists dir: {config.hostlists_dir}")
        
        logger.info("Connecting to database...")
        await storage.connect()
        logger.info("Database connected")
        
        if config.strategies:
            logger.info(f"Loading {len(config.strategies)} strategies from config...")
            await storage.init_from_config(config.strategies)
            logger.info(f"Loaded {len(config.strategies)} strategies")
        
        logger.info("Initializing NFQWS config generator...")
        nfqws_gen = get_generator(config)
        await nfqws_gen.initialize(storage)
        app.state.nfqws_generator = nfqws_gen
        logger.info(f"NFQWS generator initialized ({len(config.strategies)} profiles)")

        logger.info("Starting Monitor in background...")
        app.state.monitor_task = asyncio.create_task(monitor.start())
        logger.info("Monitor started")

        app.state.analyzer = analyzer

        # ═══════════════════════════════════════════════════════
        # АВТОЗАПУСК WINWS ПРИ СТАРТЕ
        # 1. Закрываем все существующие winws (даже запущенные вне Auto-Zapret)
        # 2. Запускаем winws с сохраненными стратегиями
        # ═══════════════════════════════════════════════════════
        try:
            logger.info("Checking for existing winws processes...")
            
            # Закрываем ВСЕ процессы winws (даже если запущены не через Auto-Zapret)
            await executor.stop_winws()
            
            logger.info("Starting winws with saved strategies...")
            success, msg = await executor.restart_winws_full(app.state.nfqws_generator)
            
            if success:
                logger.info("✅ WinWS started with saved strategies")
            else:
                logger.warning(f"Failed to start WinWS: {msg}")
        except Exception as e:
            logger.warning(f"Failed to auto-start WinWS: {e}")

        logger.info("=" * 60)
        logger.info("Auto-Zapret API started (Monitor running)")
        logger.info("=" * 60)

    @profiler
    async def _ensure_winws_running():
        """
        Проверка запущен ли winws.
        
        ПРИМЕЧАНИЕ: Автозапуск winws выполняется в main.run() при старте приложения.
        Эта функция только проверяет статус и логирует предупреждение если winws не запущен.
        """
        logger.info("Checking if winws is running...")

        # Проверяем запущен ли winws
        winws_pid = executor._find_nfqws_pid()

        if winws_pid is None:
            logger.warning("winws is not running. It should be started by main.run() at startup.")
            logger.warning("If winws is still not running, strategies will be started on-demand when needed.")
        else:
            logger.info(f"winws is already running (PID: {winws_pid})")

    @app.on_event("shutdown")
    @profiler
    async def shutdown():
        logger.info("=" * 60)
        logger.info("Auto-Zapret API Shutdown")
        logger.info("=" * 60)
        
        logger.info("Stopping Monitor...")
        monitor.stop()

        logger.info("Waiting for Monitor task to complete...")
        if hasattr(app.state, 'monitor_task') and not app.state.monitor_task.done():
            app.state.monitor_task.cancel()
            try:
                await app.state.monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Monitor stopped")

        logger.info("Shutting down Analyzer...")
        if hasattr(app.state, 'analyzer'):
            await app.state.analyzer.shutdown()
        logger.info("Analyzer shutdown complete")

        logger.info("Stopping winws...")
        await executor.stop_winws()
        logger.info("winws stopped")

        logger.info("Closing database connection...")
        await storage.close()
        logger.info("Database connection closed")

        # Выводим отчёт профайлера
        try:
            from .utils.profiler import report
            logger.info("=" * 60)
            logger.info("PROFILER REPORT - Performance Statistics")
            logger.info("=" * 60)
            report(logger_obj=logger)  # Вывод через logger
        except Exception as e:
            logger.warning(f"Failed to print profiler report: {e}")

        logger.info("=" * 60)
        logger.info("Auto-Zapret API shutdown complete")
        logger.info("=" * 60)
    
    # ==================== API Endpoints ====================
    
    @app.get("/api/health", response_model=HealthResponse)
    @profiler
    async def health_check():
        """Проверка состояния API"""
        return HealthResponse(
            status="healthy",
            version="0.1.0",
            database=config.database_path,
            nfqws_log=config.nfqws_log_file,
            timestamp=datetime.now().isoformat()
        )
    
    # --- Strategies ---
    
    @app.get("/api/strategies")
    @profiler
    async def list_strategies():
        """Список всех стратегий"""
        strategies = await storage.list_strategies()
        return {
            "strategies": [
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "zapret_params": s.zapret_params,
                    "priority": s.priority
                }
                for s in strategies
            ]
        }
    
    @app.post("/api/strategies")
    @profiler
    async def create_strategy(strategy: StrategyCreate):
        """Создание новой стратегии"""
        # Валидация параметров через nfqws generator
        nfqws_gen = app.state.nfqws_generator
        valid, error = nfqws_gen.validate_params(strategy.zapret_params)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        
        # Используем новый метод с возвратом статуса
        strategy_id, was_created = await storage.create_strategy(
            name=strategy.name,
            params=strategy.zapret_params,
            description=strategy.description
        )
        
        if was_created:
            # Обновляем nfqws профиль
            strat_obj = await storage.get_strategy_by_id(strategy_id)
            if strat_obj:
                await nfqws_gen.update_profile(strat_obj)
            
            # Генерируем startup script
            script_path = os.path.join(config.data_dir, "start-nfqws-auto.cmd")
            nfqws_gen.generate_windows_batch(script_path)
            
            return {"id": strategy_id, "message": f"Strategy '{strategy.name}' created"}
        else:
            # Стратегия уже существует (по имени или params)
            existing = await storage.get_strategy(strategy.name)
            if existing and existing.name == strategy.name:
                raise HTTPException(status_code=409, detail=f"Strategy '{strategy.name}' already exists")
            else:
                # Существует по params - возвращаем информацию
                existing_by_params = await storage.get_strategy_by_params(strategy.zapret_params)
                raise HTTPException(
                    status_code=409,
                    detail=f"Strategy with same params already exists: '{existing_by_params.name}'"
                )
    
    @app.get("/api/strategies/{strategy_name}")
    @profiler
    async def get_strategy(strategy_name: str):
        """Получение информации о стратегии"""
        strategy = await storage.get_strategy(strategy_name)
        if not strategy:
            raise HTTPException(status_code=404, detail="Strategy not found")
        
        return {
            "id": strategy.id,
            "name": strategy.name,
            "description": strategy.description,
            "zapret_params": strategy.zapret_params,
            "priority": strategy.priority
        }
    
    @app.put("/api/strategies/{strategy_name}")
    @profiler
    async def update_strategy(strategy_name: str, strategy: StrategyUpdate):
        """Обновление стратегии"""
        existing = await storage.get_strategy(strategy_name)
        if not existing:
            raise HTTPException(status_code=404, detail="Strategy not found")

        # Получаем nfqws generator
        nfqws_gen = app.state.nfqws_generator

        # Обновляем поля
        if strategy.description is not None:
            existing.description = strategy.description
        if strategy.zapret_params is not None:
            # Валидация параметров
            valid, error = nfqws_gen.validate_params(strategy.zapret_params)
            if not valid:
                raise HTTPException(status_code=400, detail=error)
            existing.zapret_params = strategy.zapret_params
        if strategy.priority is not None:
            existing.priority = strategy.priority

        # Проверяем конфликт params
        ok = await storage.update_strategy(existing)
        if not ok:
            raise HTTPException(
                status_code=409,
                detail="Another strategy already has these params"
            )

        # Обновляем nfqws профиль
        await nfqws_gen.update_profile(existing)

        # Перегенерируем startup script
        script_path = os.path.join(config.data_dir, "start-nfqws-auto.cmd")
        nfqws_gen.generate_windows_batch(script_path)

        return {"message": f"Strategy '{strategy_name}' updated"}
    
    @app.delete("/api/strategies/{strategy_name}")
    @profiler
    async def delete_strategy(strategy_name: str):
        """Удаление стратегии"""
        nfqws_gen = app.state.nfqws_generator
        
        # Проверяем есть ли домены
        domains = await storage.list_domains_for_strategy(strategy_name)
        if domains:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot delete strategy with {len(domains)} domains. Remove domains first."
            )

        success = await storage.delete_strategy(strategy_name)
        if not success:
            raise HTTPException(status_code=404, detail="Strategy not found or has domains")

        # Удаляем профиль из nfqws generator
        await nfqws_gen.remove_profile(strategy_name)

        # Удаляем файл стратегии
        strategy_file = Path(config.get_strategy_file(strategy_name))
        if strategy_file.exists():
            strategy_file.unlink()
        
        # Перегенерируем startup script
        script_path = os.path.join(config.data_dir, "start-nfqws-auto.cmd")
        nfqws_gen.generate_windows_batch(script_path)

        return {"message": f"Strategy '{strategy_name}' deleted"}
    
    # --- Domains ---
    
    @app.get("/api/domains")
    @profiler
    async def list_domains(active_only: bool = True):
        """Список доменов"""
        domains = await storage.list_domains(active_only=active_only)
        result = []
        for d in domains:
            strategy = await storage.get_strategy_by_id(d.strategy_id)
            result.append({
                "domain": d.domain,
                "strategy_id": d.strategy_id,
                "strategy_name": strategy.name if strategy else f"ID:{d.strategy_id}",
                "added_at": d.added_at,
                "fail_count": d.fail_count,
                "is_active": bool(d.is_active)
            })
        return {"domains": result}
    
    @app.post("/api/domains")
    @profiler
    async def create_domain(domain_obj: DomainCreate):
        """Привязка домена к стратегии"""
        strategy = await storage.get_strategy(domain_obj.strategy_name)
        if not strategy:
            raise HTTPException(status_code=404, detail="Strategy not found")

        # Проверяем есть ли уже стратегия у домена
        domain_info = await storage.get_domain(domain_obj.domain)

        # Всегда применяем через executor (идемпотентно)
        if domain_info and domain_info.is_active:
            # Домен уже на стратегии - проверяем нужно ли менять
            if domain_info.strategy_id != strategy.id:
                # Меняем стратегию
                old_strategy = await storage.get_strategy_by_id(domain_info.strategy_id)
                if old_strategy:
                    success, msg = await executor.reassign_domain(
                        domain_obj.domain, old_strategy.name, strategy.name
                    )
                else:
                    success, msg = await executor.apply_strategy(domain_obj.domain, strategy.name)
            else:
                # Та же стратегия - всё равно применяем (идемпотентно)
                success, msg = await executor.apply_strategy(domain_obj.domain, strategy.name)
        else:
            # Новый домен
            success, msg = await executor.apply_strategy(domain_obj.domain, strategy.name)

        if success:
            # Только после успеха записываем в БД
            await storage.assign_domain(domain_obj.domain, strategy.id)
            return {
                "message": f"Domain '{domain_obj.domain}' assigned to '{domain_obj.strategy_name}'",
                "applied": True
            }
        else:
            raise HTTPException(status_code=500, detail=msg)
    
    @app.post("/api/domains/bulk")
    @profiler
    async def bulk_create_domains(domain_obj: DomainBulkCreate):
        """Массовая привязка доменов к стратегии"""
        strategy = await storage.get_strategy(domain_obj.strategy_name)
        if not strategy:
            raise HTTPException(status_code=404, detail="Strategy not found")

        results = []
        for domain in domain_obj.domains:
            # Проверяем текущее состояние домена
            domain_info = await storage.get_domain(domain)
            
            # Применяем через executor с учётом возможной старой стратегии
            if domain_info and domain_info.is_active and domain_info.strategy_id != strategy.id:
                # Домен на другой стратегии - нужен reassign
                old_strategy = await storage.get_strategy_by_id(domain_info.strategy_id)
                if old_strategy:
                    success, msg = await executor.reassign_domain(
                        domain, old_strategy.name, strategy.name
                    )
                else:
                    success, msg = await executor.apply_strategy(domain, strategy.name)
            else:
                # Новый домен или та же стратегия
                success, msg = await executor.apply_strategy(domain, strategy.name)
            
            if success:
                # Затем записываем в БД
                await storage.assign_domain(domain, strategy.id)
                results.append({"domain": domain, "status": "assigned"})
            else:
                results.append({"domain": domain, "status": "failed", "error": msg})

        return {"assigned": len([r for r in results if r["status"] == "assigned"]), "domains": results}
    
    @app.delete("/api/domains/{domain}")
    @profiler
    async def delete_domain(domain: str):
        """Удаление домена"""
        # Сначала находим стратегию домена
        domain_info = await storage.get_domain(domain)
        if domain_info:
            strategy = await storage.get_strategy_by_id(domain_info.strategy_id)
            if strategy:
                # Удаляем из файла стратегии
                success, msg = await executor.remove_domain(domain, strategy.name)
                # Игнорируем "not found" — это нормально
                if not success and "not found" not in msg.lower() and "not present" not in msg.lower():
                    raise HTTPException(status_code=500, detail=f"Failed to remove from file: {msg}")

        # Потом удаляем из БД с проверкой результата
        deleted = await storage.hard_remove_domain(domain)
        if not deleted:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        return {"message": f"Domain '{domain}' removed"}
    
    @app.get("/api/domains/{domain}/stats")
    @profiler
    async def get_domain_stats(domain: str):
        """Статистика по домену"""
        domain_info = await storage.get_domain(domain)
        if not domain_info:
            raise HTTPException(status_code=404, detail="Domain not found")
        
        stats = await storage.get_domain_stats(domain)
        return {
            "domain": domain,
            "stats": stats
        }
    
    # --- Stats ---
    
    @app.get("/api/stats", response_model=StatsResponse)
    @profiler
    async def get_stats():
        """Общая статистика"""
        domains = await storage.list_domains()
        strategies = await storage.list_strategies()
        events = await storage.get_stats(limit=1000)
        
        # Считаем события по типам
        events_by_type = {}
        for e in events:
            events_by_type[e.event_type] = events_by_type.get(e.event_type, 0) + 1
        
        # Последние 10 событий
        recent = await storage.get_stats(limit=10)
        recent_events = [
            {
                "domain": e.domain,
                "event_type": e.event_type,
                "timestamp": e.timestamp,
                "strategy_id": e.strategy_id
            }
            for e in recent
        ]
        
        return StatsResponse(
            total_strategies=len(strategies),
            total_domains=len(domains),
            active_domains=sum(1 for d in domains if d.is_active),
            total_events=len(events),
            events_by_type=events_by_type,
            recent_events=recent_events
        )
    
    # --- Actions ---

    @app.post("/api/actions/reload")
    @profiler
    async def reload_config():
        """Перезагрузка конфигурации nfqws (SIGHUP)"""
        # Сначала ждём отложенные HUP
        await executor.flush_pending_hup(timeout=2.0)
        
        success, msg = await executor.send_hup_to_nfqws()
        if success:
            return {"status": "success", "message": msg}
        else:
            raise HTTPException(status_code=500, detail=msg)

    @app.get("/api/actions/nfqws-config")
    @profiler
    async def get_nfqs_config():
        """Получение текущей конфигурации nfqws"""
        nfqws_gen = app.state.nfqws_generator
        return nfqws_gen.get_config_summary()

    @app.post("/api/actions/generate-nfqws-scripts")
    @profiler
    async def generate_nfqs_scripts():
        """Генерация скриптов запуска nfqws"""
        nfqws_gen = app.state.nfqws_generator
        
        # Генерируем все варианты
        scripts = {}
        
        # Windows batch
        bat_path = os.path.join(config.data_dir, "start-nfqws-auto.cmd")
        nfqws_gen.generate_windows_batch(bat_path)
        scripts["windows"] = bat_path
        
        # Shell script
        sh_path = os.path.join(config.data_dir, "start-nfqws-auto.sh")
        nfqws_gen.generate_startup_script(sh_path)
        scripts["shell"] = sh_path
        
        # Systemd service
        service_path = os.path.join(config.data_dir, "nfqws-auto.service")
        nfqws_gen.generate_systemd_service(service_path)
        scripts["systemd"] = service_path
        
        return {
            "status": "success",
            "scripts": scripts,
            "nfqws_args": nfqws_gen.generate_nfqs_args()
        }

    @app.post("/api/actions/apply-strategy")
    @profiler
    async def apply_strategy(domain: str, strategy_name: str):
        """Применение стратегии к домену"""
        # Проверяем существование стратегии
        strategy = await storage.get_strategy(strategy_name)
        if not strategy:
            raise HTTPException(status_code=404, detail="Strategy not found")
        
        success, msg = await executor.apply_strategy(domain, strategy_name)
        if success:
            # Применяем через executor (идемпотентно) и записываем в БД
            await storage.assign_domain(domain, strategy.id)
            return {"success": True, "message": msg}
        else:
            raise HTTPException(status_code=500, detail=msg)
    
    # --- Logs & Progress ---
    
    @app.get("/api/logs")
    @profiler
    async def get_logs(limit: int = 100):
        """Получение логов в реальном времени"""
        return {"logs": get_log_history(limit)}
    
    @app.get("/api/progress")
    @profiler
    async def get_progress():
        """Получение прогресса подбора стратегий"""
        return {"progress": brute_force_progress}
    
    @app.get("/api/progress/{domain}")
    @profiler
    async def get_domain_progress(domain: str):
        """Получение прогресса для конкретного домена"""
        if domain in brute_force_progress:
            return brute_force_progress[domain]
        raise HTTPException(status_code=404, detail="No progress found for domain")

    @app.post("/api/brute_force/stop/{domain}")
    @profiler
    async def stop_brute_force(domain: str):
        """
        Остановка перебора стратегий для домена
        
        Args:
            domain: Домен для которого нужно остановить перебор
            
        Returns:
            {"success": True} или {"success": False, "error": "..."}
        """
        if domain not in brute_force_progress:
            return {"success": False, "error": "Перебор для этого домена не запущен"}
        
        progress = brute_force_progress[domain]
        if progress.get("status") != "in_progress":
            return {"success": False, "error": "Перебор уже завершен"}
        
        # Помечаем как остановленный пользователем
        from datetime import datetime
        brute_force_progress[domain]["status"] = "stopped_by_user"
        brute_force_progress[domain]["completed"] = datetime.now().isoformat()
        brute_force_progress[domain]["error"] = "Остановлено пользователем"
        
        logger.info(f"[api] Brute force for {domain} stopped by user")
        
        return {"success": True, "domain": domain}

    @app.post("/api/actions/check-dpi")
    @profiler
    async def check_dpi(domain: str):
        """Ручная проверка домена на DPI блокировку"""
        result = await analyzer.dpi_detector.check_domain(domain, timeout=60)
        return result.to_dict()

    @app.get("/api/actions/check-dpi")
    @profiler
    async def check_dpi_get(domain: str):
        """Ручная проверка домена на DPI блокировку (GET)"""
        result = await analyzer.dpi_detector.check_domain(domain, timeout=60)
        return result.to_dict()
    
    @app.post("/api/actions/simulate-event")
    @profiler
    async def simulate_event(domain: str, event_type: str = "fail_counter", counter: int = 1, threshold: int = 3, protocol: str = "TLS"):
        """Симуляция события autohostlist для тестирования"""
        from .monitor import AutoHostlistEvent, EventType
        from .analyzer import add_log_entry

        # Преобразуем event_type в Enum, используя UNKNOWN для неизвестных типов
        try:
            event_type_enum = EventType(event_type)
        except ValueError:
            event_type_enum = EventType.UNKNOWN

        event = AutoHostlistEvent(
            event_type=event_type_enum,
            domain=domain,
            profile_id=1,
            client="192.168.1.100:54321",
            protocol=protocol,
            fail_counter=counter,
            fail_threshold=threshold
        )

        # Добавляем в лог
        await add_log_entry({
            "type": event_type,
            "domain": domain,
            "counter": counter,
            "threshold": threshold,
            "message": f"Simulated: {event_type} {counter}/{threshold} ({protocol})",
            "client": event.client,
            "profile": event.profile_id,
            "protocol": protocol
        })

        # Реально обрабатываем событие через analyzer (только если это известный тип)
        if event_type_enum != EventType.UNKNOWN:
            await analyzer.handle_event(event)

        return {"status": "ok", "message": f"Simulated {event_type} for {domain}"}

    @app.post("/api/actions/force-bruteforce/{domain}")
    @profiler
    async def force_bruteforce(domain: str, mode: str = "first_working"):
        """
        Принудительный запуск брутфорса для домена

        Args:
            domain: Домен для брутфорса
            mode: Режим - "first_working" или "all_best"

        Returns:
            {"success": True, "message": "..."} или {"success": False, "error": "..."}
        """
        from .analyzer import normalize_domain
        from uuid import uuid4

        domain = normalize_domain(domain)

        # Проверяем есть ли уже стратегия у домена
        domain_info = await storage.get_domain(domain)
        current_strategy = None
        if domain_info and domain_info.is_active:
            current_strategy = await storage.get_strategy_by_id(domain_info.strategy_id)

        # Временно меняем режим в конфиге
        old_mode = analyzer.config.brute_force_mode
        analyzer.config.brute_force_mode = mode

        try:
            # Запускаем брутфорс напрямую
            logger.info(f"[api] Force brute force for {domain} (mode={mode})")

            # Добавляем лог
            from .analyzer import add_log_entry
            await add_log_entry({
                "type": "force_bruteforce",
                "domain": domain,
                "mode": mode,
                "message": f"🚀 Запущен принудительный брутфорс для {domain} (mode={mode})"
            })

            # Вызываем brute force напрямую
            bf_result = await analyzer._brute_force_strategies(domain)

            logger.info(f"[api] Brute force result: status={bf_result.status}, params={bf_result.params[:50] if bf_result.params else None}...")

            if bf_result.status == BruteForceStatus.FOUND and bf_result.params:
                # Проверяем нет ли уже стратегии с такими параметрами
                existing_strategy = await storage.get_strategy_by_params(bf_result.params)

                if existing_strategy:
                    # Используем существующую стратегию
                    strategy_name = existing_strategy.name
                    strategy_id = existing_strategy.id
                    logger.info(f"[api] Found existing strategy with same params: {strategy_name}")
                else:
                    # Создаём новую стратегию с уникальным именем
                    strategy_name = f"strategy_{uuid4().hex[:12]}"
                    strategy_id, was_created = await storage.create_strategy(
                        name=strategy_name,
                        params=bf_result.params,
                        description=bf_result.description or "Auto-created strategy (force bruteforce)"
                    )
                    logger.info(f"[api] Created new strategy {strategy_name} for {domain}")

                # Применяем стратегию к домену
                if current_strategy and current_strategy.id != strategy_id:
                    # Переносим домен из старой стратегии в новую
                    old_strategy_name = current_strategy.name
                    success, msg = await executor.reassign_domain(
                        domain, old_strategy_name, strategy_name
                    )
                else:
                    # Домен не был на стратегии или та же стратегия
                    success, msg = await executor.apply_strategy(domain, strategy_name)

                if success:
                    # Добавляем домен к стратегии в БД
                    await storage.assign_domain(domain, strategy_id)
                    await storage.update_strategy_stats(strategy_id, success=True)
                    await storage.log_event(StatEvent(
                        domain=domain,
                        event_type="applied",
                        strategy_id=strategy_id,
                        details=f"Created/matched strategy (force bruteforce): {bf_result.params}"
                    ))

                    # ═══════════════════════════════════════════════════════
                    # ПОЛНЫЙ РЕСТАРТ WINWS СО ВСЕМИ СТРАТЕГИЯМИ
                    # ═══════════════════════════════════════════════════════
                    logger.info(f"[api] Strategy applied → full winws restart...")

                    # 1. Синхронизируем profiles из БД
                    await analyzer.nfqws_generator.sync_from_storage()

                    # 2. Обновляем стратегию в nfqws-генераторе
                    strategy_obj = await storage.get_strategy_by_id(strategy_id)
                    if strategy_obj:
                        await analyzer.nfqws_generator.update_profile(strategy_obj)

                    # 3. Перегенерируем батник
                    script_path = os.path.join(analyzer.config.data_dir, "start-nfqws-auto.cmd")
                    analyzer.nfqws_generator.generate_windows_batch(script_path)

                    # 4. Полный рестарт winws
                    success, msg = await executor.restart_winws_full(analyzer.nfqws_generator)

                    if success:
                        await add_log_entry({
                            "type": "winws_full_restart",
                            "domain": domain,
                            "strategy": strategy_name,
                            "message": f"✅ winws перезапущен со стратегией {strategy_name}"
                        })
                        await analyzer._clear_autohostlist()
                    else:
                        await add_log_entry({
                            "type": "winws_restart_failed",
                            "message": f"❌ Restart failed: {msg}"
                        })
                    # ═══════════════════════════════════════════════════════

                    logger.info(f"[api] Strategy {strategy_name} saved to pool and applied to {domain}")
                    
                    return {
                        "success": True,
                        "message": f"✅ Найдена и применена стратегия: {strategy_name}",
                        "strategy": strategy_name,
                        "params": bf_result.params
                    }
                else:
                    return {
                        "success": False,
                        "error": f"❌ Не удалось применить стратегию: {msg}"
                    }

            elif bf_result.status == BruteForceStatus.NO_DPI:
                return {
                    "success": True,
                    "message": "ℹ️ DPI не обнаружен, стратегия не нужна"
                }
            else:
                return {
                    "success": False,
                    "error": f"❌ Не найдено рабочей стратегии: {bf_result.description or 'Unknown error'}"
                }
        finally:
            # Возвращаем старый режим
            analyzer.config.brute_force_mode = old_mode

    @app.post("/api/actions/reselect-existing/{domain}")
    @profiler
    async def reselect_existing(domain: str):
        """
        Перевыбор стратегии из уже существующих в БД
        
        Тестирует все существующие стратегии на домене и выбирает лучшую по скорости.
        
        Args:
            domain: Домен для перевыбора
        
        Returns:
            {"success": True, "message": "...", "strategy": "..."} или {"success": False, "error": "..."}
        """
        from .analyzer import normalize_domain, StrategyTestStatus, add_log_entry
        
        domain = normalize_domain(domain)
        
        # Проверяем есть ли уже стратегия у домена
        domain_info = await storage.get_domain(domain)
        current_strategy = None
        if domain_info and domain_info.is_active:
            current_strategy = await storage.get_strategy_by_id(domain_info.strategy_id)
        
        logger.info(f"[api] Re-selecting existing strategy for {domain}")
        
        await add_log_entry({
            "type": "reselect_existing",
            "domain": domain,
            "message": f"🔍 Тестирование существующих стратегий для {domain}..."
        })
        
        # Получаем все стратегии
        strategies = await storage.get_strategies_by_priority(min_success_rate=0.0)
        
        if not strategies:
            return {"success": False, "error": "Нет существующих стратегий в БД"}
        
        working_strategies = []
        
        # Тестируем каждую стратегию
        for strategy in strategies:
            result = await analyzer._test_strategy(domain, strategy.zapret_params)
            
            if result.status == StrategyTestStatus.WORKS:
                logger.info(f"✅ Strategy {strategy.name} WORKS (RTT: {result.response_time:.3f}s)")
                working_strategies.append((strategy, result))
                await storage.update_strategy_stats(strategy.id, success=True)
            else:
                await storage.update_strategy_stats(strategy.id, success=False)
        
        if not working_strategies:
            await add_log_entry({
                "type": "reselect_existing_failed",
                "domain": domain,
                "message": f"❌ Ни одна стратегия не сработала для {domain}"
            })
            return {"success": False, "error": "Ни одна существующая стратегия не сработала"}
        
        # Сортируем по RTT и выбираем лучшую
        working_strategies.sort(key=lambda x: x[1].response_time)
        best_strategy, best_result = working_strategies[0]
        
        logger.info(f"🏆 Best strategy for {domain}: {best_strategy.name} (RTT: {best_result.response_time:.3f}s)")
        
        await add_log_entry({
            "type": "reselect_existing_success",
            "domain": domain,
            "strategy": best_strategy.name,
            "message": f"✅ Выбрана лучшая стратегия: {best_strategy.name} (RTT: {best_result.response_time:.3f}s)"
        })
        
        # Применяем стратегию
        if current_strategy and current_strategy.id != best_strategy.id:
            success, msg = await executor.reassign_domain(domain, current_strategy.name, best_strategy.name)
        else:
            success, msg = await executor.apply_strategy(domain, best_strategy.name)
        
        if success:
            await storage.assign_domain(domain, best_strategy.id)
            await storage.reset_fail_count(domain)
            
            # Рестарт winws
            await app.state.nfqws_generator.sync_from_storage()
            strategy_obj = await storage.get_strategy_by_id(best_strategy.id)
            if strategy_obj:
                await app.state.nfqws_generator.update_profile(strategy_obj)
            
            script_path = os.path.join(config.data_dir, "start-nfqws-auto.cmd")
            app.state.nfqws_generator.generate_windows_batch(script_path)
            
            success, msg = await executor.restart_winws_full(app.state.nfqws_generator)
            
            if success:
                await add_log_entry({
                    "type": "winws_full_restart",
                    "domain": domain,
                    "strategy": best_strategy.name,
                    "message": "✅ winws перезапущен с новой стратегией"
                })
            else:
                await add_log_entry({
                    "type": "winws_restart_failed",
                    "message": f"❌ Restart failed: {msg}"
                })
            
            return {
                "success": True,
                "message": f"✅ Стратегия перевыбрана: {best_strategy.name}",
                "strategy": best_strategy.name,
                "response_time": best_result.response_time
            }
        else:
            return {"success": False, "error": f"Ошибка применения: {msg}"}

    @app.get("/api/config/brute-force-mode")
    @profiler
    async def get_brute_force_mode():
        """Получение текущего режима брутфорса"""
        return {
            "mode": analyzer.config.brute_force_mode,
            "quick_mode": analyzer.config.brute_force_quick_mode
        }

    @app.post("/api/config/brute-force-mode")
    @profiler
    async def set_brute_force_mode(mode: str, quick_mode: bool = None):
        """
        Установка режима брутфорса
        
        Args:
            mode: "first_working" или "all_best"
            quick_mode: True/False для быстрого режима
        
        Returns:
            {"success": True, "mode": "...", "quick_mode": True/False}
        """
        if mode not in ["first_working", "all_best"]:
            return {"success": False, "error": "Неверный режим. Используйте 'first_working' или 'all_best'"}
        
        analyzer.config.brute_force_mode = mode
        if quick_mode is not None:
            analyzer.config.brute_force_quick_mode = quick_mode
        
        logger.info(f"[api] Brute force mode changed to {mode} (quick_mode={analyzer.config.brute_force_quick_mode})")
        
        return {
            "success": True,
            "mode": mode,
            "quick_mode": analyzer.config.brute_force_quick_mode
        }

    # ==================== Web UI ====================

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        """Главная страница Dashboard"""
        stats = await get_stats()
        strategies_data = await list_strategies()
        domains_data = await list_domains()

        return templates.TemplateResponse("index.html", {
            "request": request,
            "stats": stats,
            "strategies": strategies_data["strategies"],
            "domains": domains_data["domains"]
        })

    @app.get("/strategies", response_class=HTMLResponse)
    async def strategies_page(request: Request):
        """Страница стратегий"""
        strategies_data = await list_strategies()
        return templates.TemplateResponse("strategies.html", {
            "request": request,
            "strategies": strategies_data["strategies"]
        })

    @app.get("/domains", response_class=HTMLResponse)
    async def domains_page(request: Request):
        """Страница доменов"""
        domains_data = await list_domains(active_only=False)
        strategies_data = await list_strategies()
        return templates.TemplateResponse("domains.html", {
            "request": request,
            "domains": domains_data["domains"],
            "strategies": strategies_data["strategies"]
        })

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request):
        """Страница логов"""
        events = await storage.get_stats(limit=100)
        return templates.TemplateResponse("logs.html", {
            "request": request,
            "events": [
                {
                    "domain": e.domain,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "strategy_id": e.strategy_id
                }
                for e in events
            ]
        })
    
    return app


# ==================== Main Entry Point ====================

def get_app():
    """Точка входа для uvicorn"""
    return create_app()
