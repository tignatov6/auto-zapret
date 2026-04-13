"""
Main - точка входа и CLI интерфейс
"""

import asyncio
import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiofiles
import click

from . import __version__
from .config import Config, get_config, reload_config
from .storage import Storage, Strategy, Domain, StatEvent
from .executor import Executor
from .monitor import Monitor, LogParser, EventType
from .analyzer import Analyzer
from .utils.profiler import get_profiler
profiler = get_profiler("main")

# Настройка логирования
log_dir = Path(__file__).parent.parent / "logs" / "python"
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / "auto-zapret.log"

# Создаём root logger с двумя handlers (консоль + файл)
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# Очищаем существующие handlers
root_logger.handlers.clear()

# Формат логов
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# File handler (rotating)
file_handler = logging.handlers.RotatingFileHandler(
    log_file,
    encoding='utf-8',
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=5  # Хранить 5 старых файлов
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

# Добавляем handlers
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)

logger = logging.getLogger(__name__)


class AutoZapretApp:
    """Основное приложение Auto-Zapret"""
    
    @profiler
    async def initialize(self) -> None:
        """Инициализация компонентов"""
        logger.info("=" * 60)
        logger.info("Initializing Auto-Zapret...")
        logger.info("=" * 60)
        logger.info(f"Config directory: {Path(self.config.config_dir).resolve()}")
        logger.info(f"Database path: {self.config.database_path}")
        logger.info(f"NFQWS log file: {self.config.nfqws_log_file}")
        logger.info(f"Hostlists directory: {self.config.hostlists_dir}")
        logger.info(f"Fail threshold: {self.config.fail_threshold}")
        logger.info(f"Retrans threshold: {self.config.retrans_threshold}")

        # Инициализация хранилища
        logger.info("Connecting to database...")
        self.storage = Storage(self.config.database_path)
        await self.storage.connect()
        logger.info("Database connection established")

        # Инициализация стратегий из конфига
        if self.config.strategies:
            logger.info(f"Loading {len(self.config.strategies)} strategies from config...")
            await self.storage.init_from_config(self.config.strategies)
            logger.info(f"Loaded {len(self.config.strategies)} strategies from config")
        else:
            logger.info("No strategies found in config")

        # Инициализация остальных компонентов
        logger.info("Initializing Executor...")
        self.executor = Executor(self.config)
        logger.info("Initializing Analyzer...")
        self.analyzer = Analyzer(self.storage, self.executor, self.config)
        logger.info("Initializing Monitor...")
        self.monitor = Monitor(
            self.config,
            replay_existing_logs=self.config.monitor_replay_existing_logs
        )

        # Регистрация callback
        self.monitor.register_callback(self.analyzer.handle_event)
        logger.info("Registered analyzer callback")

        # Запуск IP Monitor для приложений без SNI
        if self.config.ip_monitor_enabled and self.analyzer.ip_monitor:
            logger.info("Starting IP Monitor in background...")
            self._ip_monitor_task = asyncio.create_task(self.analyzer.ip_monitor.start())
            logger.info("IP Monitor started")
        else:
            self._ip_monitor_task = None
            logger.info("IP Monitor not enabled")

        # Очищаем autohostlist файл при старте
        await self._clear_autohostlist()

        # Проверяем и запускаем winws если не запущен
        await self._ensure_winws_running()

        logger.info("=" * 60)
        logger.info("Auto-Zapret initialized successfully")
        logger.info("=" * 60)

    @profiler
    async def _ensure_winws_running(self) -> None:
        """Проверка и запуск winws если не запущен"""
        logger.info("Checking if winws is running...")
        
        # Проверяем запущен ли winws
        winws_pid = self.executor._find_nfqws_pid()
        
        if winws_pid is None:
            logger.info("winws is not running. Starting winws with default strategy...")
            
            # Получаем все активные стратегии из БД
            strategies = await self.storage.get_strategies_by_priority(min_success_rate=0.0)
            
            if strategies:
                # Запускаем winws с первой стратегией (самый высокий приоритет)
                # Используем пустой домен - winws будет работать со всеми из hostlist файлов
                success, msg, startup_time = await self.executor.start_winws_with_strategy(
                    strategies[0].zapret_params,
                    domain=None,
                    measure_startup=False
                )
                
                if success:
                    logger.info(f"winws started successfully with strategy '{strategies[0].name}'")
                else:
                    logger.warning(f"Failed to start winws: {msg}")
            else:
                logger.info("No strategies available, winws will be started on-demand when needed")
        else:
            logger.info(f"winws is already running (PID: {winws_pid})")

    @profiler
    async def _clear_autohostlist(self) -> None:
        """Очистка файла autohostlist"""
        autohostlist_path = self.config.get_auto_hostlist_path()
        try:
            # Очищаем файл (создаём пустой)
            async with aiofiles.open(autohostlist_path, 'w', encoding='utf-8') as f:
                await f.write("")
            logger.debug(f"Cleared autohostlist file: {autohostlist_path}")
        except Exception as e:
            logger.debug(f"Failed to clear autohostlist: {e}")

    @profiler
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.storage: Optional[Storage] = None
        self.executor: Optional[Executor] = None
        self.analyzer: Optional[Analyzer] = None
        self.monitor: Optional[Monitor] = None
        self._running = False
        self._autohostlist_cleanup_task: Optional[asyncio.Task] = None
        self._ip_monitor_task: Optional[asyncio.Task] = None  # IP Monitor task

    @profiler
    async def shutdown(self) -> None:
        """Корректное завершение работы"""
        logger.info("Shutting down Auto-Zapret...")

        # 0. Останавливаем periodic cleanup и IP Monitor
        self._running = False
        if self._autohostlist_cleanup_task:
            self._autohostlist_cleanup_task.cancel()
            try:
                await self._autohostlist_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Останавливаем IP Monitor
        if self._ip_monitor_task and not self._ip_monitor_task.done():
            logger.info("Stopping IP Monitor...")
            if self.analyzer.ip_monitor:
                self.analyzer.ip_monitor.stop()
            self._ip_monitor_task.cancel()
            try:
                await self._ip_monitor_task
            except asyncio.CancelledError:
                pass

        # 1. Сначала останавливаем monitor
        if self.monitor:
            self.monitor.stop()

        # 2. Потом analyzer (background tasks)
        if self.analyzer:
            await self.analyzer.shutdown()

        # 3. Останавливаем winws если он запущен
        if self.executor:
            logger.info("Stopping winws...")
            await self.executor.stop_winws()

        # 4. В конце storage
        if self.storage:
            await self.storage.close()

        # 5. Выводим отчёт профайлера
        try:
            from .utils.profiler import report
            logger.info("=" * 60)
            logger.info("PROFILER REPORT - Performance Statistics")
            logger.info("=" * 60)
            report(logger_obj=logger)  # Вывод через logger
        except Exception as e:
            logger.warning(f"Failed to print profiler report: {e}")

        logger.info("Auto-Zapret shutdown complete")
    
    @profiler
    async def run(self) -> None:
        """Запуск основного цикла"""
        self._running = True

        logger.info("Starting Auto-Zapret main loop...")
        logger.info(f"Monitoring log file: {self.config.nfqws_log_file}")

        # Запускаем периодическую очистку autohostlist
        self._autohostlist_cleanup_task = asyncio.create_task(self._periodic_autohostlist_cleanup())

        try:
            # Используем monitor.start() который работает через callbacks
            await self.monitor.start()

        except asyncio.CancelledError:
            logger.info("Main loop cancelled")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            raise
        finally:
            await self.shutdown()

    @profiler
    async def _periodic_autohostlist_cleanup(self) -> None:
        """Периодическая очистка autohostlist (каждые 30 секунд)"""
        while self._running:
            await asyncio.sleep(30)
            await self._clear_autohostlist()
    
    @profiler
    def stop(self) -> None:
        """Остановка приложения"""
        self._running = False


# ==================== CLI Commands ====================

@click.group()
@click.version_option(version=__version__)
@click.option('--config-dir', type=click.Path(exists=True), 
              help='Directory with configuration files')
@click.pass_context
@profiler
def cli(ctx, config_dir: Optional[str]):
    """Auto-Zapret - Адаптивная мультистратегическая маршрутизация для Zapret"""
    ctx.ensure_object(dict)
    
    # Загружаем конфигурацию
    config = Config.load(config_dir)
    ctx.obj['config'] = config
    ctx.obj['app'] = AutoZapretApp(config)


@cli.command()
@click.pass_context
@profiler
def start(ctx):
    """Запуск Auto-Zapret в режиме демона"""
    app: AutoZapretApp = ctx.obj['app']
    
    @profiler
    async def run_async():
        await app.initialize()
        await app.run()
    
    try:
        asyncio.run(run_async())
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, stopping...")
        app.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind')
@click.option('--port', default=8000, help='Port to bind')
@click.option('--log-level', default='error', help='Logging level')
@click.pass_context
@profiler
def serve(ctx, host, port, log_level):
    """Запуск Web API и UI"""
    import uvicorn
    from .api import create_app

    config: Config = ctx.obj['config']

    app = create_app(config)

    click.echo(f"Starting Auto-Zapret Web UI at http://{host}:{port}")
    click.echo("Press CTRL+C to quit")

    # Отключаем только access-логи uvicorn, наши логи сохраняем
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,  # НЕ отключаем существующие логи!
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            }
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            }
        },
        "loggers": {
            "uvicorn": {
                "handlers": ["default"],
                "level": "ERROR",  # Только ошибки
                "propagate": False
            },
            "uvicorn.error": {
                "handlers": ["default"],
                "level": "ERROR",
                "propagate": False
            },
            "uvicorn.access": {
                "handlers": [],
                "level": "CRITICAL",  # Полностью отключаем access-логи
                "propagate": False
            }
        }
    }

    uvicorn.run(app, host=host, port=port, log_config=log_config)


@cli.command()
@click.pass_context
@profiler
def status(ctx):
    """Проверка статуса Auto-Zapret"""
    config: Config = ctx.obj['config']
    
    click.echo("Auto-Zapret Status")
    click.echo("=" * 40)
    click.echo(f"Config directory: {Path(config.hostlists_dir).parent}")
    click.echo(f"Database: {config.database_path}")
    click.echo(f"Log file: {config.nfqws_log_file}")
    click.echo(f"Hostlists dir: {config.hostlists_dir}")
    click.echo(f"Fail threshold: {config.fail_threshold}")
    click.echo(f"Retrans threshold: {config.retrans_threshold}")
    
    # Проверяем существование файлов
    click.echo("\nFile Status:")
    click.echo(f"  Database exists: {Path(config.database_path).exists()}")
    click.echo(f"  Log file exists: {Path(config.nfqws_log_file).exists()}")
    click.echo(f"  Hostlists dir exists: {Path(config.hostlists_dir).exists()}")


@cli.group()
@profiler
def strategies():
    """Управление стратегиями"""
    pass


@strategies.command('list')
@click.pass_context
@profiler
def strategies_list(ctx):
    """Список всех стратегий"""
    config: Config = ctx.obj['config']
    
    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        
        try:
            strat_list = await storage.list_strategies()
            
            if not strat_list:
                click.echo("No strategies found. Initialize from config first.")
                return
            
            click.echo("\nStrategies:")
            click.echo("=" * 60)
            
            for s in strat_list:
                click.echo(f"\n[{s.priority}] {s.name}")
                click.echo(f"  ID: {s.id}")
                click.echo(f"  Description: {s.description}")
                click.echo(f"  Params: {s.zapret_params}")
        finally:
            await storage.close()
    
    asyncio.run(run_async())


@strategies.command('add')
@click.argument('name')
@click.option('--params', required=True, help='Zapret параметры для стратегии')
@click.option('--description', default='', help='Описание стратегии')
@click.option('--priority', type=int, default=99, help='Приоритет (меньше = выше)')
@click.pass_context
@profiler
def strategies_add(ctx, name: str, params: str, description: str, priority: int):
    """Добавление новой стратегии"""
    config: Config = ctx.obj['config']
    
    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        
        try:
            strategy = Strategy(
                name=name,
                description=description,
                zapret_params=params,
                priority=priority
            )
            
            strategy_id = await storage.add_strategy(strategy)
            click.echo(f"Strategy '{name}' added with ID {strategy_id}")
        finally:
            await storage.close()
    
    asyncio.run(run_async())


@cli.group()
@profiler
def domains():
    """Управление доменами"""
    pass


@domains.command('list')
@click.option('--all', 'show_all', is_flag=True, help='Показать все включая неактивные')
@click.pass_context
@profiler
def domains_list(ctx, show_all: bool):
    """Список доменов"""
    config: Config = ctx.obj['config']
    
    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        
        try:
            domains = await storage.list_domains(active_only=not show_all)
            
            if not domains:
                click.echo("No domains found.")
                return
            
            click.echo("\nDomains:")
            click.echo("=" * 60)
            
            for d in domains:
                strategy = await storage.get_strategy_by_id(d.strategy_id)
                strategy_name = strategy.name if strategy else f"ID:{d.strategy_id}"
                
                status = "✓" if d.is_active else "✗"
                click.echo(f"\n{status} {d.domain}")
                click.echo(f"  Strategy: {strategy_name}")
                click.echo(f"  Fail count: {d.fail_count}")
                click.echo(f"  Added: {d.added_at}")
                if d.last_fail:
                    click.echo(f"  Last fail: {d.last_fail}")
        finally:
            await storage.close()
    
    asyncio.run(run_async())


@domains.command('remove')
@click.argument('domain')
@click.pass_context
@profiler
def domains_remove(ctx, domain: str):
    """Удаление домена"""
    config: Config = ctx.obj['config']

    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        executor = Executor(config)

        try:
            # Сначала удаляем из файла
            domain_info = await storage.get_domain(domain)
            if domain_info:
                strategy = await storage.get_strategy_by_id(domain_info.strategy_id)
                if strategy:
                    success, msg = await executor.remove_domain(domain, strategy.name)
                    if not success and "not found" not in msg.lower():
                        click.echo(f"Failed to remove from file: {msg}")
                        return

            # Потом из БД
            success = await storage.hard_remove_domain(domain)
            if success:
                click.echo(f"Domain '{domain}' removed")
            else:
                click.echo(f"Domain '{domain}' not found")
        finally:
            await storage.close()

    asyncio.run(run_async())


@domains.command('assign')
@click.argument('domain')
@click.argument('strategy_name')
@click.pass_context
@profiler
def domains_assign(ctx, domain: str, strategy_name: str):
    """Привязка домена к стратегии"""
    config: Config = ctx.obj['config']

    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        executor = Executor(config)

        try:
            strategy = await storage.get_strategy(strategy_name)
            if not strategy:
                click.echo(f"Strategy '{strategy_name}' not found")
                return

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
            
            if not success:
                click.echo(f"Failed to apply strategy: {msg}")
                return

            # Потом записываем в БД
            await storage.assign_domain(domain, strategy.id)
            click.echo(f"Domain '{domain}' assigned to strategy '{strategy_name}'")
        finally:
            await storage.close()

    asyncio.run(run_async())


@cli.command()
@click.pass_context
@profiler
def stats(ctx):
    """Показать статистику"""
    config: Config = ctx.obj['config']
    
    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        
        try:
            # Общая статистика
            domains = await storage.list_domains()
            strategies = await storage.list_strategies()
            events = await storage.get_stats(limit=1000)
            
            click.echo("\nAuto-Zapret Statistics")
            click.echo("=" * 40)
            click.echo(f"Total strategies: {len(strategies)}")
            click.echo(f"Total domains: {len(domains)}")
            click.echo(f"Active domains: {sum(1 for d in domains if d.is_active)}")
            click.echo(f"Total events: {len(events)}")
            
            # Статистика по типам событий
            event_types = {}
            for e in events:
                event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
            
            click.echo("\nEvents by type:")
            for etype, count in sorted(event_types.items()):
                click.echo(f"  {etype}: {count}")
            
            # Последние события
            click.echo("\nLast 10 events:")
            recent = await storage.get_stats(limit=10)
            for e in recent:
                click.echo(f"  {e.timestamp}: {e.domain} - {e.event_type}")
        finally:
            await storage.close()
    
    asyncio.run(run_async())


@cli.command()
@click.pass_context
@profiler
def init_db(ctx):
    """Инициализация базы данных стратегиями из конфига"""
    config: Config = ctx.obj['config']
    
    @profiler
    async def run_async():
        storage = Storage(config.database_path)
        await storage.connect()
        
        try:
            if not config.strategies:
                click.echo("No strategies in config file")
                return
            
            await storage.init_from_config(config.strategies)
            click.echo(f"Initialized {len(config.strategies)} strategies from config")
        finally:
            await storage.close()
    
    asyncio.run(run_async())


@profiler
def main():
    """Точка входа для console script"""
    cli(obj={})


if __name__ == '__main__':
    main()
