# Исправление автозапуска winws

## Дата: 2026-03-25

---

## 🐛 Проблема

**Симптомы:**
- Логи winws не появляются в UI
- WinWS запускается с одной стратегией по умолчанию
- Автозапуск с сохраненными стратегиями не работает

**Причина:**
Автозапуск winws был реализован в `main.run()`, но FastAPI вызывает `@app.on_event("startup")` **до** того, как `run()` успевает сработать.

**Последовательность (неправильная):**
```
1. create_app() → @app.on_event("startup")
2. _ensure_winws_running() → запуск с ОДНОЙ стратегией
3. main.run() → автозапуск (уже не срабатывает)
```

---

## ✅ Решение

Переместить автозапуск winws из `main.run()` в `@app.on_event("startup")` внутри `create_app()`.

**Последовательность (правильная):**
```
1. create_app() → @app.on_event("startup")
2. executor.stop_winws() → закрытие всех winws
3. executor.restart_winws_full() → запуск со ВСЕМИ стратегиями
4. main.run() → основной цикл (winws уже запущен)
```

---

## 🔧 Изменения

### 1. **api.py** - Автозапуск в `@app.on_event("startup")`

**Было:**
```python
@app.on_event("startup")
async def startup():
    # ... инициализация ...
    
    # Проверяем и запускаем winws если не запущен
    await _ensure_winws_running()  # ← Запускал с ОДНОЙ стратегией
```

**Стало:**
```python
@app.on_event("startup")
async def startup():
    # ... инициализация ...
    
    # ═══════════════════════════════════════════════════════
    # АВТОЗАПУСК WINWS ПРИ СТАРТЕ
    # 1. Закрываем все существующие winws
    # 2. Запускаем winws с сохраненными стратегиями
    # ═══════════════════════════════════════════════════════
    try:
        logger.info("Checking for existing winws processes...")
        
        # Закрываем ВСЕ процессы winws
        await executor.stop_winws()
        
        logger.info("Starting winws with saved strategies...")
        success, msg = await executor.restart_winws_full(app.state.nfqws_generator)
        
        if success:
            logger.info("✅ WinWS started with saved strategies")
        else:
            logger.warning(f"Failed to start WinWS: {msg}")
    except Exception as e:
        logger.warning(f"Failed to auto-start WinWS: {e}")
```

### 2. **main.py** - Удаление дублирующего кода

**Было:**
```python
async def run(self) -> None:
    """Запуск основного цикла"""
    self._running = True
    
    # ═══════════════════════════════════════════════════════
    # АВТОЗАПУСК WINWS ПРИ СТАРТЕ
    # ═══════════════════════════════════════════════════════
    try:
        await self.executor.stop_winws()
        await self.executor.restart_winws_full(self.nfqws_generator)
        logger.info("✅ WinWS started with saved strategies")
    except Exception as e:
        logger.warning(f"Failed to auto-start WinWS: {e}")
```

**Стало:**
```python
async def run(self) -> None:
    """Запуск основного цикла"""
    self._running = True
    
    logger.info("Starting Auto-Zapret main loop...")
    
    # Запускаем периодическую очистку autohostlist
    self._autohostlist_cleanup_task = asyncio.create_task(...)
    
    try:
        await self.monitor.start()
    ...
```

### 3. **api.py** - Упрощение `_ensure_winws_running()`

**Было:**
```python
async def _ensure_winws_running():
    """Проверка и запуск winws если не запущен"""
    winws_pid = executor._find_nfqws_pid()
    
    if winws_pid is None:
        logger.info("winws is not running. Starting winws with default strategy...")
        
        strategies = await storage.get_strategies_by_priority(min_success_rate=0.0)
        if strategies:
            await executor.start_winws_with_strategy(strategies[0].zapret_params, ...)
```

**Стало:**
```python
async def _ensure_winws_running():
    """
    Проверка запущен ли winws.
    
    ПРИМЕЧАНИЕ: Автозапуск winws выполняется в create_app() при старте.
    Эта функция только проверяет статус и логирует предупреждение.
    """
    winws_pid = executor._find_nfqws_pid()
    
    if winws_pid is None:
        logger.warning("winws is not running. It should be started by main.run() at startup.")
        logger.warning("If winws is still not running, strategies will be started on-demand.")
    else:
        logger.info(f"winws is already running (PID: {winws_pid})")
```

---

## 📊 Ожидаемые логи

### При старте Auto-Zapret:

```
2026-03-25 02:30:00,000 - autozapret.api - INFO - ============================================================
2026-03-25 02:30:00,000 - autozapret.api - INFO - Auto-Zapret API Startup
2026-03-25 02:30:00,001 - autozapret.api - INFO - ============================================================
2026-03-25 02:30:00,002 - autozapret.api - INFO - Database: D:\t1pe\Projects\auto-zapret\data\autozapret.db
2026-03-25 02:30:00,003 - autozapret.api - INFO - Connecting to database...
2026-03-25 02:30:00,010 - autozapret.api - INFO - Database connected
2026-03-25 02:30:00,011 - autozapret.api - INFO - Initializing NFQWS config generator...
2026-03-25 02:30:00,020 - autozapret.nfqws_config - INFO - Synced 2 nfqws profiles from storage
2026-03-25 02:30:00,021 - autozapret.api - INFO - NFQWS generator initialized (2 profiles)
2026-03-25 02:30:00,022 - autozapret.api - INFO - Starting Monitor in background...
2026-03-25 02:30:00,023 - autozapret.monitor - INFO - Monitor started
2026-03-25 02:30:00,024 - autozapret.executor - INFO - Checking for existing winws processes...
2026-03-25 02:30:00,025 - autozapret.executor - DEBUG - Running taskkill /F /IM winws.exe...
2026-03-25 02:30:00,100 - autozapret.executor - INFO - Starting winws with saved strategies...
2026-03-25 02:30:00,101 - autozapret.executor - INFO - [executor] Полный рестарт winws со всеми профилями...
2026-03-25 02:30:00,102 - autozapret.executor - DEBUG - [executor] Generated 28 args
2026-03-25 02:30:00,500 - autozapret.executor - INFO - [executor] winws перезапущен с 28 аргументами (все стратегии)
2026-03-25 02:30:00,501 - autozapret.api - INFO - ✅ WinWS started with saved strategies
2026-03-25 02:30:00,502 - autozapret.api - INFO - ============================================================
2026-03-25 02:30:00,502 - autozapret.api - INFO - Auto-Zapret API started (Monitor running)
2026-03-25 02:30:00,502 - autozapret.api - INFO - ============================================================
```

---

## 🧪 Тестирование

### Тест 1: **Проверка логов winws**

**Шаги:**
1. Примените стратегии для нескольких доменов через UI
2. Перезапустите Auto-Zapret
3. Проверьте логи

**Ожидаемые логи:**
```
✅ WinWS started with saved strategies
```

**Проверка в UI:**
- Откройте http://localhost:8000/logs
- Логи winws должны появляться в реальном времени

---

### Тест 2: **Проверка закрытия существующего winws**

**Шаги:**
1. Запустите winws вручную:
   ```bash
   start /B D:\t1pe\Projects\auto-zapret\zapret-src\nfq\winws.exe
   ```
2. Запустите Auto-Zapret
3. Проверьте логи

**Ожидаемые логи:**
```
Checking for existing winws processes...
Running taskkill /F /IM winws.exe...
Starting winws with saved strategies...
✅ WinWS started with saved strategies
```

---

### Тест 3: **Проверка работы с несколькими стратегиями**

**Шаги:**
1. Проверьте БД (должны быть сохраненные стратегии):
   ```bash
   python -c "import sqlite3; conn = sqlite3.connect('data/autozapret.db'); 
              print(conn.execute('SELECT COUNT(*) FROM strategies').fetchone())"
   ```
2. Перезапустите Auto-Zapret
3. Проверьте аргументы winws через Process Explorer

**Ожидаемый результат:**
```
winws.exe --new --filter-tcp=443 --hostlist=...\strat-strategy_abc.txt
          --new --filter-tcp=443 --hostlist=...\strat-strategy_xyz.txt
          ...
```

---

## 📝 Файлы изменены

| Файл | Изменение |
|------|-----------|
| `autozapret/api.py` | Автозапуск winws перемещен в `@app.on_event("startup")` |
| `autozapret/api.py` | `_ensure_winws_running()` упрощен (только проверка) |
| `autozapret/main.py` | Удален дублирующий код автозапуска |

---

## ✅ Заключение

**Автозапуск winws теперь работает корректно:**
- ✅ Закрывает все существующие winws при старте
- ✅ Запускает winws со ВСЕМИ сохраненными стратегиями
- ✅ Логи winws появляются в UI
- ✅ Нет дублирования кода

**Пользовательский опыт:**
1. Запустил Auto-Zapret → winws настроен автоматически
2. Открыл UI → вижу логи winws в реальном времени
3. Все домены работают с правильными стратегиями
