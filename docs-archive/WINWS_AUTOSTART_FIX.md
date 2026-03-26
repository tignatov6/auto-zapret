# Автозапуск winws с закрытием существующего

## Дата: 2026-03-25

---

## ✅ Реализованная функциональность

### Принудительное закрытие существующего winws перед автозапуском

**Проблема:**
- Пользователь мог запустить winws вручную до запуска Auto-Zapret
- Или winws остался запущен после предыдущего сеанса
- Это приводило к конфликту портов и некорректной работе

**Решение:**
При старте Auto-Zapret:
1. **Проверяет** наличие запущенных процессов winws.exe
2. **Закрывает** ВСЕ процессы winws (даже запущенные вне Auto-Zapret)
3. **Запускает** winws с сохраненными стратегиями Auto-Zapret

---

## 🔧 Реализация

### Изменения в `autozapret/main.py`

**Было:**
```python
async def run(self) -> None:
    """Запуск основного цикла"""
    self._running = True
    
    logger.info("Starting Auto-Zapret main loop...")
    
    # Автозапуск winws
    try:
        logger.info("Checking for saved strategies to restore...")
        await self.executor.restart_winws_full()
        logger.info("WinWS started with saved strategies")
    except Exception as e:
        logger.warning(f"Failed to auto-start WinWS: {e}")
```

**Стало:**
```python
async def run(self) -> None:
    """Запуск основного цикла"""
    self._running = True
    
    logger.info("Starting Auto-Zapret main loop...")
    
    # ═══════════════════════════════════════════════════════
    # АВТОЗАПУСК WINWS ПРИ СТАРТЕ
    # 1. Закрываем все существующие winws (даже запущенные вне Auto-Zapret)
    # 2. Запускаем winws с сохраненными стратегиями Auto-Zapret
    # ═══════════════════════════════════════════════════════
    try:
        logger.info("Checking for existing winws processes...")
        
        # Закрываем ВСЕ процессы winws (даже если запущены не через Auto-Zapret)
        await self.executor.stop_winws()
        
        logger.info("Starting winws with saved strategies...")
        await self.executor.restart_winws_full(self.nfqws_generator)
        logger.info("✅ WinWS started with saved strategies")
    except Exception as e:
        logger.warning(f"Failed to auto-start WinWS: {e}")
```

---

## 📋 Детали реализации `stop_winws()`

Метод `executor.stop_winws()` делает следующее:

### 1. **Остановка "нашего" процесса winws**
```python
if self._winws_process is not None:
    self._winws_process.terminate()
    self._winws_process.wait(timeout=3)
```

### 2. **Принудительное убийство ВСЕХ процессов winws.exe**
```python
if sys.platform == 'win32':
    subprocess.run(
        ['taskkill', '/F', '/IM', 'winws.exe'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5
    )
```

**Команда `taskkill /F /IM winws.exe`:**
- `/F` — принудительное завершение (force)
- `/IM` — по имени образа (image name)
- `winws.exe` — имя процесса

**Результат:** Убивает **ВСЕ** процессы `winws.exe` в системе, независимо от того:
- Кто их запустил
- С какими параметрами
- От имени какого пользователя

### 3. **Пауза на завершение**
```python
await asyncio.sleep(0.3)
```

---

## 📊 Сценарии работы

### Сценарий 1: **WinWS не запущен**
```
[INFO] Checking for existing winws processes...
[DEBUG] Running taskkill /F /IM winws.exe...
[INFO] Starting winws with saved strategies...
[INFO] ✅ WinWS started with saved strategies
```

**Результат:** taskkill не находит процессов (это нормально), запускается новый winws.

---

### Сценарий 2: **WinWS запущен вручную**
```
[INFO] Checking for existing winws processes...
[DEBUG] Running taskkill /F /IM winws.exe...
[INFO] Starting winws with saved strategies...
[INFO] ✅ WinWS started with saved strategies
```

**Результат:** Существующий winws убит, запущен новый с параметрами Auto-Zapret.

---

### Сценарий 3: **WinWS запущен другим экземпляром Auto-Zapret**
```
[INFO] Checking for existing winws processes...
[DEBUG] Running taskkill /F /IM winws.exe...
[INFO] Starting winws with saved strategies...
[INFO] ✅ WinWS started with saved strategies
```

**Результат:** Старый процесс убит, новый запущен с актуальными стратегиями.

---

### Сценарий 4: **Ошибка запуска**
```
[INFO] Checking for existing winws processes...
[DEBUG] Running taskkill /F /IM winws.exe...
[INFO] Starting winws with saved strategies...
[WARNING] Failed to auto-start WinWS: winws.exe not found
```

**Результат:** WinWS не запущен, Auto-Zapret продолжает работу (Monitor отслеживает события).

---

## 🧪 Тестирование

### Тест 1: **Проверка закрытия существующего winws**

**Шаги:**
1. Запустите winws вручную:
   ```bash
   D:\t1pe\Projects\auto-zapret\zapret-src\nfq\winws.exe --filter-tcp=443
   ```
2. Проверьте что процесс запущен:
   ```bash
   tasklist | findstr winws
   # winws.exe                     1234 Console    1     1,234 K
   ```
3. Запустите Auto-Zapret:
   ```bash
   python -m autozapret.main serve
   ```
4. Проверьте логи Auto-Zapret

**Ожидаемые логи:**
```
[INFO] Checking for existing winws processes...
[DEBUG] Running taskkill /F /IM winws.exe...
[INFO] Starting winws with saved strategies...
[INFO] ✅ WinWS started with saved strategies
```

5. Проверьте tasklist снова:
   ```bash
   tasklist | findstr winws
   # winws.exe                     5678 Console    1     2,345 K
   ```

**Результат:** PID изменился (1234 → 5678) — старый процесс убит, новый запущен.

---

### Тест 2: **Проверка с несколькими процессами winws**

**Шаги:**
1. Запустите несколько процессов winws:
   ```bash
   start /B winws.exe --filter-tcp=443
   start /B winws.exe --filter-tcp=80
   start /B winws.exe --dpi-desync=fake
   ```
2. Проверьте:
   ```bash
   tasklist | findstr winws
   # winws.exe                     1111
   # winws.exe                     2222
   # winws.exe                     3333
   ```
3. Запустите Auto-Zapret

**Ожидаемый результат:**
```
[DEBUG] Running taskkill /F /IM winws.exe...
# Все 3 процесса убиты
[INFO] ✅ WinWS started with saved strategies
# Запущен 1 новый процесс с правильными параметрами
```

---

### Тест 3: **Проверка параметров запуска**

**Шаги:**
1. Примените стратегии для нескольких доменов через UI
2. Перезапустите Auto-Zapret
3. Проверьте параметры запущенного winws

**Ожидаемые логи:**
```
[executor] Полный рестарт winws со всеми профилями...
[executor] Generated 28 args
[executor] winws перезапущен с 28 аргументами (все стратегии)
```

**Проверка через Process Explorer:**
```
winws.exe --new --filter-tcp=443 --hostlist=D:\...\strat-strategy_abc.txt 
          --new --filter-tcp=443 --hostlist=D:\...\strat-strategy_xyz.txt
          ...
```

---

## ⚠️ Важные замечания

### 1. **Права доступа**

Для выполнения `taskkill /F /IM winws.exe` могут потребоваться права администратора.

**Решение:** Запускайте Auto-Zapret от имени администратора.

---

### 2. **Конфликт с другими скриптами**

Если у вас есть другие скрипты/программы, использующие winws, они будут остановлены.

**Решение:** Убедитесь, что только Auto-Zapret управляет winws.

---

### 3. **Кратковременный разрыв соединения**

При перезапуске winws может быть кратковременный разрыв соединения (0.3-0.5с).

**Влияние:** Минимальное, большинство соединений восстановится автоматически.

---

## 📝 Файлы изменены

| Файл | Изменение |
|------|-----------|
| `autozapret/main.py` | Добавлен вызов `await self.executor.stop_winws()` перед автозапуском |

---

## ✅ Заключение

**Реализована полная автоматизация управления winws:**

1. ✅ При старте Auto-Zapret проверяет наличие запущенных winws
2. ✅ Закрывает ВСЕ процессы winws.exe (taskkill /F /IM)
3. ✅ Запускает winws с сохраненными стратегиями Auto-Zapret
4. ✅ Логирует весь процесс для отладки

**Пользовательский опыт:**
- Запустил Auto-Zapret → winws настроен автоматически
- Не нужно вручную закрывать старые процессы
- Не нужно проверять параметры запуска
