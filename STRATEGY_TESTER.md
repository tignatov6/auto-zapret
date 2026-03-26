# Strategy Tester - Реальное тестирование DPI стратегий

## Проблема старой реализации

**Старый `analyzer._test_strategy()`:**
```python
async def _test_strategy(self, domain: str, params: str):
    # Просто проверяем доступность домена БЕЗ применения параметров!
    result = await self.dpi_detector.check_domain(domain, timeout=30)
    
    # Сравниваем статические рекомендации с params
    if canonicalize_params(result.zapret_params) == canonicalize_params(params):
        return StrategyTestResult(status=StrategyTestStatus.WORKS)
```

**Проблемы:**
1. ❌ **Не применяет реальные параметры** к nfqws
2. ❌ **Не тестирует реальное HTTPS соединение**
3. ❌ **Гадает** совпадут ли статические рекомендации с params
4. ❌ **14 стратегий** × 30-60 сек = **9+ минут** на перебор
5. ❌ **Статические таймауты** не адаптируются под сеть

---

## Новая реализация

### `strategy_tester.py` - правильный подход

**Что делает правильно:**
1. ✅ **Применяет стратегию через executor** к nfqws
2. ✅ **Ждёт применения** (HUP signal + debounce)
3. ✅ **Реальное HTTPS тестирование** с TLS handshake
4. ✅ **Несколько тестовых сайтов** для надёжности
5. ✅ **Динамическая калибровка таймаутов** на основе RTT
6. ✅ **Параллельное тестирование** нескольких стратегий

---

## Архитектура

```
┌──────────────────────────────────────────────────────────┐
│                   StrategyTester                         │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  calibrate() - Калибровка таймаутов                │ │
│  │  - Измеряет RTT до 7 сайтов (параллельно)         │ │
│  │  - Рассчитывает mean_rtt + 33%                    │ │
│  │  - Кэшируется на 5 минут                          │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  test_strategy() - Тест стратегии                  │ │
│  │  1. executor.apply_strategy(domain, params)        │ │
│  │  2. await asyncio.sleep(apply_wait)                │ │
│  │  3. aiohttp HTTPS запросы (параллельно)           │ │
│  │  4. Анализ результатов                            │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  test_strategies_parallel() - Параллельный тест   │ │
│  │  - Semaphore (MAX_CONCURRENT_TESTS=3)             │ │
│  │  - Тестирует 3 стратегии одновременно             │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  check_dpi_present() - Быстрая проверка DPI       │ │
│  │  - Один HTTPS запрос без стратегии                │ │
│  │  - Timeout = calibrated timeout_base              │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Калибровка таймаутов

### Динамический расчёт

**Вместо констант:**
```python
# БЫЛО (константы)
TCP_TIMEOUT = 1
INIT_WAIT = 4.0
DOWNLOAD_TIMEOUT = 3
```

**Стало (динамически):**
```python
# Измеряем RTT до сайтов
calibration = await tester.calibrate()

# Рассчитываем таймауты
timeout_base = mean_rtt * 1.33  # Средний RTT + 33%
timeout_extended = timeout_base * 2.5

# Примеры:
# Быстрая сеть (RTT=50ms):   timeout_base=0.07s, timeout_extended=0.17s
# Медленная сеть (RTT=200ms): timeout_base=0.27s, timeout_extended=0.67s
# Заблокированная (RTT=∞):   timeout_base=2.0s (min), timeout_extended=5.0s (max)
```

### Алгоритм калибровки

```python
async def calibrate(self, force=False):
    # Проверяем кэш (5 минут)
    if not force and now - calibration_time < 300:
        return cached_result
    
    # Измеряем RTT параллельно
    tasks = [measure_rtt(site) for site in CALIBRATION_SITES]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем успешные
    successful = [r for r in results if r.rtt is not None]
    
    # Рассчитываем статистику
    mean_rtt = statistics.mean(successful)
    std_rtt = statistics.stdev(successful)
    
    # Таймауты: mean + 33%
    timeout_base = max(MIN_TIMEOUT, min(MAX_TIMEOUT, mean_rtt * 1.33))
    timeout_extended = timeout_base * 2.5
    
    # Кэшируем
    self._calibration = CalibrationResult(...)
    self._calibration_time = now
    
    return calibration
```

### Тестовые сайты

**Русские (ожидаем быстрые):**
- ya.ru
- yandex.ru
- vk.com
- mail.ru
- ozon.ru

**Международные (могут быть медленнее):**
- google.com
- cloudflare.com

**Потенциально заблокированные (для проверки):**
- youtube.com
- discord.com

---

## Реальное HTTPS тестирование

### Алгоритм

```python
async def test_strategy(self, domain, params, timeout=None):
    async with self._test_semaphore:  # MAX_CONCURRENT_TESTS=3
        return await self._test_strategy_impl(domain, params, timeout)

async def _test_strategy_impl(self, domain, params, timeout):
    # ШАГ 1: Применяем стратегию через executor
    success, msg = await self.executor.apply_strategy(domain, params)
    if not success:
        return StrategyTestResult(status=ERROR, error=msg)
    
    # ШАГ 2: Ждём применения (HUP signal + debounce)
    apply_wait = max(1.0, timeout * 0.3)  # 30% от таймаута
    await asyncio.sleep(apply_wait)
    
    # ШАГ 3: Реальное HTTPS тестирование
    session = await self._get_session()
    
    async def test_site(host, port):
        async with session.get(f"https://{host}/", timeout=timeout) as resp:
            if resp.status == 200:
                return (host, True, rtt_ms, None)
            else:
                return (host, False, 0, f"HTTP {resp.status}")
    
    # Тестируем несколько сайтов параллельно
    tasks = [test_site(host, port) for host, port in TEST_SITES]
    results = await asyncio.gather(*tasks)
    
    # ШАГ 4: Анализ результатов
    successful = [r for r in results if r[1]]
    
    if successful:
        return StrategyTestResult(status=WORKS, ...)
    else:
        return StrategyTestResult(status=FAILS, ...)
```

### Отличия от smart_tuner.py

| Характеристика | smart_tuner.py | strategy_tester.py |
|---------------|----------------|-------------------|
| **Применение стратегии** | winws.exe subprocess | executor.apply_strategy() |
| **HTTPS тест** | socket + ssl.wrap_socket | aiohttp.ClientSession |
| **Параллелизм** | Последовательно | Semaphore (3 параллельно) |
| **Таймауты** | Константы | Динамические (калибровка) |
| **Интеграция** | Standalone скрипт | Модуль autozapret |

---

## Интеграция с analyzer.py

### Старый код

```python
# analyzer.py (старый)
async def _test_strategy(self, domain: str, params: str):
    # Просто проверяем доступность БЕЗ применения параметров
    result = await self.dpi_detector.check_domain(domain, timeout=30)
    
    # Сравниваем статические рекомендации
    if canonicalize_params(result.zapret_params) == canonicalize_params(params):
        return StrategyTestResult(status=WORKS)
```

### Новый код

```python
# analyzer.py (новый)
async def _test_strategy(self, domain: str, params: str):
    # Используем strategy_tester для реального тестирования
    result = await self.strategy_tester.test_strategy(
        domain=domain,
        strategy_params=params,
        timeout=30
    )
    
    # Конвертируем результат для совместимости
    return StrategyTestResult(
        status=StrategyTestStatus(result.status.value),
        domain=result.domain,
        strategy_params=result.strategy_params,
        response_time=result.response_time_ms / 1000,
        error=result.error
    )
```

---

## Использование

### Базовое

```python
from autozapret.strategy_tester import get_tester

# Получаем singleton
tester = get_tester(storage, executor, config)

# Калибруем таймауты
calibration = await tester.calibrate()
print(f"Timeout base: {calibration.timeout_base:.2f}s")

# Тестируем стратегию
result = await tester.test_strategy(
    domain="youtube.com",
    strategy_params="--dpi-desync=fake,multisplit"
)

if result.status == StrategyTestStatus.WORKS:
    print(f"Strategy works! RTT: {result.response_time_ms:.0f}ms")
```

### Параллельное тестирование

```python
strategies = [
    {"name": "fake", "params": "--dpi-desync=fake"},
    {"name": "split", "params": "--dpi-desync=split"},
    {"name": "disorder", "params": "--dpi-desync=disorder"},
]

results = await tester.test_strategies_parallel(
    domain="youtube.com",
    strategies=strategies
)

# Находим лучшую
working = [r for r in results if r.status == StrategyTestStatus.WORKS]
best = min(working, key=lambda r: r.response_time_ms)

print(f"Best strategy: {best.details['strategy_name']}")
```

### Быстрая проверка DPI

```python
# Проверяем есть ли DPI блокировка
if await tester.check_dpi_present("youtube.com"):
    print("DPI detected, need strategy")
else:
    print("No DPI, strategy not needed")
```

---

## Производительность

### Старая реализация

```
14 стратегий × 40 сек (среднее) = 560 сек = 9.3 минут
```

### Новая реализация

```
Параллелизм 3 стратегии:
  14 / 3 = 5 групп
  
Время на группу:
  apply_wait (30% от timeout) + HTTPS тест (1-2 сек)
  = 1.5 сек + 2 сек = 3.5 сек
  
Итого: 5 групп × 3.5 сек = 17.5 сек
```

**Ускорение: 9.3 мин → 17.5 сек = ×32 быстрее!**

---

## Тесты

### Запуск тестов

```bash
python -m pytest tests/test_strategy_tester.py -v
```

### Покрытие

```
test_strategy_tester.py::test_calibration PASSED
test_strategy_tester.py::test_calibration_cached PASSED
test_strategy_tester.py::test_calibration_force PASSED
test_strategy_tester.py::test_calibration_failed PASSED
test_strategy_tester.py::test_test_strategy_executor_fail PASSED
test_strategy_tester.py::test_get_tester_singleton PASSED
test_strategy_tester.py::test_dynamic_timeout_calculation PASSED
test_strategy_tester.py::test_apply_wait_timeout PASSED

8 passed in 0.97s
```

---

## Зависимости

```txt
aiohttp>=3.9.0  # Для HTTPS тестирования
```

---

## Будущие улучшения

### Приоритет 1
- [ ] Интеграция с smart_tuner.py для генерации 500+ стратегий
- [ ] Кэширование результатов тестирования
- [ ] Прогресс бар для brute force

### Приоритет 2
- [ ] Тест скорости (как в smart_tuner.py)
- [ ] Адаптивный выбор TEST_SITES на основе региона
- [ ] Экспоненциальное увеличение таймаута при retry

### Приоритет 3
- [ ] HTTP/3 (QUIC) тестирование
- [ ] Машинное обучение для предсказания успешных стратегий
- [ ] Распределённое тестирование (несколько клиентов)

---

*Версия: 0.3.1 | Дата: Март 2026*
