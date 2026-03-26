# Перебор стратегий Auto-Zapret - Полная реализация

## Реализованные компоненты

### ✅ 1. Strategy Generator (`strategy_generator.py`)

**Назначение:** Генерация 500+ стратегий для перебора

**Особенности:**
- Основан на логике smart_tuner.py и blockcheck.sh
- Генерирует стратегии всех типов:
  - **Базовые Split** (multisplit, multidisorder) - ~40 стратегий
  - **WSSIZE** (window size) - ~12 стратегий
  - **SeqOvl** (sequence overlap) - ~12 стратегий
  - **Fake с TTL циклом** (1-16) - ~512 стратегий
  - **Fake с AutoTTL** (1-8) - ~64 стратегии
  - **Fake TLS моды** - 2 стратегии
  - **HostFakeSplit моды** - 2 стратегии
  - **HTTP моды** - 3 стратегии

**Результат:**
- Без fake файлов: **59 стратегий**
- С fake файлами: **679 стратегий**

### ✅ 2. Strategy Tester (`strategy_tester.py`)

**Назначение:** Реальное тестирование стратегий

**Особенности:**
- **Динамическая калибровка таймаутов**
  - Измеряет RTT до 9 сайтов (ya.ru, yandex.ru, vk.com, mail.ru, ozon.ru, google.com, cloudflare.com, youtube.com, discord.com)
  - Рассчитывает `timeout_base = mean_rtt × 1.33`
  - Кэшируется на 5 минут
  
- **Реальное HTTPS тестирование**
  - Применяет стратегию через `executor.apply_strategy()`
  - Ждёт применения (HUP signal + debounce)
  - Делает HTTPS запросы через `aiohttp`
  - Тестирует несколько сайтов параллельно

- **Параллельное тестирование**
  - Semaphore ограничивает `MAX_CONCURRENT_TESTS=3`
  - Тестирует 3 стратегии одновременно

**Производительность:**
```
Старая реализация (14 стратегий):
  14 × 40 сек = 560 сек = 9.3 минут

Новая реализация (679 стратегий):
  679 / 3 = 226 групп
  226 × 3.5 сек = 791 сек = 13.2 минут
  
Ускорение на стратегию: ×32
```

### ✅ 3. Интеграция с Analyzer (`analyzer.py`)

**Обновлённый метод `_brute_force_strategies()`:**

```python
async def _brute_force_strategies(self, domain: str) -> BruteForceResult:
    # 1. Генерируем стратегии
    strategies = self.strategy_generator.generate_all()
    total = len(strategies)  # 59 или 679
    
    # 2. Тестируем пачками по 3
    for i in range(0, total, batch_size=3):
        batch = strategies[i:i + batch_size]
        
        results = await self.strategy_tester.test_strategies_parallel(
            domain=domain,
            strategies=[{"name": s.name, "params": s.to_params()} for s in batch]
        )
        
        # 3. Проверяем результаты
        for result in results:
            if result.status == StrategyTestStatus.WORKS:
                return BruteForceResult(FOUND, params=result.strategy_params)
            
            if result.status == StrategyTestStatus.NO_DPI:
                return BruteForceResult(NO_DPI)
```

---

## Сравнение с smart_tuner.py

| Характеристика | smart_tuner.py | Auto-Zapret |
|---------------|----------------|-------------|
| **Генерация стратегий** | ✅ 518+ | ✅ 679 |
| **Применение стратегии** | ✅ winws.exe subprocess | ✅ executor.apply_strategy() |
| **HTTPS тест** | ✅ socket + ssl | ✅ aiohttp |
| **Параллелизм** | ❌ Последовательно | ✅ Semaphore (3) |
| **Таймауты** | ❌ Константы | ✅ Динамические |
| **Калибровка** | ❌ Нет | ✅ 9 сайтов |
| **Интеграция** | ❌ Standalone | ✅ Модуль auto-zapret |
| **Brute force время** | ~30 минут | ~13 минут |

---

## Примеры использования

### 1. Генерация стратегий

```python
from autozapret.strategy_generator import StrategyGenerator

# Без fake файлов
gen = StrategyGenerator(has_fake_files=False)
strategies = gen.generate_all()
print(f"Generated {len(strategies)} strategies")  # 59

# С fake файлами
gen2 = StrategyGenerator(has_fake_files=True)
strategies2 = gen2.generate_all()
print(f"Generated {len(strategies2)} strategies")  # 679

# Преобразование в параметры
for strat in strategies[:5]:
    print(f"{strat.name}: {strat.to_params()}")
```

**Пример вывода:**
```
multisplit_sniext+1_ts_R1: --dpi-desync=multisplit --dpi-desync-split-pos=sniext+1 --dpi-desync-fooling=ts --dpi-desync-repeats=1
multisplit_1_ts_R1: --dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=1
...
fake_p__TTL1_ts_R2: --dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=ts --dpi-desync-repeats=2
fake_autottl-1_R2: --dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-autottl=-1
```

### 2. Тестирование стратегии

```python
from autozapret.strategy_tester import StrategyTester, get_tester

# Получаем singleton
tester = get_tester(storage, executor, config)

# Калибруем таймауты
calibration = await tester.calibrate()
print(f"Mean RTT: {calibration.mean_rtt_ms:.0f}ms")
print(f"Timeout base: {calibration.timeout_base:.2f}s")

# Тестируем стратегию
result = await tester.test_strategy(
    domain="youtube.com",
    strategy_params="--dpi-desync=fake,multisplit"
)

if result.status == StrategyTestStatus.WORKS:
    print(f"Strategy works! RTT: {result.response_time_ms:.0f}ms")
```

### 3. Параллельное тестирование

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
if working:
    best = min(working, key=lambda r: r.response_time_ms)
    print(f"Best: {best.details['strategy_name']} ({best.response_time_ms:.0f}ms)")
```

---

## Тесты

### Strategy Generator

```bash
python -m pytest tests/test_strategy_generator.py -v
```

**Результат:**
```
15 passed in 0.52s
```

### Strategy Tester

```bash
python -m pytest tests/test_strategy_tester.py -v
```

**Результат:**
```
8 passed in 0.70s
```

---

## Структура стратегии

```python
@dataclass
class StrategyConfig:
    name: str              # Уникальное имя
    mode: str              # Режим: fake, split, disorder, multisplit, ...
    pos: Optional[str]     # Позиция split: 1, 2, sniext+1, midsld, ...
    fool: Optional[str]    # Fooling: ts, md5sig, badsum, badseq, datanoack
    rep: int = 1           # Повторения: 1, 2, 3
    wssize: Optional[str]  # Window size: None, "1:6"
    ttl: Optional[int]     # TTL: None, 1-16
    autottl: Optional[str] # AutoTTL: None, "-1" .. "-8"
    seqovl: Optional[int]  # Sequence overlap: None, 1, 2
    fake_tls_mod: Optional[str]  # Fake TLS mod: None, "rnd,rndsni,dupsid", ...
    extra: List[str]       # Дополнительные параметры
    
    def to_params(self) -> str:
        """Преобразовать в параметры командной строки"""
        params = []
        if self.mode: params.append(f"--dpi-desync={self.mode}")
        if self.pos: params.append(f"--dpi-desync-split-pos={self.pos}")
        if self.fool: params.append(f"--dpi-desync-fooling={self.fool}")
        if self.rep: params.append(f"--dpi-desync-repeats={self.rep}")
        if self.wssize: params.append(f"--wssize={self.wssize}")
        if self.ttl: params.append(f"--dpi-desync-ttl={self.ttl}")
        if self.autottl: params.append(f"--dpi-desync-autottl={self.autottl}")
        if self.seqovl: params.append(f"--dpi-desync-split-seqovl={self.seqovl}")
        if self.fake_tls_mod: params.append(f"--dpi-desync-fake-tls-mod={self.fake_tls_mod}")
        if self.extra: params.extend(self.extra)
        return " ".join(params)
```

---

## Приоритеты стратегий

Стратегии генерируются в порядке приоритета:

1. **Базовые Split** (приоритет 1) - Самые быстрые и надёжные
2. **WSSIZE** (приоритет 2) - Модификация window size
3. **SeqOvl** (приоритет 3) - Sequence overlap
4. **Fake с TTL** (приоритет 4) - Требуют fake файлы, медленные
5. **Fake TLS моды** (приоритет 5) - Специфичные модификаторы
6. **HostFakeSplit моды** (приоритет 6) - Экзотические варианты
7. **HTTP моды** (приоритет 7) - Для HTTP трафика

Перебор останавливается на первой рабочей стратегии.

---

## Будущие улучшения

### Приоритет 1
- [ ] Кэширование результатов тестирования для доменов
- [ ] Прогресс бар в Web UI
- [ ] Статистика успешных стратегий

### Приоритет 2
- [ ] Тест скорости (как в smart_tuner.py)
- [ ] Адаптивный выбор TEST_SITES на основе региона
- [ ] Экспоненциальное увеличение таймаута при retry

### Приоритет 3
- [ ] HTTP/3 (QUIC) тестирование
- [ ] Машинное обучение для предсказания успешных стратегий
- [ ] Распределённое тестирование (несколько клиентов)

---

*Версия: 0.4.0 | Дата: Март 2026*
