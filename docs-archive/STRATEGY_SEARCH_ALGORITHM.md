# Алгоритм поиска и применения стратегий Auto-Zapret

## Общая схема

```
┌─────────────────────────────────────────────────────────────────┐
│  Monitor обнаруживает fail counter 3/3 для домена              │
│  example.com : profile 2 : fail counter 3/3                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Analyzer.handle_event() получает событие                      │
│  - type: "fail_counter"                                        │
│  - domain: "example.com"                                       │
│  - counter: 3, threshold: 3                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Проверка cooldown (storage.get_strategy_cooldown)             │
│  - Если cooldown активен → выход, ждём истечения               │
│  - Если cooldown истёк → продолжаем                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Проверка текущей стратегии домена                             │
│  - storage.get_domain(domain)                                  │
│  - Если есть активная стратегия → проверяем её первой          │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
┌─────────────────────────────────┐  ┌─────────────────────────────────┐
│  ШАГ 1: Проверка существующих   │  │  ШАГ 2: Подбор новой стратегии  │
│  стратегий (по приоритету)      │  │  (brute force)                  │
└─────────────────────────────────┘  └─────────────────────────────────┘
```

---

## Детальное описание шагов

### Шаг 0: Проверка cooldown

**Файл:** `analyzer.py`, метод `_apply_strategy_to_domain_impl()`

```python
cooldown_until = await self.storage.get_strategy_cooldown(domain)
if cooldown_until:
    # Домен в cooldown - выходим
    logger.info(f"Domain {domain} in cooldown until {cooldown_until}")
    return
```

**Логика:**
- Если для домена установлен cooldown (30 минут после неудачного подбора)
- Все проверки пропускаются до истечения cooldown
- Cooldown устанавливается когда brute force не нашёл рабочую стратегию

**Cooldown устанавливается в:**
```python
# analyzer.py, метод _no_strategy_found()
await self.storage.set_strategy_cooldown(domain, cooldown_minutes, reason)
```

---

### Шаг 1: Проверка существующих стратегий

**Файл:** `analyzer.py`, метод `_apply_strategy_to_domain_impl()`

#### 1.1 Получение текущей стратегии домена

```python
existing_domain = await self.storage.get_domain(domain)
current_strategy = None
if existing_domain and existing_domain.is_active:
    current_strategy = await self.storage.get_strategy_by_id(
        existing_domain.strategy_id
    )
```

**Важно:** Если у домена уже есть стратегия, она проверяется **первой** (оптимизация).

#### 1.2 Получение списка стратегий

```python
strategies = await self.storage.get_strategies_by_priority(min_success_rate=0.0)
```

**SQL запрос** (`storage.py`):
```sql
SELECT * FROM strategies
WHERE success_rate >= 0.0 OR total_checks = 0
ORDER BY priority ASC, success_rate DESC, domains_count DESC
```

**Порядок проверки:**
1. Стратегии с меньшим `priority` (1 = наивысший приоритет)
2. Стратегии с большим `success_rate`
3. Стратегии с большим `domains_count`
4. Стратегии с `total_checks = 0` (untested) тоже включаются

#### 1.3 Тестирование текущей стратегии (если есть)

```python
if current_strategy:
    result = await self._test_strategy(domain, current_strategy.zapret_params)
    
    if result.status == StrategyTestStatus.WORKS:
        # Стратегия работает - обновляем статистику и выходим
        await self.storage.update_strategy_stats(current_strategy.id, success=True)
        await self.storage.reset_fail_count(domain)
        return
    
    elif result.status == StrategyTestStatus.NO_DPI:
        # DPI не обнаружен - стратегия не нужна
        await self.storage.reset_fail_count(domain)
        await self.storage.clear_strategy_cooldown(domain)
        return
    
    else:
        # Стратегия не работает - помечаем как fail
        await self.storage.update_strategy_stats(current_strategy.id, success=False)
```

#### 1.4 Тестирование остальных стратегий

```python
for strategy in strategies:
    if current_strategy and strategy.id == current_strategy.id:
        continue  # Уже проверили
    
    result = await self._test_strategy(domain, strategy.zapret_params)
    
    if result.status == StrategyTestStatus.WORKS:
        # Найдена рабочая стратегия!
        if current_strategy and current_strategy.id != strategy.id:
            # Reassign - перенос с одной стратегии на другую
            await self.executor.reassign_domain(
                domain, current_strategy.name, strategy.name
            )
        else:
            # Apply - применение к домену без стратегии
            await self.executor.apply_strategy(domain, strategy.name)
        
        await self.storage.assign_domain(domain, strategy.id)
        await self.storage.update_strategy_stats(strategy.id, success=True)
        return
    
    elif result.status == StrategyTestStatus.NO_DPI:
        # DPI не обнаружен - стратегия не нужна
        await self.storage.reset_fail_count(domain)
        await self.storage.clear_strategy_cooldown(domain)
        return
    
    else:
        # Стратегия не подошла
        await self.storage.update_strategy_stats(strategy.id, success=False)
```

---

### Шаг 2: Подбор новой стратегии (Brute Force)

**Файл:** `analyzer.py`, метод `_brute_force_strategies()`

Запускается если **ни одна существующая стратегия не подошла**.

#### 2.1 DPI Detector (основной метод)

```python
result = await self.dpi_detector.check_domain(domain, timeout=60)
```

**Возможные результаты:**

| Статус | Описание | Действие |
|--------|----------|----------|
| `DPI_DETECTED` + `zapret_params` | Найдены рабочие параметры | Используем эти параметры |
| `NO_DPI` | DPI не обнаружен | Стратегия не нужна |
| `DNS_BLOCKED` | DNS блокировка | Ставим cooldown |
| `IP_BLOCKED` | IP блокировка | Ставим cooldown |
| `ERROR` | Ошибка проверки | Fallback на перебор |

#### 2.2 Проверка существующей стратегии с такими параметрами

```python
if result.zapret_params:
    existing_strategy = await self.storage.get_strategy_by_params(
        result.zapret_params
    )
    
    if existing_strategy:
        # Используем существующую стратегию
        strategy_id = existing_strategy.id
        strategy_name = existing_strategy.name
    else:
        # Создаём новую стратегию
        strategy_name = f"strategy_{uuid4().hex[:12]}"
        strategy_id, was_created = await self.storage.create_strategy(
            name=strategy_name,
            params=result.zapret_params,
            description=result.method
        )
```

#### 2.3 Fallback brute force (резервный метод)

Если DPI detector не нашёл параметры, используется перебор заранее заданных комбинаций.

**Файл:** `analyzer.py`, метод `_fallback_brute_force()`

```python
BRUTE_FORCE_STRATEGIES = [
    {"params": "--dpi-desync=fake", "description": "Fake packets"},
    {"params": "--dpi-desync=split", "description": "Split only"},
    {"params": "--disorder", "description": "Disorder only"},
    {"params": "--dpi-desync=fake,split", "description": "Fake + Split"},
    # ... ещё 10+ комбинаций
]

for i, strat in enumerate(BRUTE_FORCE_STRATEGIES):
    result = await self.dpi_detector.check_domain(domain, timeout=30)
    
    if result.status == DPIStatus.DPI_DETECTED and result.zapret_params:
        # Найдена рабочая комбинация
        return BruteForceResult(
            status=BruteForceStatus.FOUND,
            params=result.zapret_params,
            description=strat["description"]
        )
```

#### 2.4 Если стратегия не найдена

```python
if bf_result.status == BruteForceStatus.NOT_FOUND:
    # Ни одна стратегия не подошла
    await self._no_strategy_found(domain)
    return
```

**Метод `_no_strategy_found()`:**
```python
async def _no_strategy_found(self, domain: str) -> None:
    """Установка cooldown когда стратегия не найдена"""
    cooldown_minutes = self.config.strategy_cooldown_minutes  # 30 минут
    
    await add_log_entry({
        "type": "no_strategy",
        "domain": domain,
        "message": f"⚠️ No working strategy found after {attempts} attempts"
    })
    
    await self.storage.set_strategy_cooldown(
        domain, cooldown_minutes, "No working strategy found"
    )
```

---

## Метод тестирования стратегии

**Файл:** `analyzer.py`, метод `_test_strategy()`

```python
async def _test_strategy(self, domain: str, params: str) -> StrategyTestResult:
    """
    Тестирование стратегии на домене через DPI detector
    """
    # Проверяем домен через DPI detector
    result = await self.dpi_detector.check_domain(domain, timeout=30)
    
    if result.status == DPIStatus.NO_DPI:
        # DPI не обнаружен - стратегия не нужна
        return StrategyTestResult(status=StrategyTestStatus.NO_DPI)
    
    if result.status == DPIStatus.DPI_DETECTED:
        if result.zapret_params:
            # Сравниваем параметры (после канонизации)
            normalized_result = canonicalize_params(result.zapret_params)
            normalized_test = canonicalize_params(params)
            
            if normalized_result == normalized_test:
                # Параметры совпадают - стратегия работает
                return StrategyTestResult(status=StrategyTestStatus.WORKS)
        
        # Параметры не совпали
        return StrategyTestResult(status=StrategyTestStatus.FAILS)
    
    if result.status == DPIStatus.DNS_BLOCKED:
        return StrategyTestResult(status=StrategyTestStatus.DNS_BLOCKED)
    
    if result.status == DPIStatus.IP_BLOCKED:
        return StrategyTestResult(status=StrategyTestStatus.IP_BLOCKED)
```

**Важно:** Тестирование **не использует** переданные `params` для проверки! Оно проверяет какие параметры нашёл DPI detector и сравнивает их с тестируемыми.

---

## Диаграмма состояний домена

```
                    ┌─────────────────┐
                    │  Домен добавлен │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
              ┌─────│  Активный (OK)  │─────┐
              │     └────────┬────────┘     │
              │              │              │
              │              ▼              │
              │     ┌─────────────────┐     │
              │     │ Fail counter +1 │     │
              │     └────────┬────────┘     │
              │              │              │
              │              ▼              │
              │     ┌─────────────────┐     │
              │     │ Counter < 3?    │     │
              │     └────────┬────────┘     │
              │              │ yes          │
              │              │              │
              │              ▼ no           │
              │     ┌─────────────────┐     │
              │     │  Запуск анализа │     │
              │     └────────┬────────┘     │
              │              │              │
              │    ┌─────────┴─────────┐    │
              │    │                   │    │
              │    ▼                   ▼    │
              │ ┌─────────────┐  ┌─────────────┐
              │ │ Найдена     │  │ Не найдена  │
              │ │ стратегия   │  │ стратегия   │
              │ └──────┬──────┘  └──────┬──────┘
              │        │                │
              │        │                ▼
              │        │         ┌─────────────┐
              │        │         │ Cooldown 30 │
              │        │         │ минут       │
              │        │         └──────┬──────┘
              │        │                │
              │        ▼                │
              │ ┌─────────────┐         │
              │ │ Применить   │◄────────┘
              │ │ стратегию   │
              │ └──────┬──────┘
              │        │
              ▼        ▼
       ┌──────────────────┐
       │ Домен на стратегии│
       └──────────────────┘
```

---

## Примеры логов с пояснениями

### Успешный подбор стратегии

```
00:31:48 🔴 fail_counter cloudflare-ech.com TLS Fail counter: 3/3 (tls)
         │
         └─> Порог достигнут, запуск анализа

00:31:48 ⚠️ threshold_reached cloudflare-ech.com tls
         │
         └─> Threshold reached (3), starting strategy selection

00:31:48 🔍 checking_existing cloudflare-ech.com tls
         │
         └─> Проверяем существующие стратегии для домена

00:31:48 🚀 brute_force_start cloudflare-ech.com
         │
         └─> Существующие стратегии не подошли, запуск brute force

00:31:48 📝 brute_force_no_dpi cloudflare-ech.com
         │
         └─> DPI не обнаружен - стратегия не нужна

00:31:48 📝 no_dpi cloudflare-ech.com
         │
         └─> Финальное подтверждение: No DPI detected
```

### Неудачный подбор (cooldown)

```
00:29:03 ❌ brute_force_failed www.googleadservices.com
         │
         └─> Ни одна из 14 стратегий не подошла

00:29:03 ⏸️ cooldown_set www.googleadservices.com
         │
         └─> Установлен cooldown 30 минут
```

### Успешное применение существующей стратегии

```
00:28:09 🔴 fail_counter beacons.gcp.gvt2.com TLS Fail counter: 3/3
         │
         └─> Порог достигнут

00:28:09 🔍 checking_existing beacons.gcp.gvt2.com tls
         │
         └─> Проверяем существующие стратегии

00:28:10 📝 no_dpi beacons.gcp.gvt2.com
         │
         └─> DPI не обнаружен при проверке
         └─> Стратегия не нужна, домен разблокирован
```

---

## База данных: связанные таблицы

### Таблица `strategies`

| Колонка | Тип | Описание |
|---------|-----|----------|
| `id` | INTEGER | Уникальный ID стратегии |
| `name` | TEXT | Уникальное имя |
| `zapret_params` | TEXT | Параметры Zapret |
| `params_canonical` | TEXT | Нормализованные параметры (для уникальности) |
| `priority` | INTEGER | Приоритет (меньше = выше) |
| `success_rate` | REAL | Процент успешных проверок (0.0-1.0) |
| `total_checks` | INTEGER | Всего проверок |
| `domains_count` | INTEGER | Количество доменов на стратегии |

### Таблица `domains`

| Колонка | Тип | Описание |
|---------|-----|----------|
| `domain` | TEXT | Домен (уникальный) |
| `strategy_id` | INTEGER | ID стратегии (FK) |
| `is_active` | BOOLEAN | Активен ли домен |
| `fail_count` | INTEGER | Текущий счётчик неудач |
| `added_at` | TEXT | Дата добавления |
| `last_fail` | TEXT | Дата последней неудачи |

### Таблица `strategy_cooldowns`

| Колонка | Тип | Описание |
|---------|-----|----------|
| `domain` | TEXT | Домен (уникальный) |
| `until` | TEXT | Истекает в (ISO format) |
| `reason` | TEXT | Причина установки |

---

## Оптимизации алгоритма

### 1. Проверка текущей стратегии первой

Если домен уже на стратегии, она проверяется первой. Это позволяет:
- Быстро восстановить работу если проблема временная
- Избежать лишнего перебора других стратегий

### 2. Приоритизация стратегий

Стратегии сортируются по:
1. `priority ASC` - пользовательские приоритеты
2. `success_rate DESC` - более успешные проверяются раньше
3. `domains_count DESC` - популярные стратегии проверяются раньше

### 3. Включение untested стратегий

Стратегии с `total_checks = 0` тоже проверяются. Это позволяет:
- Автоматически тестировать новые стратегии
- Находить лучшие решения для специфичных доменов

### 4. Cooldown для неудачных подборов

Если brute force не нашёл стратегию:
- Устанавливается cooldown 30 минут
- Избегается постоянный перебор для одного домена
- Экономия CPU и сети

### 5. DPI detector вместо прямого тестирования

Вместо реального применения стратегии и проверки соединения:
- Используется DPI detector для анализа
- Сравниваются найденные параметры с параметрами стратегии
- Быстрее и меньше нагрузка на сеть

---

## Потенциальные проблемы и решения

### Проблема 1: Ложные negatives DPI detector

**Симптом:** DPI detector не находит блокировку, но сайт не работает.

**Решение:** 
- Увеличить timeout проверки
- Добавить дополнительные методы детекции (HTTP status, TLS handshake)

### Проблема 2: Долгий brute force

**Симптом:** 14 итераций перебора занимают много времени.

**Решение:**
- Параллелизация проверок (ограничить semaphore)
- Кэширование результатов для одинаковых доменов

### Проблема 3: Частые перезапуски nfqws

**Симптом:** HUP сигнал отправляется слишком часто.

**Решение:**
- Debounce механизм (уже реализован)
- Пакетное применение изменений

---

*Версия: 0.3.0 | Дата: Март 2026*
