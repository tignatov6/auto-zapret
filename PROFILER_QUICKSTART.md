# Профилирование Auto-Zapret - Быстрый старт

## Что было сделано

✅ Все функции и методы в проекте обернуты в профайлер
✅ Добавлен автоматический вывод статистики при завершении работы
✅ Создана документация (PROFILER_GUIDE.md)

## Запуск с профилированием

### 1. Запуск через CLI

```bash
# Обычный запуск (профайлер включен по умолчанию)
python -m autozapret start

# Запуск Web API
python -m autozapret serve
```

### 2. Просмотр статистики

Профайлер автоматически выводит отчёт при завершении работы (Ctrl+C):

```
─── MiniProfiler report ───

[analyzer]  total 12.453 s
  _brute_force_strategies_impl:   8.234s  |  66.1% |      15×
  _test_strategy_impl:            2.891s  |  23.2% |      42×
  handle_event:                   0.982s  |   7.9% |     156×

[executor]  total 5.234 s
  start_winws_with_strategy:      3.123s  |  59.7% |      42×
  stop_winws:                     1.456s  |  27.8% |      43×
─────────────────────────────
```

## Отключение профилирования

Для продакшена можно отключить профайлер (минимальные накладные расходы):

```python
from autozapret.utils.profiler import enable_profiling

# В начале программы
enable_profiling(False)
```

## Интерпретация результатов

### Формат отчёта

```
[module_name]  total X.XXX s
  function_name:                X.XXXs  |  XX.X% |    N×
```

- `total` - суммарное время модуля
- `function_name` - имя функции
- `X.XXXs` - общее время выполнения
- `XX.X%` - процент от времени модуля
- `N×` - количество вызовов

### На что смотреть

1. **Функции с >50% времени** - главные кандидаты на оптимизацию
2. **Функции с 1000+ вызовами** - частые вызовы
3. **I/O операции** - диск, сеть, БД (обычно самые медленные)

## Примеры использования

### Программный вызов отчёта

```python
from autozapret.utils.profiler import report

# Вывести отчёт в любой момент
report(sort_by="time")  # Сортировка по времени
report(sort_by="calls") # Сортировка по количеству вызовов
```

### Очистка статистики

```python
from autozapret.utils.profiler import clear_stats

clear_stats()  # Очистить всю статистику
```

## Производительность

- Накладные расходы: ~1-2 мкс на вызов функции
- Потокобезопасен (thread-safe)
- Может быть отключен в продакшене

## Структура файлов

```
autozapret/
├── utils/
│   └── profiler.py       # Модуль профайлера
├── helpers.py            # Общие утилиты (бывший utils.py)
├── config.py             # Конфигурация (декорирован)
├── storage.py            # Хранилище (декорирован)
├── executor.py           # Executor (декорирован)
├── monitor.py            # Monitor (декорирован)
├── dpi_detector.py       # DPI Detector (декорирован)
├── analyzer.py           # Analyzer (декорирован)
├── strategy_generator.py # Generator (декорирован)
├── strategy_tester.py    # Tester (декорирован)
├── nfqws_config.py       # Config Generator (декорирован)
├── api.py                # Web API (декорирован)
└── main.py               # Точка входа (декорирован)
```

## Документация

Полная документация: [PROFILER_GUIDE.md](PROFILER_GUIDE.md)

## Вопросы?

См. раздел "Вопросы и ответы" в PROFILER_GUIDE.md
