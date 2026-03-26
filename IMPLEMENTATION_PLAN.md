# Auto-Zapret: План реализации

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    auto-zapret                          │
│  (единый процесс / служба)                              │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Monitor   │  │  Analyzer   │  │  Executor   │     │
│  │             │  │             │  │             │     │
│  │ - tail лог  │  │ - база      │  │ - управление│     │
│  │ - парсинг   │  │   стратегий │  │   файлами   │     │
│  │ - события   │  │ - тесты     │  │ - SIGHUP    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Storage (SQLite/JSON)              │   │
│  │  - стратегии (название, параметры)              │   │
│  │  - домены → стратегия mapping                   │   │
│  │  - статистика                                   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Этап 0: Подготовка

### 0.1 Выбор стека
**Язык:** Python 3.10+
**Причины:**
- Быстрая разработка прототипа
- Богатые библиотеки для работы с логами, сетью
- Легко интегрируется с shell командами

**Зависимости:**
```
aiosqlite / sqlite3  # база данных
aiofiles             # асинхронная работа с файлами
watchdog             # мониторинг логов (опционально)
click / typer        # CLI интерфейс
```

### 0.2 Структура проекта
```
auto-zapret/
├── autozapret/
│   ├── __init__.py
│   ├── main.py           # точка входа
│   ├── monitor.py        # мониторинг логов
│   ├── analyzer.py       # подбор стратегий
│   ├── executor.py       # применение стратегий
│   ├── storage.py        # база данных
│   ├── config.py         # конфигурация
│   └── strategies/       # предопределённые стратегии
│       ├── __init__.py
│       ├── base.py
│       └── default.py
├── config/
│   ├── autozapret.json   # конфиг приложения
│   └── strategies.json   # библиотека стратегий
├── data/
│   └── autozapret.db     # SQLite база
├── logs/
│   └── autozapret.log
├── tests/
├── requirements.txt
└── README.md
```

---

## Этап 1: Ядро (MVP)

### 1.1 Storage (storage.py)
**Задачи:**
- [ ] Создать SQLite схему:
  ```sql
  CREATE TABLE strategies (
      id INTEGER PRIMARY KEY,
      name TEXT UNIQUE,
      zapret_params TEXT,  -- JSON с параметрами для nfqws
      created_at TIMESTAMP
  );
  
  CREATE TABLE domains (
      domain TEXT PRIMARY KEY,
      strategy_id INTEGER,
      added_at TIMESTAMP,
      fail_count INTEGER DEFAULT 0,
      last_fail TIMESTAMP,
      FOREIGN KEY (strategy_id) REFERENCES strategies(id)
  );
  
  CREATE TABLE stats (
      domain TEXT,
      timestamp TIMESTAMP,
      event_type TEXT,  -- 'fail', 'success', 'applied'
      strategy_id INTEGER
  );
  ```

- [ ] Реализовать CRUD:
  - `add_strategy(name, params)`
  - `get_strategy(name)`
  - `list_strategies()`
  - `assign_domain(domain, strategy_id)`
  - `get_domain_strategy(domain)`
  - `increment_fail(domain)`
  - `reset_fail(domain)`

### 1.2 Executor (executor.py)
**Задачи:**
- [ ] Функция добавления домена в hostlist файл:
  ```python
  def add_domain_to_hostlist(filename: str, domain: str) -> bool:
      # Проверка на дубликат
      # Append в файл
      # Возврат статуса
  ```

- [ ] Функция отправки SIGHUP:
  ```python
  def send_hup_to_nfqws() -> bool:
      # Найти PID nfqws
      # Отправить kill -HUP
  ```

- [ ] Функция применения стратегии:
  ```python
  async def apply_strategy(domain: str, strategy_name: str) -> bool:
      # 1. Найти файл hostlist для стратегии
      # 2. Добавить домен
      # 3. Отправить SIGHUP
      # 4. Записать в базу
  ```

### 1.3 Monitor (monitor.py)
**Задачи:**
- [ ] Парсер логов nfqws:
  ```python
  # Формат лога autohostlist:
  # example.com : profile 3 : client 192.168.1.1:12345 : proto TLS : fail counter 2/3
  
  class LogParser:
      def parse_line(self, line: str) -> Optional[AutoHostlistEvent]:
          # Извлечь: domain, profile, client, proto, fail_counter, threshold
  ```

- [ ] Tail файла (постоянное чтение):
  ```python
  async def tail_log(logfile: str):
      # Асинхронное чтение новых строк
      # Yield событий парсеру
  ```

- [ ] Детектор событий:
  - `DomainFail(domain, strategy, counter)`
  - `DomainAdded(domain, strategy)`
  - `DomainSuccess(domain)` — если нужно

### 1.4 Analyzer (analyzer.py)
**Задачи:**
- [ ] Простейшая логика (MVP):
  ```python
  class Analyzer:
      def __init__(self, storage):
          self.storage = storage
          
      async def on_domain_fail(self, domain: str, current_strategy: str, counter: int):
          if counter >= THRESHOLD:
              # Найти другую стратегию для этого домена
              new_strategy = await self.find_working_strategy(domain)
              if new_strategy:
                  await executor.apply_strategy(domain, new_strategy)
  ```

- [ ] База стратегий (hardcoded для начала):
  ```python
  DEFAULT_STRATEGIES = {
      "youtube": {
          "name": "youtube_fix",
          "params": "--dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2"
      },
      "discord": {
          "name": "discord_fix", 
          "params": "--dpi-desync=split --dpi-desync-split-pos=1,midsld"
      },
      # ...
  }
  ```

### 1.5 Main (main.py)
**Задачи:**
- [ ] CLI интерфейс:
  ```bash
  autozapret start              # запуск демона
  autozapret status             # статус
  autozapret strategies list    # список стратегий
  autozapret strategies add     # добавить стратегию
  autozapret domains list       # список доменов
  autozapret domains remove     # удалить домен
  autozapret stats              # статистика
  ```

- [ ] Главный цикл:
  ```python
  async def main():
      storage = Storage()
      executor = Executor(storage)
      analyzer = Analyzer(storage, executor)
      monitor = Monitor(storage, analyzer)
      
      await monitor.start_tailing()
  ```

---

## Этап 2: Интеграция с Zapret

### 2.1 Конфигурация nfqws
**Задачи:**
- [ ] Создать шаблон запуска nfqws с поддержкой auto-zapret:
  ```bash
  nfqws \
    --filter-tcp=80 --filter-tcp=443 \
    --hostlist-auto=/opt/zapret/ipset/zapret-hosts-auto.txt \
    --hostlist-auto-fail-threshold=3 \
    --hostlist-auto-retrans-threshold=3 \
    --hostlist-auto-debug=/var/log/zapret-autohostlist.log \
    --new \
    --hostlist=/opt/zapret/ipset/strat-youtube.txt \
    --dpi-desync=fake,multisplit \
    --dpi-desync-split-pos=method+2 \
    --new \
    --hostlist=/opt/zapret/ipset/strat-discord.txt \
    --dpi-desync=split \
    --dpi-desync-split-pos=1,midsld
  ```

- [ ] Документировать требуемые параметры

### 2.2 Управление процессом nfqws
**Задачи:**
- [ ] Детекция PID nfqws:
  ```python
  def find_nfqws_pid() -> Optional[int]:
      # pgrep nfqws
      # или чтение из PID file
  ```

- [ ] Graceful restart (опционально):
  ```python
  def restart_nfqws_if_needed():
      # Если SIGHUP недостаточно
  ```

---

## Этап 3: Улучшения

### 3.1 Умный Analyzer
**Задачи:**
- [ ] Статистика по стратегиям:
  - Процент успешных применений
  - Среднее время работы до следующей проблемы

- [ ] Рекомендательная система:
  - Если домен похож на youtube (по паттерну трафика) → применить youtube стратегию
  - Если стратегия X работает для 90% доменов → пробовать её первой

- [ ] Тестирование стратегий:
  ```python
  async def test_strategy(domain: str, strategy: str) -> bool:
      # HTTP HEAD запрос или TLS handshake
      # Проверка успешности
  ```

### 3.2 Web UI (опционально)
**Задачи:**
- [ ] Простой HTTP сервер:
  - Dashboard со статистикой
  - Список доменов и стратегий
  - Ручное добавление/удаление
  - Логи в реальном времени

### 3.3 Расширенное логирование
**Задачи:**
- [ ] Структурированные логи (JSON)
- [ ] Экспорт статистики
- [ ] Alerts при частых проблемах

---

## Этап 4: Поддержка IP (будущее)

### 4.1 Расширение Storage
**Задачи:**
- [ ] Таблица для IP:
  ```sql
  CREATE TABLE ip_addresses (
      ip TEXT PRIMARY KEY,  -- CIDR notation
      strategy_id INTEGER,
      added_at TIMESTAMP,
      fail_count INTEGER,
      FOREIGN KEY (strategy_id) REFERENCES strategies(id)
  );
  ```

### 4.2 Расширение Executor
**Задачи:**
- [ ] Управление ipset файлами:
  ```python
  def add_ip_to_ipset(filename: str, ip: str) -> bool:
      # Append CIDR в файл
  ```

### 4.3 Расширение Monitor
**Задачи:**
- [ ] Детектирование IP из логов:
  - Парсинг IP вместо hostname
  - Reverse DNS lookup (опционально)

---

## Этап 5: Production readiness

### 5.1 Надёжность
**Задачи:**
- [ ] Обработка ошибок nfqws
- [ ] Recovery после перезапуска
- [ ] Rate limiting для SIGHUP

### 5.2 Производительность
**Задачи:**
- [ ] Кэширование часто используемых данных
- [ ] Batch операции для файлов
- [ ] Оптимизация SQLite запросов

### 5.3 Тестирование
**Задачи:**
- [ ] Unit тесты для всех модулей
- [ ] Integration тесты с nfqws
- [ ] Нагрузочные тесты

---

## Приоритеты реализации

| Приоритет | Задача | Оценка времени |
|-----------|--------|----------------|
| **P0** | Storage (SQLite схема + CRUD) | 2-3 часа |
| **P0** | Executor (файлы + SIGHUP) | 1-2 часа |
| **P0** | Monitor (парсинг логов) | 2-3 часа |
| **P0** | Analyzer (базовая логика) | 1-2 часа |
| **P0** | Main (CLI + запуск) | 2-3 часа |
| **P1** | Интеграция с nfqws | 1-2 часа |
| **P1** | Тестирование на реальной системе | 4-8 часов |
| **P2** | Умный Analyzer | 4-6 часов |
| **P2** | Расширенное логирование | 2-3 часа |
| **P3** | Web UI | 8-16 часов |
| **P4** | Поддержка IP | 6-10 часов |

**Итого MVP:** 8-13 часов чистой работы
**Итого с тестированием:** 12-21 часов

---

## Риски и зависимости

### Технические риски:
1. **SIGHUP не всегда работает** — зависит от способа запуска nfqws
2. **Гонка при записи в файлы** — нужны атомарные операции
3. **Логирование nfqws может измениться** — парсер должен быть робастным

### Зависимости:
1. Zapret должен быть установлен и настроен
2. nfqws должен запускаться с `--hostlist-auto-debug`
3. Права на запись в директории с hostlist файлами

---

## Критерии готовности MVP

- [ ] auto-zapret запускается и работает в фоне
- [ ] Детектирует проблемы через логи autohostlist
- [ ] Автоматически добавляет домены в нужные hostlist файлы
- [ ] Отправляет SIGHUP для применения
- [ ] Ведёт базу данных доменов и стратегий
- [ ] CLI для управления

---

*План будет обновляться по мере реализации*
