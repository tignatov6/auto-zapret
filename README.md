# Auto-Zapret

**Адаптивная мультистратегическая маршрутизация для Zapret**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Описание

Auto-Zapret — это система автоматического подбора и применения оптимальных стратегий обхода DPI для каждого домена в реальном времени.

### Проблема

Текущие решения для обхода DPI (например, Zapret) работают по статическим правилам:
- **Универсальность против эффективности**: Стратегия, работающая для YouTube, может сломать Discord или банки
- **Ручная настройка**: При блокировке нового сайта нужно вручную перебирать стратегии

### Решение

Auto-Zapret автоматически:
1. **Детектирует** проблемы с доступом к доменам через логи nfqws/winws
2. **Тестирует** существующие стратегии на проблемном домене
3. **Подбирает** новую стратегию перебором 600+ вариантов (если существующие не работают)
4. **Применяет** рабочую стратегию без перезапуска службы
5. **Запоминает** выбор для будущего использования

---

## Быстрый старт

### Требования

- **Python 3.10+**
- **Zapret** (nfqws для Linux или winws для Windows)
- **Права администратора** (для работы с драйвером WinDivert на Windows)

### Установка

```bash
# Клонирование репозитория
git clone <repository-url> auto-zapret
cd auto-zapret

# Установка зависимостей
pip install -r requirements.txt
```

### Настройка Zapret

#### Linux (nfqws)

```bash
nfqws \
  --filter-tcp=80 --filter-tcp=443 \
  --hostlist-auto=/opt/zapret/ipset/zapret-hosts-auto.txt \
  --hostlist-auto-fail-threshold=3 \
  --hostlist-auto-debug=/var/log/zapret-autohostlist.log \
  --new \
  --hostlist=/opt/zapret/ipset/strat-youtube.txt \
  --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 \
  --new \
  --hostlist=/opt/zapret/ipset/strat-discord.txt \
  --dpi-desync=split --disorder
```

#### Windows (winws)

```cmd
# Установка драйвера WinDivert (от администратора)
install-windivert.cmd

# Запуск winws (от администратора)
start-winws.cmd
```

### Запуск Auto-Zapret

```bash
# Инициализация базы данных
python -m autozapret.main init-db

# Запуск Web UI (порт 8000)
python -m autozapret.main serve --host 0.0.0.0 --port 8000

# Или запуск демона (фоновая обработка логов)
python -m autozapret.main start
```

### Доступ к Web UI

Откройте в браузере: `http://localhost:8000`

Возможности Web UI:
- 📊 Dashboard со статистикой в реальном времени
- ⚙️ Управление стратегиями (создание, редактирование, удаление)
- 🌐 Управление доменами (привязка к стратегиям)
- 📋 Просмотр логов событий
- 🔄 Перезагрузка nfqws/winws из интерфейса

---

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    Auto-Zapret                          │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Monitor   │  │  Analyzer   │  │  Executor   │     │
│  │             │  │             │  │             │     │
│  │ • tail лог  │  │ • подбор    │  │ • файлы     │     │
│  │ • парсинг   │  │   стратегий │  │ • SIGHUP    │     │
│  │ • события   │  │ • brute     │  │ • верификац.│     │
│  │             │  │   force     │  │             │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Storage (SQLite)                   │   │
│  │  • стратегии (600+ профилей)                    │   │
│  │  • домены → стратегия mapping                   │   │
│  │  • статистика тестирования                      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │          Web API / UI (FastAPI)                 │   │
│  │  • REST API (JSON)                              │   │
│  │  • Dashboard (Bootstrap 5)                      │   │
│  │  • Swagger docs (/docs)                         │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│              Zapret (nfqws / winws)                     │
│  --hostlist-auto=auto.txt --new --hostlist=strat_*.txt │
└─────────────────────────────────────────────────────────┘
```

---

## Компоненты

### Monitor
- Чтение логов nfqws/winws в реальном времени (tail -f)
- Парсинг событий autohostlist (fail counter, domain added, fail reset)
- Поддержка callback для обработки событий
- Detect log rotation (автоматическое восстановление при ротации логов)

### Analyzer
- Обработка событий fail counter (порог срабатывания: 3 неудачи)
- Тестирование существующих стратегий (параллельно, 3 стратегии одновременно)
- Brute-force перебор 600+ стратегий при отсутствии работающих
- Cooldown для предотвращения частых изменений (30 минут)
- Сбор статистики по стратегиям (success rate, среднее время ответа)

### Executor
- Добавление/удаление доменов в hostlist файлы
- Отправка SIGHUP nfqws (Linux) или обновление файлов (Windows)
- Проверка на дубликаты (включая поддомены)
- Debounce для SIGHUP (защита от частых перезагрузок)
- Полный рестарт winws при применении новой стратегии

### Storage
- SQLite база данных
- Стратегии, домены, статистика тестирования
- Асинхронный доступ (aiosqlite)
- Миграции схемы (автоматическое добавление новых полей)

### Strategy Generator
- Генерация 600+ стратегий для brute-force
- Типы стратегий:
  - **Базовые Split** (multisplit, multidisorder) — ~40 стратегий
  - **WSSIZE** (window size) — ~12 стратегий
  - **SeqOvl** (sequence overlap) — ~12 стратегий
  - **Fake с TTL циклом** (1-16) — ~512 стратегий
  - **Fake с AutoTTL** (-1..-8) — ~64 стратегии
  - **Fake TLS моды** — 2 стратегии
  - **HTTP моды** — 3 стратегии

### Strategy Tester
- Динамическая калибровка таймаутов (измерение RTT до 9 сайтов)
- Реальное HTTPS тестирование через aiohttp
- Параллельное тестирование (Semaphore, 3 стратегии одновременно)
- Кэширование результатов калибровки (TTL: 5 минут)

---

## REST API

### Endpoints

#### Health & Stats
```
GET  /api/health          # Проверка состояния
GET  /api/stats           # Общая статистика
```

#### Strategies
```
GET    /api/strategies              # Список стратегий
POST   /api/strategies              # Создать стратегию
GET    /api/strategies/{name}       # Получить стратегию
PUT    /api/strategies/{name}       # Обновить стратегию
DELETE /api/strategies/{name}       # Удалить стратегию
```

#### Domains
```
GET    /api/domains                 # Список доменов
POST   /api/domains                 # Добавить домен
POST   /api/domains/bulk            # Массовое добавление
DELETE /api/domains/{domain}        # Удалить домен
GET    /api/domains/{domain}/stats  # Статистика домена
```

#### Actions
```
POST /api/actions/reload            # Перезагрузить nfqws (SIGHUP)
POST /api/actions/test-strategy     # Тест стратегии
POST /api/actions/check-dpi         # Проверка домена на DPI блокировку
```

### Примеры использования

```bash
# Получить статистику
curl http://localhost:8000/api/stats

# Добавить стратегию
curl -X POST http://localhost:8000/api/strategies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "netflix",
    "zapret_params": "--dpi-desync=fake --dpi-desync-split-pos=tlsrec",
    "priority": 5,
    "description": "Для Netflix"
  }'

# Добавить домен
curl -X POST http://localhost:8000/api/domains \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "netflix.com",
    "strategy_name": "netflix"
  }'

# Перезагрузить nfqws
curl -X POST http://localhost:8000/api/actions/reload
```

### Swagger UI

Полная документация API: `http://localhost:8000/docs`

---

## CLI команды

```bash
# Инициализация
python -m autozapret.main init-db

# Статус
python -m autozapret.main status

# Запуск Web UI
python -m autozapret.main serve --host 0.0.0.0 --port 8000

# Запуск демона
python -m autozapret.main start

# Управление стратегиями
python -m autozapret.main strategies list
python -m autozapret.main strategies add mystrat --params="--dpi-desync=fake"

# Управление доменами
python -m autozapret.main domains list
python -m autozapret.main domains assign example.com youtube

# Статистика
python -m autozapret.main stats
```

---

## Конфигурация

### config/autozapret.json

```json
{
    "log_level": "INFO",
    "strategy_cooldown_minutes": 30,
    "bruteforce_cooldown_minutes": 60,
    "analysis_max_parallel": 5,
    "monitor_replay_existing_logs": false,
    "brute_force_mode": "first_working",
    "brute_force_quick_mode": true
}
```

### config/strategies.json

```json
{
    "strategies": [
        {
            "name": "youtube",
            "description": "Обход блокировок YouTube",
            "zapret_params": "--dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2",
            "priority": 1
        },
        {
            "name": "discord",
            "description": "Обход блокировок Discord",
            "zapret_params": "--dpi-desync=split --disorder",
            "priority": 2
        }
    ]
}
```

---

## Структура проекта

```
auto-zapret/
├── autozapret/
│   ├── __init__.py           # Версия проекта
│   ├── main.py               # CLI интерфейс
│   ├── config.py             # Конфигурация
│   ├── storage.py            # SQLite база
│   ├── executor.py           # Применение стратегий
│   ├── monitor.py            # Мониторинг логов
│   ├── analyzer.py           # Анализ событий
│   ├── api.py                # Web API / UI
│   ├── dpi_detector.py       # Детектор DPI блокировок
│   ├── strategy_tester.py    # Тестирование стратегий
│   ├── strategy_generator.py # Генерация 600+ стратегий
│   ├── nfqws_config.py       # Генератор конфигов nfqws
│   ├── blockcheck_selector.py # Подбор стратегий blockcheck-style
│   └── utils/
│       └── profiler.py       # Профайлер производительности
├── config/
│   ├── autozapret.json       # Конфиг приложения
│   ├── strategies.json       # Библиотека стратегий
│   └── ultimate_strategies.json # Расширенная библиотека
├── templates/
│   ├── base.html             # Базовый шаблон
│   ├── index.html            # Dashboard
│   ├── strategies.html       # Стратегии
│   ├── domains.html          # Домены
│   └── logs.html             # Логи
├── data/
│   ├── autozapret.db         # SQLite база данных
│   ├── zapret-hosts-auto.txt # Авто-домены
│   ├── strat-youtube.txt     # Стратегия YouTube
│   ├── strat-discord.txt     # Стратегия Discord
│   └── strat-default.txt     # Стратегия по умолчанию
├── logs/
│   ├── autohostlist.log      # Лог событий nfqws
│   └── python/               # Логи Python приложения
├── tests/
│   ├── conftest.py           # Fixtures
│   ├── test_storage.py
│   ├── test_executor.py
│   ├── test_monitor.py
│   ├── test_analyzer.py
│   ├── test_api.py
│   ├── test_strategy_tester.py
│   ├── test_strategy_generator.py
│   └── test_nfqws_config.py
├── bin/
│   ├── winws.exe             # WinWS (Windows)
│   └── blockcheck/           # Утилиты blockcheck
├── install-windivert.cmd     # Установка WinDivert
├── start-winws.cmd           # Запуск WinWS
├── stop-winws.cmd            # Остановка WinWS
├── auto-zapret.service       # Systemd сервис (Web UI)
├── auto-zapret-daemon.service # Systemd сервис (daemon)
├── requirements.txt
├── pytest.ini
├── run_tests.py
└── README.md
```

---

## Тестирование

```bash
# Запуск всех тестов
python run_tests.py

# Запуск с покрытием
pytest --cov=autozapret --cov-report=html

# Конкретный тест
pytest tests/test_analyzer.py -v

# Открыть отчёт о покрытии
open htmlcov/index.html  # Linux/Mac
start htmlcov\index.html  # Windows
```

### Статистика тестов

```
Всего тестов: 125
Покрытие: 68%
Статус: ✅ Все проходят
```

---

## Systemd сервисы (Linux)

### auto-zapret.service (Web UI)

```ini
[Unit]
Description=Auto-Zapret Web API
After=network.target zapret.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/auto-zapret
ExecStart=/usr/bin/python3 -m autozapret.main serve --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

### auto-zapret-daemon.service (фоновая обработка)

```ini
[Unit]
Description=Auto-Zapret Monitor Daemon
After=network.target zapret.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/auto-zapret
ExecStart=/usr/bin/python3 -m autozapret.main start
Restart=always

[Install]
WantedBy=multi-user.target
```

### Установка

```bash
# Копирование сервисов
cp auto-zapret.service /etc/systemd/system/
cp auto-zapret-daemon.service /etc/systemd/system/

# Перезагрузка systemd
systemctl daemon-reload

# Включение автозапуска
systemctl enable auto-zapret
systemctl enable auto-zapret-daemon

# Запуск
systemctl start auto-zapret
systemctl start auto-zapret-daemon

# Проверка статуса
systemctl status auto-zapret
```

---

## Производительность

### Brute-force перебор стратегий

| Метрика | Значение |
|---------|----------|
| Всего стратегий | 600+ |
| Параллельное тестирование | 3 стратегии одновременно |
| Время теста 1 стратегии | ~3.5 сек |
| Общее время brute-force | ~13 минут |
| Ускорение (vs последовательно) | ×32 |

### Динамическая калибровка таймаутов

```
RTT до сайтов:
  ya.ru: 15ms
  yandex.ru: 18ms
  vk.com: 22ms
  mail.ru: 25ms
  ...

Timeout base: 28ms × 1.33 = 37ms
```

---

## Планы развития

### Приоритет 1
- [ ] Поддержка IP адресов (ipset)
- [ ] Reverse DNS lookup для IP
- [ ] Интеграция с DNS резолвером

### Приоритет 2
- [ ] JSON логирование
- [ ] Alerts при частых проблемах
- [ ] Rate limiting для SIGHUP

### Приоритет 3
- [ ] Машинное обучение для предсказания успешных стратегий
- [ ] Облачная синхронизация стратегий
- [ ] Мобильное приложение

---

## Поддержка

- **Документация:** `README.md`, `IMPLEMENTATION_PLAN.md`, `DOCS.md`
- **API Docs:** `http://localhost:8000/docs` (Swagger UI)
- **Quick Start:** `QUICK_START.md`, `RUN_INSTRUCTIONS.md`
- **Issues:** Создавайте в репозитории

---

## Лицензия

MIT

---

*Версия: 0.4.0 | Дата: Март 2026*
