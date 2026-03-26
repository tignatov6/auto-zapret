# Auto-Zapret: Итоговая документация

## Статус проекта

✅ **Версия 0.3.0 - Полная реализация с тестами API**

- ✅ 125 автотестов проходят
- ✅ 68% покрытие кода
- ✅ Web UI / Dashboard
- ✅ REST API с тестами
- ✅ CLI интерфейс
- ✅ Systemd сервисы
- ✅ NFQWS Config Generator

---

## Быстрый старт

### 1. Установка

```bash
# Клонирование репозитория
cd /opt
git clone <repo> auto-zapret
cd auto-zapret

# Установка зависимостей
pip install -r requirements.txt
```

### 2. Настройка Zapret

```bash
# Пример запуска nfqws с поддержкой autohostlist
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

### 3. Инициализация Auto-Zapret

```bash
# Инициализация БД
python -m autozapret.main init-db

# Проверка
python -m autozapret.main status
```

### 4. Запуск

```bash
# Вариант A: Web UI (порт 8000)
python -m autozapret.main serve --host 0.0.0.0 --port 8000

# Вариант B: Демон (фоновая обработка)
python -m autozapret.main start

# Вариант C: Systemd
cp auto-zapret.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable auto-zapret
systemctl start auto-zapret
```

### 5. Доступ к Web UI

Откройте в браузере: `http://localhost:8000`

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                     Auto-Zapret 0.2.0                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Monitor    │  │   Analyzer   │  │   Executor   │      │
│  │              │  │              │  │              │      │
│  │ • tail логов │  │ • подбор     │  │ • файлы      │      │
│  │ • парсинг    │  │   стратегий  │  │ • SIGHUP     │      │
│  │ • события    │  │ • cooldown   │  │ • верификация│      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Storage (SQLite)                         │   │
│  │  - стратегии (name, params, priority)                │   │
│  │  - домены (domain → strategy mapping)                │   │
│  │  - события (stats, audit log)                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Web API / UI (FastAPI)                   │   │
│  │  - REST API (JSON)                                    │   │
│  │  - Dashboard (HTML/Bootstrap)                         │   │
│  │  - Swagger docs (/docs)                               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              CLI (Click)                              │   │
│  │  - init-db, status, serve, start                      │   │
│  │  - strategies *, domains *, stats                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Zapret (nfqws)                           │
│  --hostlist-auto=auto.txt --new --hostlist=strat_*.txt     │
└─────────────────────────────────────────────────────────────┘
```

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

## Web UI

### Страницы

| Страница | URL | Описание |
|----------|-----|----------|
| Dashboard | `/` | Общая статистика, быстрые действия |
| Стратегии | `/strategies` | Управление стратегиями |
| Домены | `/domains` | Управление доменами |
| Логи | `/logs` | Журнал событий |

### Возможности

- ✅ Статистика в реальном времени
- ✅ Добавление/удаление стратегий
- ✅ Привязка доменов к стратегиям
- ✅ Просмотр логов событий
- ✅ Перезагрузка nfqws из UI
- ✅ Адаптивный дизайн (Bootstrap 5)

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

## NFQWS Config Generator

Модуль `nfqws_config.py` предоставляет генератор runtime-конфигурации для nfqws.

### Основные возможности

- **Генерация профилей стратегий** - создание профилей nfqws для каждой стратегии
- **Валидация параметров** - проверка корректности параметров Zapret
- **Генерация скриптов** - создание startup скриптов для Windows/Linux/Systemd

### API

```python
from autozapret.nfqws_config import NfqwsConfigGenerator, get_generator

# Получение singleton экземпляра
gen = get_generator(config)

# Валидация параметров
valid, error = gen.validate_params("--dpi-desync=fake,multisplit")

# Генерация аргументов для nfqws
args = gen.generate_nfqs_args()

# Обновление профиля стратегии
await gen.update_profile(strategy_obj)

# Удаление профиля
await gen.remove_profile("youtube")

# Генерация Windows batch скрипта
gen.generate_windows_batch("start-nfqws-auto.cmd")

# Генерация Shell скрипта
gen.generate_startup_script("start-nfqws-auto.sh")

# Генерация Systemd сервиса
gen.generate_systemd_service("nfqws-auto.service")
```

### Структура профиля

Каждый профиль содержит:
- `name` - имя стратегии
- `priority` - приоритет (меньше = выше)
- `zapret_params` - параметры Zapret
- `hostlist_file` - путь к файлу hostlist

### Примеры валидных параметров

```
--dpi-desync=fake
--dpi-desync=split
--dpi-desync=fake,multisplit
--disorder
--dpi-desync=fake --dpi-desync-split-pos=method+2
```

### Генерация скриптов

Модуль автоматически генерирует:
1. **Windows**: `start-nfqws-auto.cmd` - batch файл для запуска nfqws
2. **Linux Shell**: `start-nfqws-auto.sh` - shell скрипт
3. **Systemd**: `nfqws-auto.service` - сервис для автозапуска

---

## Тестирование

```bash
# Запуск всех тестов
python -m pytest tests/ -v

# Запуск с покрытием
python -m pytest tests/ --cov=autozapret --cov-report=html

# Конкретный тест
python -m pytest tests/test_api.py -v

# Открыть отчёт о покрытии
open htmlcov/index.html
```

### Статистика тестов

```
Всего тестов: 103
Покрытие: 72%
Статус: ✅ Все проходят
```

---

## Systemd сервисы

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

## Структура проекта

```
auto-zapret/
├── autozapret/
│   ├── __init__.py          # Версия проекта
│   ├── main.py              # CLI интерфейс
│   ├── config.py            # Конфигурация
│   ├── storage.py           # SQLite база
│   ├── executor.py          # Применение стратегий
│   ├── monitor.py           # Мониторинг логов
│   ├── analyzer.py          # Анализ событий
│   └── api.py               # Web API / UI
├── config/
│   ├── autozapret.json      # Конфиг приложения
│   └── strategies.json      # Библиотека стратегий
├── templates/
│   ├── base.html            # Базовый шаблон
│   ├── index.html           # Dashboard
│   ├── strategies.html      # Стратегии
│   ├── domains.html         # Домены
│   └── logs.html            # Логи
├── tests/
│   ├── conftest.py          # Fixtures
│   ├── test_storage.py
│   ├── test_executor.py
│   ├── test_monitor.py
│   ├── test_analyzer.py
│   ├── test_integration.py
│   ├── test_main.py
│   └── test_coverage.py
├── auto-zapret.service      # Systemd сервис (Web UI)
├── auto-zapret-daemon.service  # Systemd сервис (daemon)
├── requirements.txt
├── pytest.ini
├── run_tests.py
├── README.md
└── IMPLEMENTATION_PLAN.md
```

---

## Планы развития

### Приоритет 1 (ближайшие итерации)
- [ ] Интеграция с реальным nfqws (тест на живой системе)
- [ ] Поддержка IP адресов (ipset)
- [ ] Тестирование стратегий (HTTP HEAD / TLS handshake)

### Приоритет 2
- [ ] JSON логирование
- [ ] Alerts при частых проблемах
- [ ] Rate limiting для SIGHUP

### Приоритет 3
- [ ] Машинное обучение для подбора стратегий
- [ ] Облачная синхронизация стратегий
- [ ] Мобильное приложение

---

## Поддержка

- **Документация:** `README.md`, `IMPLEMENTATION_PLAN.md`
- **API Docs:** `http://localhost:8000/docs`
- **Issues:** Создавайте в репозитории

---

*Версия: 0.3.0 | Дата: Март 2026*
