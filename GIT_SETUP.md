# Руководство по первоначальным коммитам

## Шаг 1: Проверка файлов

Перед первым коммитом убедитесь что созданы все необходимые файлы:

```bash
# Проверка наличия основных файлов
ls -la README.md LICENSE .gitignore .gitattributes pyproject.toml
```

## Шаг 2: Первоначальный коммит

Рекомендуется сделать несколько атомарных коммитов:

### Коммит 1: Основные файлы репозитория
```bash
git add README.md LICENSE .gitignore .gitattributes pyproject.toml
git commit -m "Initial repository structure

- Add README.md with project description and documentation
- Add MIT License
- Add .gitignore for Python/Windows/Linux
- Add .gitattributes for line ending normalization
- Add pyproject.toml for modern Python packaging"
```

### Коммит 2: Исходный код ядра
```bash
git add autozapret/*.py autozapret/utils/*.py
git commit -m "Add core Auto-Zapret modules

- main.py: CLI interface and application entry point
- config.py: Configuration management
- storage.py: SQLite database layer with migrations
- executor.py: Strategy application and nfqws/winws management
- monitor.py: Log monitoring and event parsing
- analyzer.py: Event analysis and strategy selection
- api.py: FastAPI Web UI and REST API
- dpi_detector.py: DPI blocking detection
- strategy_tester.py: Real HTTPS strategy testing
- strategy_generator.py: 600+ strategy generation
- nfqws_config.py: nfqws runtime config generator
- blockcheck_selector.py: Blockcheck-style strategy selection
- profiler.py: Performance profiling utilities"
```

### Коммит 3: Шаблоны Web UI
```bash
git add templates/*.html
git commit -m "Add Web UI templates

- base.html: Base template with Bootstrap 5
- index.html: Dashboard with real-time stats
- strategies.html: Strategy management page
- domains.html: Domain management page
- logs.html: Event logs with real-time updates"
```

### Коммит 4: Конфигурация
```bash
git add config/autozapret.json pytest.ini requirements.txt
git commit -m "Add configuration files

- autozapret.json: Application settings
- pytest.ini: pytest configuration
- requirements.txt: Python dependencies"
```

### Коммит 5: Systemd сервисы и скрипты
```bash
git add *.service *.cmd *.sh install-windivert.cmd
git commit -m "Add system integration files

- auto-zapret.service: Systemd service for Web UI
- auto-zapret-daemon.service: Systemd service for background daemon
- install-windivert.cmd: WinDivert driver installation
- start-winws.cmd: WinWS startup script
- stop-winws.cmd: WinWS shutdown script
- blockcheck.sh: Blockcheck integration script"
```

### Коммит 6: Тесты
```bash
git add tests/*.py run_tests.py pytest.ini
git commit -m "Add test suite

- test_storage.py: Database CRUD tests
- test_executor.py: Strategy application tests
- test_monitor.py: Log parsing tests
- test_analyzer.py: Strategy selection tests
- test_api.py: REST API tests
- test_strategy_tester.py: HTTPS testing tests
- test_strategy_generator.py: Strategy generation tests
- test_nfqws_config.py: Config generator tests
- conftest.py: pytest fixtures
- run_tests.py: CI test runner"
```

### Коммит 7: Документация
```bash
git add *.md
git commit -m "Add documentation

- idea.md: Project concept and architecture
- IMPLEMENTATION_PLAN.md: Implementation roadmap
- DOCS.md: Complete documentation
- QUICK_START.md: Quick start guide
- RUN_INSTRUCTIONS.md: Running instructions
- BRUTE_FORCE_IMPLEMENTATION.md: Brute force details
- STRATEGY_SEARCH_ALGORITHM.md: Strategy selection algo
- STRATEGY_TESTER.md: Strategy testing docs
- PROFILER_GUIDE.md: Profiler documentation
- And other technical documentation"
```

### Коммит 8: Дополнительные файлы
```bash
git add smart_tuner.py debug_bruteforce.py *.bat
git commit -m "Add utility scripts

- smart_tuner.py: Standalone strategy tuner
- debug_bruteforce.py: Debugging utilities
- Windows batch files for autostart"
```

## Шаг 3: Проверка истории

```bash
# Проверка истории коммитов
git log --oneline

# Проверка статуса
git status
```

## Шаг 4: Создание удалённого репозитория

```bash
# Создать репозиторий на GitHub/GitLab/Bitbucket
# Затем добавить remote:

git remote add origin https://github.com/your-username/auto-zapret.git
git branch -M main
git push -u origin main
```

## Шаг 5: Проверка .gitignore

Убедитесь что .gitignore корректно работает:

```bash
# Проверка что игнорируется
git status --ignored

# Должны быть проигнорированы:
# - __pycache__/
# - *.pyc
# - .pytest_cache/
# - htmlcov/
# - coverage.xml
# - .coverage
# - logs/*.log
# - data/*.db
# - config/strategies.json
# - data/strat-*.txt
# - data/zapret-hosts-auto.txt
```

## Рекомендации

1. **Не коммитьте бинарные файлы**:
   - `zapret-src/` (исходники Zapret)
   - `bin/*.exe` (бинарники winws)
   - `*.dll`, `*.sys` (драйверы)

2. **Не коммитьте чувствительные данные**:
   - Логи с персональной информацией
   - Конфигурационные файлы с IP адресами
   - Базы данных с историей

3. **Соблюдайте атомарность коммитов**:
   - Один коммит = одна логическая единица
   - Пишите осмысленные сообщения коммитов

4. **Используйте теги для версий**:
   ```bash
   git tag -a v0.4.0 -m "Version 0.4.0 - Brute force implementation"
   git push origin v0.4.0
   ```

---

*Версия: 1.0 | Дата: Март 2026*
