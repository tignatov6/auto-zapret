# 🚀 Auto-Zapret + Zapret (WinWS) - Инструкция по запуску

## 📋 Что установлено

| Компонент | Версия | Путь |
|-----------|--------|------|
| **Zapret** | v72.12 | `D:\t1pe\Projects\auto-zapret\zapret-src\zapret-v72.12` |
| **WinWS** | v72.12 | `zapret-src\zapret-v72.12\binaries\windows-x86_64\winws.exe` |
| **WinDivert** | 2.2.0 | В комплекте с Zapret |
| **Auto-Zapret** | 0.3.0 | `D:\t1pe\Projects\auto-zapret` |

---

## ⚠️ Требования

1. **Windows 7+ x64** (или Windows 10/11)
2. **Права администратора** (обязательно!)
3. **Отключенный Secure Boot** (может требоваться для WinDivert)
4. **Антивирус**: добавить исключения для `WinDivert64.sys`

---

## 🔧 Запуск (2 шага)

### Шаг 1: Запуск WinWS (DPI обходчик)

**Важно:** Запускать **ОТ АДМИНИСТРАТОРА**!

```cmd
# Открыть командную строку от администратора
cd D:\t1pe\Projects\auto-zapret
start-winws.cmd
```

Или вручную:
```cmd
cd D:\t1pe\Projects\auto-zapret\zapret-src\zapret-v72.12\binaries\windows-x86_64
winws.exe --filter-tcp=443 --filter-tcp=80 --hostlist-auto="D:\t1pe\Projects\auto-zapret\data\zapret-hosts-auto.txt" --hostlist-auto-fail-threshold=3 --hostlist-auto-debug="D:\t1pe\Projects\auto-zapret\logs\autohostlist.log" --new --hostlist="D:\t1pe\Projects\auto-zapret\data\strat-youtube.txt" --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2
```

**Проверка:**
- Должно появиться окно "WinWS Auto-Zapret"
- В логе `logs\autohostlist.log` должны появляться записи при посещении заблокированных сайтов

---

### Шаг 2: Запуск Auto-Zapret (Monitor + Web UI)

```cmd
cd D:\t1pe\Projects\auto-zapret
python -m autozapret.main serve --port 8000
```

**Проверка:**
- Откройте `http://localhost:8000`
- Раздел "Logs" должен показывать события в реальном времени

---

## 🧪 Тестирование

### 1. Откройте заблокированный сайт

Например:
- `https://youtube.com`
- `https://discord.com`
- `https://www.twitch.tv`

### 2. Наблюдайте логи

В Web UI (`http://localhost:8000/logs`):
```
🔴 youtube.com - Fail counter: 1/3 (TLS)
🔴 youtube.com - Fail counter: 2/3 (TLS)
🔴 youtube.com - Fail counter: 3/3 (TLS)
⚠️ youtube.com - Threshold reached, starting strategy selection
🔍 youtube.com - Checking existing strategies
🧪 youtube.com - Testing youtube (success_rate=0.95)
✅ youtube.com - Found existing strategy: youtube
```

### 3. Проверка hostlist файлов

Файл `data\zapret-hosts-auto.txt` должен содержать:
```
youtube.com
discord.com
```

Файл `data\strat-youtube.txt` должен содержать:
```
youtube.com
```

---

## 🛑 Остановка

### Остановить WinWS:
```cmd
cd D:\t1pe\Projects\auto-zapret
stop-winws.cmd
```

Или закройте окно "WinWS Auto-Zapret"

### Остановить Auto-Zapret:
```
Ctrl+C в окне где запущен python
```

---

## 🔍 Диагностика

### Проблема: WinWS не запускается

**Решение:**
1. Запустите от администратора
2. Проверьте что WinDivert не блокируется антивирусом
3. Попробуйте `windivert_delete.cmd` затем перезапустите

### Проблема: Логи пустые

**Решение:**
1. Проверьте что WinWS запущен
2. Проверьте путь к логу в `config\autozapret.json`
3. Перезапустите Auto-Zapret

### Проблема: Сайты не открываются

**Решение:**
1. Проверьте что WinWS работает (окно открыто)
2. Запустите `blockcheck\blockcheck.cmd` для подбора стратегии
3. Обновите стратегию в `data\strat-*.txt`

---

## 📁 Структура файлов

```
auto-zapret/
├── data/                      # Рабочие файлы
│   ├── zapret-hosts-auto.txt  # Автоматический список доменов
│   ├── strat-youtube.txt      # Стратегия YouTube
│   ├── strat-discord.txt      # Стратегия Discord
│   └── strat-default.txt      # Стратегия по умолчанию
├── logs/                      # Логи
│   └── autohostlist.log       # Лог событий nfqws
├── zapret-src/                # Zapret
│   └── zapret-v72.12/
│       └── binaries/windows-x86_64/
│           └── winws.exe      # DPI обходчик
├── start-winws.cmd            # Скрипт запуска WinWS
├── stop-winws.cmd             # Скрипт остановки
└── config/
    └── autozapret.json        # Конфигурация
```

---

## 📞 Поддержка

- **Zapret документация:** https://github.com/bol-van/zapret
- **WinWS примеры:** https://github.com/bol-van/zapret-win-bundle
- **Blockcheck:** `zapret-src\zapret-v72.12\blockcheck.sh`

---

**Версия:** 1.0 | **Дата:** Март 2026
