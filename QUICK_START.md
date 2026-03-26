# 🚀 Auto-Zapret + Zapret (WinWS) - Быстрый старт

## ⚠️ ВАЖНО: Требуется установка WinDivert

WinWS использует драйвер WinDivert для перехвата трафика. Без него работать **не будет**.

---

## 📋 Шаг 1: Установка WinDivert

**Запустить ОТ АДМИНИСТРАТОРА:**

```cmd
cd D:\t1pe\Projects\auto-zapret
install-windivert.cmd
```

**Что делает скрипт:**
- Удаляет старый драйвер WinDivert (если есть)
- Устанавливает новый драйвер из комплекта Zapret
- Запускает службу WinDivert

**Если ошибка:**
1. **Secure Boot** - отключите в BIOS
2. **Антивирус** - добавьте исключение для `WinDivert64.sys`
3. **Права** - запускайте от администратора

---

## 📋 Шаг 2: Запуск WinWS

**Запустить ОТ АДМИНИСТРАТОРА:**

```cmd
cd D:\t1pe\Projects\auto-zapret
start-winws.cmd
```

**Проверка:**
- Должно появиться окно "WinWS Auto-Zapret"
- Окно **не закрывать** - работает пока открыто

---

## 📋 Шаг 3: Запуск Auto-Zapret

**Обычный запуск (не администратор):**

```cmd
cd D:\t1pe\Projects\auto-zapret
python -m autozapret.main serve --port 8000
```

**Проверка:**
- Откройте `http://localhost:8000`
- Раздел "Logs" должен быть пуст (пока не посещали заблокированные сайты)

---

## 📋 Шаг 4: Тестирование

1. **Откройте заблокированный сайт** (youtube.com, discord.com, twitch.tv)

2. **Наблюдайте логи** в Web UI:
   ```
   🔴 youtube.com - Fail counter: 1/3 (TLS)
   🔴 youtube.com - Fail counter: 2/3 (TLS)
   🔴 youtube.com - Fail counter: 3/3 (TLS)
   ⚠️ youtube.com - Threshold reached
   🔍 youtube.com - Checking existing strategies
   ✅ youtube.com - Found existing strategy: youtube
   ```

3. **Проверьте файлы:**
   - `data/zapret-hosts-auto.txt` - появился домен
   - `data/strat-youtube.txt` - домен добавлен к стратегии

---

## 🛑 Остановка

**1. Остановить Auto-Zapret:**
```
Ctrl+C в окне Python
```

**2. Остановить WinWS:**
```cmd
stop-winws.cmd
```

**3. (Опционально) Удалить драйвер:**
```cmd
sc stop WinDivert
sc delete WinDivert
```

---

## 🔍 Диагностика

### WinWS не запускается, ошибка WinDivert

**Решение:**
```cmd
# Запустить от администратора
install-windivert.cmd
```

### Secure Boot включен

1. Перезагрузите компьютер
2. Зайдите в BIOS (F2/Del при загрузке)
3. Найдите **Secure Boot** → **Disabled**
4. Сохраните и выйдите (F10)

### Антивирус блокирует

Добавьте исключения для:
- `D:\t1pe\Projects\auto-zapret\zapret-src\zapret-v72.12\binaries\windows-x86_64\WinDivert64.sys`
- `D:\t1pe\Projects\auto-zapret\zapret-src\zapret-v72.12\binaries\windows-x86_64\winws.exe`

### Логи пустые после посещения сайтов

1. Проверьте что WinWS запущен (окно открыто)
2. Проверьте что сайт действительно заблокирован (откройте без WinWS)
3. Перезапустите WinWS

---

## 📁 Структура

```
auto-zapret/
├── install-windivert.cmd    # Установка драйвера
├── start-winws.cmd          # Запуск WinWS
├── stop-winws.cmd           # Остановка WinWS
├── data/
│   ├── zapret-hosts-auto.txt  # Авто-домены
│   ├── strat-youtube.txt      # Стратегия YouTube
│   ├── strat-discord.txt      # Стратегия Discord
│   └── strat-default.txt      # Стратегия по умолчанию
├── logs/
│   └── autohostlist.log       # Лог событий
└── zapret-src/
    └── zapret-v72.12/
        └── binaries/windows-x86_64/
            ├── winws.exe      # DPI обходчик
            └── WinDivert64.sys # Драйвер
```

---

**Версия:** 1.1 | **Дата:** Март 2026
