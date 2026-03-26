# Zapret Code Research

## Цель исследования
Полное изучение архитектуры и кода Zapret для реализации системы адаптивной мультистратегической маршрутизации.

---

## Статус реализации Auto-Zapret

✅ **MVP реализовано!**

- Все 60 тестов проходят
- Покрытие кода: 56%
- Реализованы базовые компоненты: Monitor, Analyzer, Executor, Storage

См. [README.md](./README.md) для документации по использованию.

---

## Часть 1: Общая структура проекта

### Дата начала исследования: 20 марта 2026

### Репозиторий
- **URL:** https://github.com/bol-van/zapret
- **Лицензия:** См. docs/LICENSE.txt
- **Статус:** zapret2 - активная версия, zapret (текущий) - в режиме EOL (End-Of-Life)

### Структура директорий
```
zapret-src/
├── nfq/           # nfqws (Linux) и winws (Windows) - основные демоны DPI обхода
│   ├── windows/   # Windows-specific код (windivert)
│   ├── crypto/    # Криптографические функции
│   └── ...        # Исходники ядра (desync.c, hostlist.c, params.c и т.д.)
├── tpws/          # Transparent Proxy Web Server (альтернативный метод)
│   ├── andr/      # Android версия
│   ├── macos/     # macOS совместимость
│   └── epoll-shim/# Linux epoll совместимость
├── ip2net/        # Утилита конвертации IP списков в ipset
├── mdig/          # Утилита для параллельного DNS резолвинга
├── common/        # Общие shell скрипты для установки
├── docs/          # Документация
├── init.d/        # Init скрипты для различных систем
├── ipset/         # Скрипты управления ipset
└── files/         # Дополнительные файлы конфигурации
```

---

## Часть 2: Ключевые компоненты

### 2.1 Основные исполняемые файлы

#### nfqws (Linux)
**Назначение:** Пакетный фильтр на базе Netfilter Queue для Linux
**Исходный код:** `nfq/nfqws.c` (3646 строк)
**Основные функции:**
- Перехват пакетов через libnetfilter_queue
- Conntrack для отслеживания TCP/UDP сессий
- Применение стратегий десинхронизации DPI
- Поддержка autohostlist

#### winws (Windows)
**Назначение:** Аналог nfqws для Windows на базе WinDivert
**Исходный код:** `nfq/nfqws.c` (общая база с nfqws)
**Особенности:**
- Использует WinDivert драйвер для перехвата пакетов
- Требуется подпись драйвера (проблемы с Secure Boot)
- Фильтры настраиваются через параметры `--wf-*`
- Нет поддержки ipset в ядре (user mode реализация)

#### tpws
**Назначение:** Transparent Proxy Web Server
**Принцип работы:** Сегментация TCP потока на уровне прокси
**Ограничения Windows:** Не работает нативно, только через WSL

### 2.2 Система стратегий (Strategies)

#### Разделитель --new
**Назначение:** Создание независимых стратегий обработки трафика
**Реализация:** `nfqws.c` строки ~3220-3230

**Пример использования:**
```bash
nfqws --filter-tcp=80 --dpi-desync=fake --hostlist=youtube.txt --new \
      --filter-tcp=443 --dpi-desync=split --hostlist=discord.txt
```

Каждая стратегия имеет:
- Уникальный номер профиля (`dp->n`)
- Собственные списки доменов (hostlist)
- Собственные списки IP (ipset)
- Индивидуальные параметры десинхронизации

#### Hostlist (списки доменов)
**Формат:** Текстовый файл, один домен в строке
**Особенности:**
- Поддержка комментариев (#, ;, //)
- Поддержка gzip сжатия
- Префикс `^` для строгого соответствия (без поддоменов)
- Автоматическое приведение к lowercase

**Файлы:** `hostlist.c`, `hostlist.h`

**Структуры данных:**
```c
typedef struct hostlist_pool {
    char *str;              // домен (key)
    uint32_t flags;         // HOSTLIST_POOL_FLAG_STRICT_MATCH
    UT_hash_handle hh;      // hash table
} hostlist_pool;

struct hostlist_file {
    char *filename;
    file_mod_sig mod_sig;   // для отслеживания изменений
    hostlist_pool *hostlist;
    LIST_ENTRY(hostlist_file) next;
};
```

**Механизм загрузки:**
- Ленивая загрузка при первом обращении
- Автоматическая перезагрузка при изменении файла (mod time check)
- Кэширование в памяти (hash table)

---

## Часть 3: Механизмы обхода DPI

### 3.1 Методы десинхронизации (desync.c)

**Основные режимы:**
```c
enum dpi_desync_mode {
    DESYNC_NONE=0,
    DESYNC_FAKE,           // Отправка фейковых пакетов
    DESYNC_FAKE_KNOWN,     // Фейки с известным содержимым
    DESYNC_RST,            // RST инжект
    DESYNC_RSTACK,         // RST+ACK инжект
    DESYNC_SYNACK,         // SYN+ACK режим
    DESYNC_SYNDATA,        // SYN+DATA режим
    DESYNC_FAKEDSPLIT,     // Фейк + сегментация
    DESYNC_FAKEDDISORDER,  // Фейк + disorder
    DESYNC_MULTISPLIT,     // Множественная сегментация
    DESYNC_MULTIDISORDER,  // Множественный disorder
    DESYNC_HOSTFAKESPLIT,  // Сегментация на позиции хоста
    DESYNC_IPFRAG2,        // IP фрагментация
    DESYNC_HOPBYHOP,       // IPv6 Hop-by-Hop
    DESYNC_DESTOPT,        // IPv6 Destination Options
    DESYNC_IPFRAG1,        // IP фрагментация (вариант 1)
    DESYNC_UDPLEN,         // Модификация UDP length
    DESYNC_TAMPER          // Модификация оригинала
};
```

### 3.2 Параметры командной строки

**Ключевые параметры для Auto-Zapret:**

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--hostlist-auto=<file>` | Файл для автоматического добавления проблемных доменов | - |
| `--hostlist-auto-fail-threshold=N` | Количество неудачных попыток перед добавлением в список | 3 |
| `--hostlist-auto-fail-time=N` | Время жизни записи о неудаче (секунды) | 60 |
| `--hostlist-auto-retrans-threshold=N` | Количество TCP retransmissions для детектирования проблемы | 3 |
| `--hostlist-auto-debug=<file>` | Логирование событий autohostlist | - |
| `--new` | Начать новую стратегию | - |
| `--skip` | Пропустить текущую стратегию (для условной логики) | - |

**Диапазоны значений:**
- `hostlist-auto-fail-threshold`: 1-20
- `hostlist-auto-retrans-threshold`: 2-10

---

## Часть 4: Autohostlist - детальное изучение

### 4.1 Архитектура Autohostlist

**Файлы:** `desync.c` (функции auto_hostlist_*), `pools.h` (hostfail_pool)

**Структура hostfail_pool:**
```c
typedef struct hostfail_pool {
    char *str;              // домен (key)
    int counter;            // счётчик неудач
    time_t expire;          // время истечения (unix timestamp)
    UT_hash_handle hh;      // hash table
} hostfail_pool;
```

**Структура desync_profile:**
```c
struct desync_profile {
    // ... другие параметры ...
    
    struct hostlist_file *hostlist_auto;  // указатель на autohostlist файл
    int hostlist_auto_fail_threshold;     // порог неудач
    int hostlist_auto_fail_time;          // время жизни неудачи
    int hostlist_auto_retrans_threshold;  // порог retransmission
    
    hostfail_pool *hostlist_auto_fail_counters;  // пул счётчиков
};
```

### 4.2 Алгоритм работы Autohostlist

**Шаг 1: Детектирование retransmission**
```c
// desync.c: auto_hostlist_retrans()
// Отслеживает TCP retransmissions в пределах запроса
if (ctrack->req_retrans_counter >= threshold) {
    ctrack_stop_retrans_counter(ctrack);
    return true;  // порог достигнут
}
```

**Шаг 2: Увеличение счётчика неудач**
```c
// desync.c: auto_hostlist_failed()
fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
if (!fail_counter) {
    fail_counter = HostFailPoolAdd(&dp->hostlist_auto_fail_counters, 
                                    hostname, dp->hostlist_auto_fail_time);
}
fail_counter->counter++;
```

**Шаг 3: Добавление в hostlist при достижении порога**
```c
// desync.c: auto_hostlist_failed()
if (fail_counter->counter >= dp->hostlist_auto_fail_threshold) {
    // Проверка на дубликаты
    if (!HostlistCheck(dp, hostname, bNoSubdom, &bExcluded, false) && !bExcluded) {
        // Добавление в память
        HostlistPoolAddStr(&dp->hostlist_auto->hostlist, hostname, 0);
        
        // Добавление в файл
        append_to_list_file(dp->hostlist_auto->filename, hostname);
        
        // Обновление mod signature
        file_mod_signature(dp->hostlist_auto->filename, &dp->hostlist_auto->mod_sig);
    }
}
```

### 4.3 Сброс счётчиков

**Автоматический сброс при успешном соединении:**
```c
// desync.c: auto_hostlist_reset_fail_counter()
fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
if (fail_counter) {
    HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
    DLOG("fail counter reset. website is working.\n");
}
```

### 4.4 Очистка устаревших записей

**Rate-limited purge:**
```c
// pools.c: HostFailPoolPurgeRateLimited()
// Удаляет записи с истёкшим временем expire
// Вызывается периодически в основном цикле обработки
```

---

## Часть 5: Conntrack - отслеживание соединений

### 5.1 Структура t_ctrack

**Файл:** `conntrack.h`

```c
typedef struct {
    // Состояние соединения
    time_t t_start, t_last;
    uint64_t pcounter_orig, pcounter_reply;    // счётчики пакетов
    uint32_t pos_orig, pos_reply;              // позиции в потоке
    
    // TCP состояние
    t_connstate state;  // SYN, ESTABLISHED, FIN
    uint32_t seq0, ack0;
    uint16_t winsize_orig, winsize_reply;
    
    // Autohostlist специфичные поля
    uint8_t req_retrans_counter;        // счётчик retransmissions
    bool req_seq_present;
    uint32_t req_seq_start, req_seq_end; // диапазон последовательностей запроса
    
    // Hostname кэширование
    char *hostname;
    bool hostname_discovered;
    bool hostname_ah_check;  // флаг необходимости autohostlist проверки
    
    // Кэш результатов проверки hostlist
    bool bCheckDone, bCheckResult, bCheckExcluded;
    struct desync_profile *dp;  // кэш профиля
} t_ctrack;
```

### 5.2 Временные параметры Conntrack

```c
#define CTRACK_T_SYN      60    // SYN состояние
#define CTRACK_T_FIN      60    // FIN/RST состояние  
#define CTRACK_T_EST      300   // ESTABLISHED состояние
#define CTRACK_T_UDP      60    // UDP таймаут
```

---

## Часть 6: API и возможности управления

### 6.1 Горячая перезагрузка конфигурации

**Сигнал SIGHUP:**
```c
// nfqws.c: onhup()
static void onhup(int sig) {
    printf("HUP received ! Lists will be reloaded.\n");
    bReload = true;
}

// nfqws.c: ReloadCheck()
static void ReloadCheck() {
    if (bReload) {
        ResetAllHostlistsModTime();  // Сброс mod time
        if (!LoadAllHostLists()) {   // Принудительная перезагрузка
            DLOG_ERR("hostlists load failed. this is fatal.\n");
            exit(1);
        }
        ResetAllIpsetModTime();
        if (!LoadAllIpsets()) {
            DLOG_ERR("ipset load failed. this is fatal.\n");
            exit(1);
        }
        bReload = false;
    }
}
```

**Важно:** Перезагрузка происходит в основном цикле обработки пакетов, не прерывая текущие соединения.

### 6.2 Сигналы управления

| Сигнал | Обработчик | Описание |
|--------|-----------|----------|
| `SIGHUP` | `onhup()` | Перезагрузка hostlist/ipset файлов |
| `SIGUSR1` | `onusr1()` | Дамп conntrack pool в лог |
| `SIGUSR2` | `onusr2()` | Дамп hostfail pool и ipcache в лог |

### 6.3 Логирование и события

**Параметры логирования:**
- `--debug` - включение отладочного логирования
- `--debug-log=<file>` - файл для отладочного лога

**Autohostlist отладка:**
- `--hostlist-auto-debug=<file>` - лог всех событий autohostlist

**Формат логов autohostlist:**
```
<домен> : profile <N> : client <IP:port> : proto <HTTP/TLS/QUIC> : fail counter X/Y
<домен> : profile <N> : client <IP:port> : proto <HTTP/TLS/QUIC> : adding to <файл>
<домен> : profile <N> : client <IP:port> : proto <HTTP/TLS/QUIC> : NOT adding, duplicate detected
```

---

## Часть 7: Архитектурные выводы для Auto-Zapret

### 7.1 Возможности для динамического управления

#### ✅ Реализованные возможности:

1. **Множественные независимые стратегии**
   - Параметр `--new` создаёт новый профиль
   - Каждый профиль имеет свои hostlist/ipset
   - Обработка пакетов происходит параллельно

2. **Горячая перезагрузка списков**
   - SIGHUP вызывает перезагрузку без разрыва соединений
   - Mod time проверка предотвращает лишние чтения файлов

3. **Автоматическое добавление доменов**
   - Autohostlist уже реализует детектирование проблем
   - Добавление в файл происходит атомарно (append mode)

4. **API для программного управления**
   - Функция `append_to_list_file()` для добавления доменов
   - Функция `HostlistPoolAddStr()` для добавления в память
   - Функция `HostFailPoolAdd/Find/Del()` для управления счётчиками

#### ⚠️ Ограничения:

1. **Отсутствие API для удаления доменов из hostlist**
   - Нет встроенной функции для удаления домена из файла
   - Требуется внешняя утилита для редактирования файла

2. **Нет API для изменения стратегии на лету**
   - Параметры стратегии фиксированы при запуске
   - Нельзя изменить `--dpi-desync` для существующего профиля

3. **Нет сетевого API / IPC**
   - Управление только через сигналы и файлы
   - Нет socket / pipe для внешнего управления

4. **Autohostlist работает только на добавление**
   - Не может менять стратегию для домена
   - Только добавляет в предопределённый профиль

### 7.2 Рекомендуемый подход к интеграции

#### Архитектура Auto-Zapret:

```
┌─────────────────────────────────────────────────────────────┐
│                    Auto-Zapret Manager                       │
│  (отдельный процесс / служба)                               │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Монитор    │  │  Анализатор  │  │  Исполнитель │      │
│  │  (Monitor)   │  │  (Analyzer)  │  │  (Executor)  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         ▼                 ▼                 ▼               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Анализ логов │  │ База знаний  │  │ Управление   │      │
│  │ nfqws        │  │ стратегий    │  │ файлами      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Zapret (nfqws)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Профиль 1: YouTube    --hostlist=youtube.txt        │   │
│  │  Профиль 2: Discord    --hostlist=discord.txt        │   │
│  │  Профиль 3: Auto-Fix   --hostlist-auto=auto-fix.txt  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### Компоненты Auto-Zapret:

**1. Монитор (Monitor)**
```
Входные данные:
- Логи nfqws (--debug-log или --hostlist-auto-debug)
- Сетевые события (опционально)
- Ручные запросы пользователя (UI)

Выходные данные:
- Список проблемных доменов
- Статистика по стратегиям
```

**2. Анализатор (Analyzer)**
```
Входные данные:
- Проблемные домены от Монитора
- База знаний успешных стратегий

Логика:
1. Проверка текущей стратегии домена
2. Тестирование активных стратегий
3. Расширенный перебор (если нужно)

Выходные данные:
- Рекомендованная стратегия для домена
```

**3. Исполнитель (Executor)**
```
Входные данные:
- Домен + стратегия от Анализатора

Действия:
1. Добавление домена в соответствующий hostlist файл
2. Отправка SIGHUP для перезагрузки
3. Верификация применения

Выходные данные:
- Статус применения стратегии
```

#### Механизм взаимодействия:

**Способ 1: Через файлы hostlist (рекомендуется)**
```bash
# Auto-Zapret добавляет домен в файл
echo "example.com" >> /opt/zapret/ipset/zapret-hosts-auto-fix.txt

# Отправка SIGHUP для применения
kill -HUP $(pidof nfqws)
```

**Способ 2: Прямое редактирование памяти (требует доработки nfqws)**
```c
// Требуется добавить IPC API в nfqws
// Например, Unix socket для команд:
// ADD_DOMAIN <profile_id> <domain>
// REMOVE_DOMAIN <profile_id> <domain>
// GET_STATS
```

### 7.3 Необходимые доработки Zapret

#### Минимальные (для работы через файлы):

1. **Утилита для безопасного удаления доменов из hostlist**
   - Чтение файла
   - Удаление строки
   - Атомарная запись

2. **Оптимизация SIGHUP обработки**
   - Перезагрузка только изменённых файлов
   - Инвалидация кэша по конкретному домену

#### Расширенные (для полноценного API):

1. **IPC механизм (Unix socket / named pipe)**
   ```c
   // Новый параметр: --api-socket=/var/run/nfqws.sock
   // Команды:
   // HOSTLIST_ADD <profile> <domain>
   // HOSTLIST_REMOVE <profile> <domain>
   // PROFILE_CREATE <config_string>
   // STATS_GET
   ```

2. **Динамическое создание профилей**
   ```c
   // Возможность создания нового профиля через API
   // без перезапуска процесса
   ```

3. **Статистика по доменам**
   ```c
   // Экспорт статистики:
   // - количество запросов к домену
   // - количество неудач
   // - текущая стратегия
   ```

---

## Приложения

### A. Список изученных файлов

| Файл | Строк | Описание |
|------|-------|----------|
| `nfq/nfqws.c` | 3646 | Главный файл nfqws/winws |
| `nfq/desync.c` | 3505 | Логика десинхронизации DPI |
| `nfq/hostlist.c` | ~300 | Управление списками доменов |
| `nfq/hostlist.h` | ~30 | Заголовки hostlist |
| `nfq/params.c` | ~400 | Парсинг параметров |
| `nfq/params.h` | 277 | Структуры параметров |
| `nfq/pools.c` | ~200 | Пулы данных (hash tables) |
| `nfq/pools.h` | ~200 | Заголовки пулов |
| `nfq/conntrack.h` | ~150 | Conntrack структуры |
| `nfq/helpers.c` | 551 | Вспомогательные функции |
| `docs/readme.md` | 2734 | Основная документация |
| `docs/windows.md` | 282 | Windows специфика |
| `config.default` | ~120 | Конфигурация по умолчанию |

### B. Важные фрагменты кода

#### B.1 Обработка SIGHUP
```c
// nfqws.c:57-77
static void onhup(int sig)
{
    printf("HUP received ! Lists will be reloaded.\n");
    bReload = true;
}

static void ReloadCheck()
{
    if (bReload)
    {
        ResetAllHostlistsModTime();
        if (!LoadAllHostLists()) {
            DLOG_ERR("hostlists load failed. this is fatal.\n");
            exit(1);
        }
        ResetAllIpsetModTime();
        if (!LoadAllIpsets()) {
            DLOG_ERR("ipset load failed. this is fatal.\n");
            exit(1);
        }
        bReload = false;
    }
}
```

#### B.2 Добавление домена в autohostlist
```c
// desync.c:425-470
static void auto_hostlist_failed(struct desync_profile *dp, 
                                  const char *hostname, 
                                  bool bNoSubdom, 
                                  const char *client_ip_port, 
                                  t_l7proto l7proto)
{
    hostfail_pool *fail_counter;

    fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
    if (!fail_counter)
    {
        fail_counter = HostFailPoolAdd(&dp->hostlist_auto_fail_counters, 
                                        hostname, dp->hostlist_auto_fail_time);
        if (!fail_counter) {
            DLOG_ERR("HostFailPoolAdd: out of memory\n");
            return;
        }
    }
    fail_counter->counter++;
    
    if (fail_counter->counter >= dp->hostlist_auto_fail_threshold)
    {
        HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);

        bool bExcluded = false;
        if (!HostlistCheck(dp, hostname, bNoSubdom, &bExcluded, false) && !bExcluded)
        {
            if (!HostlistPoolAddStr(&dp->hostlist_auto->hostlist, hostname, 0)) {
                DLOG_ERR("StrPoolAddStr out of memory\n");
                return;
            }
            if (!append_to_list_file(dp->hostlist_auto->filename, hostname)) {
                DLOG_PERROR("write to auto hostlist");
                return;
            }
            if (!file_mod_signature(dp->hostlist_auto->filename, &dp->hostlist_auto->mod_sig))
                DLOG_PERROR("file_mod_signature");
        }
    }
}
```

#### B.3 Append to list file
```c
// helpers.c:107-114
bool append_to_list_file(const char *filename, const char *s)
{
    FILE *F = fopen(filename,"at");
    if (!F) return false;
    bool bOK = fprintf(F,"%s\n",s)>0;
    fclose(F);
    return bOK;
}
```

### C. Диаграммы архитектуры

#### C.1 Поток обработки пакета
```
Пакет → Netfilter Queue → nfqws callback
                              │
                              ▼
                        Conntrack lookup
                              │
                              ▼
                    ┌─────────┴─────────┐
                    ▼                   ▼
            Новое соединение    Известное соединение
                    │                   │
                    ▼                   ▼
            DNS резолвинг        Кэш профиля (dp)
            (если hostname)             │
                    │                   ▼
                    ▼           HostlistCheck()
            Создание ctrack           │
                    │                 ▼
                    ▼         ┌───────┴───────┐
            Autohostlist      ▼               ▼
            проверка     Применить стратегию  Пропустить
                    │             │
                    ▼             ▼
            Обновление       DPI Desync
            счётчиков        (fake/split/etc)
                    │
                    ▼
            Добавление в файл
            (если порог достигнут)
```

#### C.2 Взаимодействие Auto-Zapret с nfqws
```
┌─────────────────┐     ┌─────────────────┐
│  Auto-Zapret    │     │     nfqws       │
│    Manager      │     │                 │
├─────────────────┤     ├─────────────────┤
│                 │     │                 │
│  Monitor        │────▶│  Debug Log      │
│  (читает лог)   │     │  (--debug-log)  │
│                 │     │                 │
│  Analyzer       │     │                 │
│  (база знаний)  │     │                 │
│                 │     │                 │
│  Executor       │     │  Hostlist Files │
│  (пишет файлы)  │────▶│  (auto-*.txt)   │
│                 │     │                 │
│  Controller     │     │  SIGHUP Handler │
│  (kill -HUP)    │────▶│                 │
│                 │     │                 │
└─────────────────┘     └─────────────────┘
```

---

## Часть 8: Следующие шаги исследования

### Приоритет 1 (критично для прототипа):
1. ✅ Изучить механизм autohostlist
2. ✅ Изучить систему множественных стратегий
3. ✅ Изучить горячую перезагрузку
4. ⬜ Написать прототип Монитора (парсинг логов)
5. ⬜ Написать прототип Исполнителя (управление файлами)

### Приоритет 2 (для полноценной системы):
1. ⬜ Спроектировать базу знаний стратегий
2. ⬜ Реализовать Анализатор (подбор стратегий)
3. ⬜ Создать UI для ручного управления
4. ⬜ Добавить статистику и мониторинг

### Приоритет 3 (оптимизация):
1. ⬜ Исследовать возможность IPC API для nfqws
2. ⬜ Оптимизировать частоту SIGHUP
3. ⬜ Реализовать инкрементальную перезагрузку

---

*Документ обновляется по мере изучения кода*
