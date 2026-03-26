# Auto-Zapret - Быстрый запуск

## 🚀 Запуск (ОДИН файл)

**Запустить ОТ АДМИНИСТРАТОРА:**

```cmd
start-auto-zapret.bat
```

**Что происходит:**
1. ✅ Открывается окно консоли
2. ✅ Проверяется WinDivert
3. ✅ Создаются файлы стратегий
4. ✅ Запускается **WinWS** (в отдельном окне)
5. ✅ Запускается **Auto-Zapret Web UI** (в отдельном окне)
6. ✅ **Окно батника остаётся открытым**

**Пока окно открыто:**
- WinWS и Auto-Zapret работают
- Откройте http://localhost:8000 для Web UI

**Для остановки:**
- Просто **закройте окно** `start-auto-zapret.bat`

---

## 📋 Отдельные компоненты

### Установка WinDivert (один раз)

**ОТ АДМИНИСТРАТОРА:**
```cmd
install-windivert.cmd
```

### Только WinWS

**ОТ АДМИНИСТРАТОРА:**
```cmd
start-winws.cmd
```

### Только Auto-Zapret Web UI

**Обычный пользователь:**
```cmd
python -m autozapret.main serve --port 8000
```

### Остановка WinWS

**ОТ АДМИНИСТРАТОРА:**
```cmd
stop-winws.cmd
```

---

## 🔍 Диагностика

### Проверка WinWS
```cmd
tasklist /FI "IMAGENAME eq winws.exe"
```

### Проверка Auto-Zapret
```cmd
curl http://localhost:8000/api/stats
```

### Логи
```cmd
type logs\autohostlist.log
```

### Домены в базе
```cmd
python -m autozapret.main domains list --all
```

---

## ⚠️ Важно

1. **WinDivert требует прав администратора**
2. **Secure Boot** - отключите в BIOS если блокирует драйвер
3. **Антивирус** - добавьте исключения для `winws.exe` и `WinDivert64.sys`
4. **Закрытие окна батника = остановка всех процессов**

---

**Версия:** 1.3 | **Дата:** Март 2026
