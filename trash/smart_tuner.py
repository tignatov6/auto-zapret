#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Tuner for Windows (Zapret WinWS) v2.7 (Smart Path Fix)
Расширенная версия: интеграция логики blockcheck.sh
Поддержка WSSIZE, циклов TTL, AutoTTL, SeqOvl и новых Fake модов.
+ АВТОМАТИЧЕСКИЙ ПОИСК ПУТЕЙ К ФАЙЛАМ ФЕЙКОВ
"""

import os
import sys
import io
import time
import subprocess
import socket
import ssl
import urllib.request
import urllib.error
import statistics
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

# ══════════════════════════════════════════════════════════
#                 ФИКС КОДИРОВКИ WINDOWS
# ══════════════════════════════════════════════════════════

def fix_encoding():
    """Исправить кодировку консоли Windows для кириллицы."""
    if sys.platform == 'win32':
        try:
            os.system('chcp 65001 >nul 2>&1')
        except Exception:
            pass
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True
            )
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True
            )
        except Exception:
            pass

fix_encoding()

# ══════════════════════════════════════════════════════════
#                      ANSI ЦВЕТА
# ══════════════════════════════════════════════════════════

class C:
    RESET  = '\033[0m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'

# ══════════════════════════════════════════════════════════
#                     КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
WINWS_PATH = BASE_DIR / "bin" / "winws.exe"

# ══════════════════════════════════════════════════════════
#            УМНЫЙ ПОИСК ФАЙЛОВ ФЕЙКОВ (NEW)
# ══════════════════════════════════════════════════════════

FAKE_DIR = None
FAKE_QUIC = None
FAKE_TLS = None

def find_fake_files():
    """
    Пытается найти bin файлы в нескольких предполагаемых местах.
    Возвращает True, если найдены оба файла (или хотя бы подходящие кандидаты).
    """
    global FAKE_DIR, FAKE_QUIC, FAKE_TLS
    
    # Список путей, где мы ожидаем увидеть папку fake
    possible_paths = [
        BASE_DIR / "bin" / "blockcheck" / "zapret" / "files" / "fake",
        BASE_DIR / "bin" / "blockcheck" / "files" / "fake",
        BASE_DIR / "bin" / "files" / "fake",
        BASE_DIR / "files" / "fake",
    ]

    # Если файлы лежат прямо в папке со скриптом (редко, но бывает)
    if (BASE_DIR / "quic_initial_www_google_com.bin").exists():
        FAKE_DIR = BASE_DIR
        FAKE_QUIC = BASE_DIR / "quic_initial_www_google_com.bin"
        FAKE_TLS = BASE_DIR / "tls_clienthello_www_google_com.bin"
        return True

    for path in possible_paths:
        if path.exists() and path.is_dir():
            # Ищем все .bin файлы в папке
            bins = list(path.glob("*.bin"))
            if bins:
                FAKE_DIR = path
                # Пытаемся умно сопоставить файлы
                quic_match = [f for f in bins if 'quic' in f.name.lower()]
                tls_match = [f for f in bins if 'tls' in f.name.lower() and 'hello' in f.name.lower()]

                if quic_match:
                    FAKE_QUIC = quic_match[0]
                else:
                    # Если точного совпадения нет, берем первый попавшийся как QUIC (рискованно, но лучше чем ничего)
                    if len(bins) > 0: FAKE_QUIC = bins[0]

                if tls_match:
                    FAKE_TLS = tls_match[0]
                else:
                    # Если точного совпадения нет, берем второй файл как TLS
                    if len(bins) > 1: FAKE_TLS = bins[1]
                
                # Проверка, нашли ли мы что-то вменяемое
                if FAKE_QUIC and FAKE_TLS:
                    return True

    return False

HAS_FAKE_FILES = find_fake_files()

TEST_TARGETS = [
    ("discord.com", 443),
    ("youtube.com", 443),
    ("speedtest.net", 443),
    ("huggingface.co", 443),
    ("npmjs.com", 443),
    ("steampowered.com", 443),
    ("pypi.org", 443),
]

DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"

# Настройки теста
TCP_TIMEOUT     = 1
INIT_WAIT       = 4.0
DOWNLOAD_TIMEOUT = 3
MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
DOWNLOAD_CHUNK_SIZE = 8192

# ══════════════════════════════════════════════════════════
#              НАСТРОЙКИ РЕЖИМА ПРОВЕРКИ
# ══════════════════════════════════════════════════════════

FAST_MODE = False  # Будет установлен через меню

# Паттерны, которые по эмпирическим данным ВСЕГДА дают FAIL на всех сайтах
# (на основе анализа логов: badsum/badseq/datanoack/http_multisplit и т.д.)
KNOWN_FAIL_PATTERNS = [
    '_badsum_', '_badseq_', '_datanoack_',
    'http_multisplit_method+2', 'http_multisplit_midsld',
    'fake_autottl-', 'fakedsplit_autottl-', 'fake,multisplit_autottl-',
]

# Диапазоны для генерации (из blockcheck.sh)
MIN_TTL = 1
MAX_TTL = 16
MIN_AUTOTTL_DELTA = 1
MAX_AUTOTTL_DELTA = 8

# ══════════════════════════════════════════════════════════
#               СТРУКТУРЫ ДАННЫХ
# ══════════════════════════════════════════════════════════

@dataclass
class Attempt:
    success: bool
    time_ms: float
    error: Optional[str] = None
    speed_mbps: Optional[float] = None
    size_bytes: int = 0

# ══════════════════════════════════════════════════════════
#                    ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║     SMART TUNER for Zapret WinWS  v2.7 (Smart Path)   ║
║    Интеграция логики blockcheck.sh (TTL, WSSIZE, Mods)   ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")

def kill_winws():
    """Жёстко убить все процессы winws.exe"""
    try:
        subprocess.run(
            ['taskkill', '/F', '/IM', 'winws.exe'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
    except Exception:
        pass
    time.sleep(0.5)

def check_prerequisites():
    """Проверить наличие необходимых файлов"""
    errors = []
    if not WINWS_PATH.exists():
        errors.append(f"  Не найден winws.exe: {WINWS_PATH}")
    
    if not HAS_FAKE_FILES:
        print(f"{C.YELLOW}[!] Внимание: Файлы фейков (.bin) НЕ НАЙДЕНЫ.{C.RESET}")
        print(f"{C.YELLOW}    Скрипт просканировал стандартные папки, но ничего не нашел.{C.RESET}")
        print(f"{C.YELLOW}    Режимы 'fake', 'hostfakesplit' и циклы TTL будут отключены.{C.RESET}")
        print(f"{C.YELLOW}    Будут проверены только базовые Splits (всего около 50 стратегий).{C.RESET}\n")
    else:
        print(f"{C.GREEN}[✓] Файлы фейков найдены автоматически:{C.RESET}")
        print(f"    Папка: {FAKE_DIR}")
        if FAKE_QUIC: print(f"    QUIC : {FAKE_QUIC.name}")
        if FAKE_TLS:  print(f"    TLS  : {FAKE_TLS.name}")
        print()
    
    if errors:
        print(f"{C.RED}[ОШИБКА] Критические ошибки:{C.RESET}")
        for e in errors:
            print(f"{C.RED}{e}{C.RESET}")
        if not WINWS_PATH.exists():
            return False
    return True

# ══════════════════════════════════════════════════════════
#       ЛОГИКА ТЕСТИРОВАНИЯ
# ══════════════════════════════════════════════════════════

def test_https(host: str, port: int = 443, timeout: float = 6) -> Attempt:
    """Полноценная проверка HTTPS с рукопожатием"""
    t0 = time.time()
    _ms = lambda: (time.time() - t0) * 1000

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except socket.timeout:
        sock.close()
        return Attempt(False, _ms(), 'timeout')
    except ConnectionRefusedError:
        sock.close()
        return Attempt(False, _ms(), 'refused')
    except OSError as exc:
        sock.close()
        e = str(exc)
        if '10061' in e:
            return Attempt(False, _ms(), 'refused')
        return Attempt(False, _ms(), 'connection')

    ctx = ssl.create_default_context()
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError:
        sock.close()
        return Attempt(False, _ms(), 'tls')
    except socket.timeout:
        sock.close()
        return Attempt(False, _ms(), 'tls')
    except ConnectionResetError:
        sock.close()
        return Attempt(False, _ms(), 'reset')
    except OSError as exc:
        sock.close()
        e = str(exc)
        if '10060' in e or 'timed out' in e.lower():
            return Attempt(False, _ms(), 'tls')
        if '10054' in e:
            return Attempt(False, _ms(), 'reset')
        return Attempt(False, _ms(), 'connection')

    try:
        ssock.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = ssock.recv(256)
        ms = _ms()
        ssock.close()
        return Attempt(True, ms, None) if data else Attempt(False, ms, 'empty')
    except Exception:
        ms = _ms()
        try:
            ssock.close()
        except Exception:
            pass
        return Attempt(False, ms, 'http')


def test_download_speed(url: str, timeout: int = DOWNLOAD_TIMEOUT, verbose=True) -> Attempt:
    """Тест скорости с лимитами"""
    t0 = time.time()
    _ms = lambda: (time.time() - t0) * 1000
    downloaded_bytes = 0
    
    max_time = timeout 

    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) DPI-Checker/3.2'}
        )
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            last_print_bytes = 0
            
            while downloaded_bytes < MAX_DOWNLOAD_SIZE:
                if (time.time() - t0) > max_time:
                    break
                
                chunk = response.read(DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                
                downloaded_bytes += len(chunk)
                
                if verbose:
                    if downloaded_bytes - last_print_bytes >= 1024 * 1024:
                        mb_downloaded = downloaded_bytes / (1024 * 1024)
                        sys.stdout.write(f"\r      [~] Загрузка: {mb_downloaded:.1f} MB")
                        sys.stdout.flush()
                        last_print_bytes = downloaded_bytes

            duration_sec = time.time() - t0
            if duration_sec == 0: duration_sec = 0.001
            
            speed_bps = downloaded_bytes / duration_sec
            speed_mbps = (speed_bps / 1024 / 1024)
            
            if verbose:
                final_mb = downloaded_bytes / (1024 * 1024)
                print(f"\r      [+] Готово: {final_mb:.1f} MB @ {speed_mbps:.2f} MB/s   \n")
            
            return Attempt(
                success=True, 
                time_ms=duration_sec * 1000, 
                speed_mbps=speed_mbps,
                size_bytes=downloaded_bytes
            )
            
    except urllib.error.URLError as e:
        return Attempt(False, _ms(), f"URL Error: {e.reason}")
    except socket.timeout:
        return Attempt(False, _ms(), 'timeout')
    except Exception as e:
        return Attempt(False, _ms(), str(e))

# ══════════════════════════════════════════════════════════
#      ГЕНЕРАЦИЯ СТРАТЕГИЙ (Расширенная логика blockcheck.sh)
# ══════════════════════════════════════════════════════════

def build_strategies():
    """
    Генерирует матрицу стратегий, максимально приближенную к логике blockcheck.sh
    для Windows (winws).
    """
    strategies = []

    splits_tls = ["1", "2", "sniext+1", "sniext+4", "host+1", "midsld", "1,midsld", "1,sniext+1,host+1,midsld"]
    splits_http = ["method+2", "midsld", "method+2,midsld"]
    
    # Fooling методы из blockcheck.sh
    fools = ["ts", "md5sig", "badsum", "badseq", "datanoack"]

    # ──── ПРИОРИТЕТ 1: Multisplit / Multidisorder + TS ────
    print(f"{C.DIM}[~] Генерация базовых Splits стратегий...{C.RESET}")
    modes_split = ["multisplit", "multidisorder"]
    
    for mode in modes_split:
        priority_pos = ["sniext+1", "1", "midsld", "1,midsld"]
        
        for pos in priority_pos:
            for rep in [1, 3]:
                for fool in ["ts"]: 
                    strategies.append({
                        "name": f"{mode}_{pos}_{fool}_R{rep}",
                        "mode": mode, "pos": pos, "fool": fool, "rep": rep,
                        "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None, "extra": None
                    })
        
        # Остальные позиции (менее приоритетные)
        for pos in splits_tls:
            if pos not in priority_pos:
                for rep in [1]:
                    for fool in ["ts", "md5sig"]:
                        strategies.append({
                            "name": f"{mode}_{pos}_{fool}_R{rep}",
                            "mode": mode, "pos": pos, "fool": fool, "rep": rep,
                            "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None, "extra": None
                        })

    # ──── ПРИОРИТЕТ 2: WSSIZE (Window Size) ────
    print(f"{C.DIM}[~] Генерация WSSIZE стратегий...{C.RESET}")
    for mode in modes_split:
        for pos in ["1", "2", "sniext+1"]:
            for wssize in [None, "1:6"]:
                for fool in ["ts"]:
                    name_wssize = f"_wssize{wssize}" if wssize else ""
                    strategies.append({
                        "name": f"{mode}_{pos}_{fool}{name_wssize}_R1",
                        "mode": mode, "pos": pos, "fool": fool, "rep": 1,
                        "wssize": wssize, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None, "extra": None
                    })

    # ──── ПРИОРИТЕТ 3: SeqOvl (Sequence Overlap) ────
    print(f"{C.DIM}[~] Генерация SeqOvl стратегий...{C.RESET}")
    for mode in modes_split:
        for pos in ["1", "2", "sniext+1"]:
            for seqovl in [1, 2]: 
                strategies.append({
                    "name": f"{mode}_{pos}_seqovl{seqovl}_R1",
                    "mode": mode, "pos": pos, "fool": "", "rep": 1,
                    "wssize": None, "ttl": None, "autottl": None, "seqovl": seqovl, "fake_tls_mod": None, "extra": None
                })

    # ──── ПРИОРИТЕТ 4: Fake режимы с полным циклом TTL и Fooling ────
    if HAS_FAKE_FILES:
        print(f"{C.GREEN}[+] Генерация FAKE режимов (TTL/Fooling)... Это займет время.{C.RESET}")
        
        fake_modes = ["fake", "fakedsplit", "fake,multisplit", "hostfakesplit"]
        
        for mode in fake_modes:
            current_splits = [None]
            if "split" in mode:
                current_splits = ["1", "midsld"]
            elif mode == "hostfakesplit":
                current_splits = [None, "midsld"] 

            for pos in current_splits:
                # Цикл TTL (1-12)
                for ttl in range(MIN_TTL, MAX_TTL + 1):
                    for fool in fools:
                        strategies.append({
                            "name": f"{mode}_p{pos or '_'}_TTL{ttl}_{fool}_R2",
                            "mode": mode, "pos": pos, "fool": fool, "rep": 2,
                            "wssize": None, "ttl": ttl, "autottl": None, "seqovl": None, "fake_tls_mod": None, "extra": None
                        })
                
                # Цикл Auto TTL
                for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                    strategies.append({
                        "name": f"{mode}_autottl-{delta}_R2",
                        "mode": mode, "pos": pos, "fool": "ts", "rep": 2,
                        "wssize": None, "ttl": 1, "autottl": f"-{delta}", "seqovl": None, "fake_tls_mod": None, "extra": None
                    })

        # ──── ПРИОРИТЕТ 5: Fake TLS Mods ────
        print(f"{C.DIM}[~] Генерация Fake TLS Mods...{C.RESET}")
        for mod in ["rnd,rndsni,dupsid", "padencap"]:
            strategies.append({
                "name": f"fake_mod_{mod}_R2",
                "mode": "fake", "pos": None, "fool": "ts", "rep": 2,
                "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": mod, "extra": None
            })
            
        # ──── ПРИОРИТЕТ 6: HostFakeSplit специфичные модификаторы ────
        print(f"{C.DIM}[~] Генерация HostFakeSplit модов...{C.RESET}")
        strategies.append({
            "name": "hostfakesplit_altorder1",
            "mode": "hostfakesplit", "pos": None, "fool": "ts", "rep": 2,
            "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None,
            "extra": ["--dpi-desync-hostfakesplit-mod=altorder=1"]
        })
        strategies.append({
            "name": "hostfakesplit_midhost",
            "mode": "hostfakesplit", "pos": "midsld", "fool": "ts", "rep": 2,
            "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None,
            "extra": ["--dpi-desync-hostfakesplit-midhost=midsld"]
        })

    # ──── ПРИОРИТЕТ 7: Http простые методы ────
    print(f"{C.DIM}[~] Генерация HTTP модификаторов...{C.RESET}")
    for pos in splits_http:
        strategies.append({
            "name": f"http_multisplit_{pos}",
            "mode": "multisplit", "pos": pos, "fool": "", "rep": 1,
            "wssize": None, "ttl": None, "autottl": None, "seqovl": None, "fake_tls_mod": None, "extra": None
        })

    return strategies

# ══════════════════════════════════════════════════════════
#              ПОСТРОЕНИЕ КОМАНДНОЙ СТРОКИ
# ══════════════════════════════════════════════════════════

def build_cmd(strat):
    """Построить список аргументов для winws.exe"""
    cmd = [str(WINWS_PATH)]

    cmd.append("--wf-tcp=80,443")
    cmd.append("--wf-udp=443")

    if HAS_FAKE_FILES and FAKE_QUIC and FAKE_TLS:
        cmd.append(f"--dpi-desync-fake-quic={FAKE_QUIC}")
        cmd.append(f"--dpi-desync-fake-tls={FAKE_TLS}")

    cmd.append("--filter-udp=443")
    if HAS_FAKE_FILES:
        cmd.append("--dpi-desync=fake")
        cmd.append(f"--dpi-desync-repeats={strat['rep'] + 2}")
    else:
        cmd.append("--dpi-desync=multisplit")
        cmd.append("--dpi-desync-repeats=2")

    cmd.append("--new")
    cmd.append("--filter-tcp=443")
    cmd.append(f"--dpi-desync={strat['mode']}")

    if strat.get('pos'):
        cmd.append(f"--dpi-desync-split-pos={strat['pos']}")

    if strat.get('fool'):
        cmd.append(f"--dpi-desync-fooling={strat['fool']}")
    
    cmd.append(f"--dpi-desync-repeats={strat['rep']}")

    if strat.get('wssize'):
        cmd.append(f"--wssize={strat['wssize']}")
        
    if strat.get('ttl'):
        cmd.append(f"--dpi-desync-ttl={strat['ttl']}")
        
    if strat.get('autottl'):
        cmd.append(f"--dpi-desync-autottl={strat['autottl']}")
        
    if strat.get('seqovl'):
        cmd.append(f"--dpi-desync-split-seqovl={strat['seqovl']}")
        
    if strat.get('fake_tls_mod'):
        cmd.append(f"--dpi-desync-fake-tls-mod={strat['fake_tls_mod']}")

    if strat.get('extra'):
        cmd.extend(strat['extra'])

    return cmd

# ══════════════════════════════════════════════════════════
#                  ЛОГИКА ТЕСТИРОВАНИЯ
# ══════════════════════════════════════════════════════════

def should_skip_fast_mode(strat_name: str) -> bool:
    """Проверить, попадает ли стратегия под известные нерабочие паттерны."""
    name_lower = strat_name.lower()
    for pattern in KNOWN_FAIL_PATTERNS:
        if pattern.lower() in name_lower:
            return True
    # Дополнительно: чистый fake без split/disorder тоже почти всегда FAIL
    if strat_name.startswith('fake_p__') and '_split' not in name_lower and 'disorder' not in name_lower:
        return True
    return False


def run_test(strategies, speed_url):
    global FAST_MODE
    results = []

    kill_winws()
    print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}  НАЧИНАЕМ АВТОПОИСК ИДЕАЛЬНОГО КОНФИГА{C.RESET}")
    print(f"{C.BOLD}  Стратегий: {len(strategies)} | Таймаут TCP: {TCP_TIMEOUT}s{C.RESET}")
    mode_str = f"{C.GREEN}БЫСТРЫЙ (пропуск нерабочих){C.RESET}" if FAST_MODE else f"{C.YELLOW}ПОЛНЫЙ (все стратегии){C.RESET}"
    print(f"{C.BOLD}  Режим: {mode_str}{C.RESET}")
    print(f"{C.BOLD}{'═'*60}{C.RESET}\n")

    for idx, strat in enumerate(strategies):
        # ─── FAST MODE: пропуск заведомо нерабочих ───
        if FAST_MODE and should_skip_fast_mode(strat['name']):
            label = f"[{idx+1}/{len(strategies)}]"
            name_display = strat['name'][:40] + "..." if len(strat['name']) > 40 else strat['name']
            print(f"{label} {C.CYAN}{name_display}{C.RESET} | {C.DIM}SKIP (pattern){C.RESET}")
            results.append({
                "strat": strat, "tcp_ok": False, "speed": 0.0,
                "cmd": build_cmd(strat),
            })
            continue
        # ──────────────────────────────────────────────

        cmd = build_cmd(strat)

        label = f"[{idx+1}/{len(strategies)}]"
        name_display = strat['name'][:40] + "..." if len(strat['name']) > 40 else strat['name']
        print(f"{label} {C.CYAN}{name_display}{C.RESET} ", end="", flush=True)

        try:
            creationflags = 0x08000000 if sys.platform == 'win32' else 0
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
            )
        except FileNotFoundError:
            print(f"{C.RED}[X] winws.exe не найден!{C.RESET}")
            break
        except Exception as e:
            print(f"{C.RED}[X] Ошибка запуска: {e}{C.RESET}")
            continue

        time.sleep(INIT_WAIT)

        poll = proc.poll()
        if poll is not None:
            stderr_out = ""
            try:
                _, stderr_bytes = proc.communicate(timeout=2)
                stderr_out = stderr_bytes.decode('utf-8', errors='replace').strip()
            except:
                pass
            print(f"{C.RED}[X] Крэш (код {poll}){C.RESET}")
            if stderr_out:
                first_line = stderr_out.split('\n')[0][:120]
                print(f"     {C.DIM}→ {first_line}{C.RESET}")
            continue

        all_ok = True
        tcp_parts = []

        for host, port in TEST_TARGETS:
            attempt = test_https(host, port, TCP_TIMEOUT)
            
            if attempt.success:
                tcp_parts.append(f"{C.GREEN}{host}:{int(attempt.time_ms)}ms{C.RESET}")
            else:
                tcp_parts.append(f"{C.RED}{host}:FAIL{C.RESET}")
                all_ok = False

        print(f"| {' '.join(tcp_parts)} ", end="", flush=True)

        speed_val = 0.0
        if all_ok and speed_url:
            dl_attempt = test_download_speed(speed_url, timeout=DOWNLOAD_TIMEOUT, verbose=False)
            
            if dl_attempt.success:
                print(f"| {C.GREEN}{dl_attempt.speed_mbps:.2f} MB/s{C.RESET}")
                speed_val = dl_attempt.speed_mbps
            else:
                print(f"| {C.YELLOW}DL_ERR{C.RESET}")
        elif all_ok:
            print(f"| {C.YELLOW}NO_URL{C.RESET}")
        else:
            print(f"| {C.DIM}SKIP{C.RESET}")

        results.append({
            "strat": strat,
            "tcp_ok": all_ok,
            "speed": speed_val,
            "cmd": cmd,
        })

        try:
            proc.terminate()
        except:
            pass
        kill_winws()

    return results

# ══════════════════════════════════════════════════════════
#              ВЫВОД РЕЗУЛЬТАТОВ
# ══════════════════════════════════════════════════════════

def print_results(results):
    print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}  ИТОГОВАЯ СТАТИСТИКА{C.RESET}")
    print(f"{C.BOLD}{'═'*60}{C.RESET}\n")

    successful = [r for r in results if r['tcp_ok']]

    if not successful:
        print(f"{C.RED}[!] НИ ОДИН КОНФИГ НЕ ОТКРЫЛ ВСЕ 3 САЙТА!{C.RESET}")
        print(f"    Возможно, необходимы другие настройки или фильтры.{C.RESET}")
        return

    successful.sort(key=lambda x: x['speed'], reverse=True)

    print(f"{C.GREEN}[+] Рабочих конфигов: {len(successful)} из {len(results)}{C.RESET}\n")

    for i, r in enumerate(successful[:10], 1):
        s = r['strat']
        speed_color = C.GREEN if r['speed'] > 1 else C.YELLOW
        
        details = []
        details.append(f"Mode: {s['mode']}")
        if s.get('pos'): details.append(f"Pos: {s['pos']}")
        if s.get('fool'): details.append(f"Fool: {s['fool']}")
        if s.get('ttl'): details.append(f"TTL: {s['ttl']}")
        if s.get('autottl'): details.append(f"AutoTTL: {s['autottl']}")
        if s.get('wssize'): details.append(f"WSSIZE: {s['wssize']}")
        if s.get('seqovl'): details.append(f"SeqOvl: {s['seqovl']}")
        if s.get('fake_tls_mod'): details.append(f"FakeMod: {s['fake_tls_mod']}")
        details.append(f"Rep: {s['rep']}")
        
        detail_str = " | ".join(details)

        print(f"  {C.BOLD}#{i}{C.RESET} {C.CYAN}{s['name']}{C.RESET}")
        print(f"     {detail_str}")
        print(f"     Скорость: {speed_color}{r['speed']:.2f} MB/s{C.RESET}")

        cmd_str = format_bat_cmd(r['cmd'])
        print(f"     {C.DIM}Команда: {cmd_str}{C.RESET}")
        print()

    best = successful[0]
    print(f"{C.GREEN}{C.BOLD}  ★ ЛУЧШИЙ ВАРИАНТ: {best['strat']['name']} "
          f"({best['speed']:.2f} MB/s){C.RESET}")

    save_best(best)

def format_bat_cmd(cmd):
    """Форматировать команду для копирования в .bat"""
    parts = []
    for c in cmd:
        s = str(c)
        s = s.replace(str(BASE_DIR) + os.sep, "")
        s = s.replace(str(BASE_DIR), ".")
        parts.append(s)
    return ' '.join(parts)

def save_best(best):
    """Сохранить лучший конфиг в файл"""
    out_file = BASE_DIR / "best_config.bat"
    try:
        cmd_line = format_bat_cmd(best['cmd'])
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write("@echo off\n")
            f.write(f"REM Лучший конфиг найденный Smart Tuner v2.7\n")
            f.write(f"REM Стратегия: {best['strat']['name']}\n")
            f.write(f"REM Скорость: {best['speed']:.2f} MB/s\n")
            f.write(f"cd /d \"%~dp0\"\n")
            f.write(f"{cmd_line}\n")
            f.write("pause\n")
        print(f"\n{C.GREEN}[✓] Лучший конфиг сохранён в: {out_file}{C.RESET}")
    except Exception as e:
        print(f"{C.YELLOW}[!] Не удалось сохранить файл: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════
#                  ИНТЕРАКТИВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════

def ask_speed_url():
    print(f"{C.BOLD}Ссылка для теста скорости скачивания:{C.RESET}")
    print(f"  [1] Cloudflare 10MB (по умолчанию)")
    print(f"  [2] Ввести свою ссылку")
    print(f"  [3] Пропустить тест скорости")
    print()
    choice = input(f"Выбор [1/2/3] (Enter = 1): ").strip()

    if choice == "2":
        custom_url = input("Введите URL файла для скачивания: ").strip()
        if custom_url:
            return custom_url
        else:
            print(f"{C.YELLOW}Пустой URL, используем Cloudflare{C.RESET}")
            return DEFAULT_SPEED_URL
    elif choice == "3":
        return ""
    else:
        return DEFAULT_SPEED_URL


def ask_check_mode():
    """Спросить пользователя о режиме проверки."""
    print(f"\n{C.BOLD}Режим проверки стратегий:{C.RESET}")
    print(f"  [1] {C.GREEN}Быстрая проверка{C.RESET} — пропускать заведомо нерабочие параметры")
    print(f"  [2] {C.YELLOW}Полная проверка{C.RESET} — тестировать все 518+ стратегий")
    print()
    choice = input(f"Выбор [1/2] (Enter = 1): ").strip()
    return choice != "2"  # True = fast mode (по умолчанию)

# ══════════════════════════════════════════════════════════
#                  ГЛАВНЫЙ БЛОК
# ══════════════════════════════════════════════════════════

if __name__ == '__main__':
    banner()

    if not check_prerequisites():
        input("\nНажмите Enter для выхода...")
        sys.exit(1)

    speed_url = None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == '--url' and i < len(sys.argv) - 1:
            speed_url = sys.argv[i + 1]

    if speed_url is None:
        speed_url = ask_speed_url()

    # <-- ДОБАВИТЬ ЗДЕСЬ:
    FAST_MODE = ask_check_mode()

    if speed_url:
        print(f"\n{C.YELLOW}[i] URL для теста скорости: {speed_url}{C.RESET}")
    else:
        print(f"\n{C.YELLOW}[i] Тест скорости отключён{C.RESET}")

    print(f"{C.YELLOW}[i] Тестовые сайты: {', '.join(h for h,p in TEST_TARGETS)}{C.RESET}\n")

    # Базовая проверка интернета
    print(f"{C.YELLOW}[~] Проверка базового интернет-соединения...{C.RESET}")
    ok_count = 0
    for host, port in TEST_TARGETS:
        attempt = test_https(host, port, TCP_TIMEOUT)
        status = f"{C.GREEN}OK ({int(attempt.time_ms)}ms){C.RESET}" if attempt.success else f"{C.RED}FAIL{C.RESET}"
        print(f"    {host}:{port} → {status}")
        if attempt.success:
            ok_count += 1
    print()

    if ok_count == 0:
        print(f"{C.YELLOW}[!] Сайты недоступны напрямую. Будем искать обход через DPI.{C.RESET}")
    elif ok_count == len(TEST_TARGETS):
        print(f"{C.GREEN}[+] Сайты доступны напрямую. Ищем конфиг с лучшей скоростью.{C.RESET}")
    else:
        print(f"{C.YELLOW}[!] Частичная блокировка. Попытаемся найти рабочий конфиг.{C.RESET}")
    
    print()

    strategies = build_strategies()
    print(f"{C.CYAN}[i] Сгенерировано стратегий: {len(strategies)}{C.RESET}\n")

    final_results = run_test(strategies, speed_url)
    print_results(final_results)

    kill_winws()
    input("\nНажмите Enter для выхода...")