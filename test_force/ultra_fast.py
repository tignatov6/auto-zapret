"""
Ultra Fast Brute Force - Максимально быстрый перебор стратегий
С таблицей таймингов и расчётом оптимальных значений
"""

import asyncio
import time
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from autozapret.config import Config, get_config
from autozapret.storage import Storage
from autozapret.executor import Executor, INIT_WAIT

# Переопределяем INIT_WAIT
import autozapret.executor as executor_module
executor_module.INIT_WAIT = 0.1

# Monkey-patch stop_winws
async def fast_stop_winws(self):
    if self._winws_process is not None:
        try:
            self._winws_process.terminate()
            self._winws_process.wait(timeout=1)
        except:
            try:
                self._winws_process.kill()
            except:
                pass
        self._winws_process = None
    
    if sys.platform == 'win32':
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'winws.exe'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except:
            pass
    
    await asyncio.sleep(0.02)
    return True, "winws stopped"

Executor.stop_winws = fast_stop_winws

# Monkey-patch start_winws_with_strategy
async def fast_start_winws(self, strategy_params: str, domain=None, measure_startup: bool = False):
    async with self._process_lock:
        await self.stop_winws()
        await asyncio.sleep(0.02)
        
        cmd = self._build_winws_cmd(strategy_params, domain)
        start_time = time.time()
        
        try:
            creationflags = 0x08000000 if sys.platform == 'win32' else 0
            self._winws_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=creationflags)
        except FileNotFoundError:
            return False, "winws.exe not found", 0.0
        except Exception as e:
            return False, f"Failed to start: {e}", 0.0
        
        startup_time = time.time() - start_time
        await asyncio.sleep(0.1)
        
        if measure_startup:
            poll = self._winws_process.poll()
            if poll is not None:
                self._winws_process = None
                return False, f"winws crashed (code {poll})", startup_time
            if self._startup_time is None:
                self._startup_time = startup_time
        
        return True, "winws started", startup_time

Executor.start_winws_with_strategy = fast_start_winws

from autozapret.strategy_generator import StrategyGenerator

# ══════════════════════════════════════════════════════════
#                 ТАЙМИНГИ
# ══════════════════════════════════════════════════════════

TEST_DOMAINS = ["discord.com", "youtube.com", "speedtest.net"]

KNOWN_STRATEGIES = {
    "discord.com": [
        ("multidisorder_midsld_ts_R3", "--dpi-desync=multidisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=ts --dpi-desync-repeats=3"),
        ("hostfakesplit_pmidsld_TTL14_ts_R2", "--dpi-desync=hostfakesplit --dpi-desync-split-pos=midsld --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-ttl=14"),
        ("hostfakesplit_p1_TTL5_ts_R2", "--dpi-desync=hostfakesplit --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-ttl=5"),
        ("multidisorder_sniext+1_ts_R3", "--dpi-desync=multidisorder --dpi-desync-split-pos=sniext+1 --dpi-desync-fooling=ts --dpi-desync-repeats=3"),
        ("hostfakesplit_autottl-2_R2", "--dpi-desync=hostfakesplit --dpi-desync-split-pos=midsld --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-ttl=1 --dpi-desync-autottl=-2"),
    ],
    "youtube.com": [
        ("multidisorder_2_md5sig_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=2 --dpi-desync-fooling=md5sig --dpi-desync-repeats=1"),
        ("multidisorder_sniext+1_seqovl1_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=sniext+1 --dpi-desync-repeats=1 --dpi-desync-split-seqovl=1"),
        ("multidisorder_sniext+1_seqovl2_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=sniext+1 --dpi-desync-repeats=1 --dpi-desync-split-seqovl=2"),
        ("multidisorder_1,midsld_ts_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=ts --dpi-desync-repeats=1"),
        ("hostfakesplit_pmidsld_TTL10_md5sig_R2", "--dpi-desync=hostfakesplit --dpi-desync-split-pos=midsld --dpi-desync-fooling=md5sig --dpi-desync-repeats=2 --dpi-desync-ttl=10"),
    ],
    "speedtest.net": [
        ("hostfakesplit_p1_TTL8_ts_R2", "--dpi-desync=hostfakesplit --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-ttl=8"),
        ("multidisorder_host+1_md5sig_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=host+1 --dpi-desync-fooling=md5sig --dpi-desync-repeats=1"),
        ("multidisorder_sniext+1_ts_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=sniext+1 --dpi-desync-fooling=ts --dpi-desync-repeats=1"),
        ("multidisorder_2_seqovl1_R1", "--dpi-desync=multidisorder --dpi-desync-split-pos=2 --dpi-desync-repeats=1 --dpi-desync-split-seqovl=1"),
        ("fake_mod_rnd,rndsni,dupsid_R2", "--dpi-desync=fake --dpi-desync-fooling=ts --dpi-desync-repeats=2 --dpi-desync-fake-tls-mod=rnd,rndsni,dupsid"),
    ],
}

CONNECT_TIMEOUT = 0.2
TLS_TIMEOUT = 0.2
HTTP_TIMEOUT = 0.15
WINWS_INIT_WAIT = 0.1
WINWS_KILL_WAIT = 0.02
TEST_PAUSE = 0.02


@dataclass
class TestResult:
    success: bool
    response_time_ms: float = 0.0
    error: str = ""
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class UltraFastBruteForce:
    def __init__(self):
        self.config = get_config()
        self.storage = Storage(self.config.database_path)
        self.executor = Executor()
        self.generator = StrategyGenerator(has_fake_files=True)
        
        self.stats = {
            "tested": 0,
            "domains": {},
            "total_time": 0.0,
            "test_times": [],
            "timings": []
        }
    
    def _test_socket(self, domain: str) -> TestResult:
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            
            try:
                sock.connect((domain, 443))
            except socket.timeout:
                sock.close()
                return TestResult(success=False, error="conn_to")
            except ConnectionRefusedError:
                sock.close()
                return TestResult(success=False, error="refused")
            except OSError:
                sock.close()
                return TestResult(success=False, error="os")
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            try:
                sock.settimeout(TLS_TIMEOUT)
                ssock = ctx.wrap_socket(sock, server_hostname=domain)
            except ssl.SSLError as e:
                sock.close()
                err = str(e).lower()
                if 'reset' in err or 'timed out' in err:
                    return TestResult(success=False, error="tls_rst")
                return TestResult(success=False, error="tls")
            except socket.timeout:
                sock.close()
                return TestResult(success=False, error="tls_to")
            except ConnectionResetError:
                sock.close()
                return TestResult(success=False, error="rst")
            except OSError as e:
                sock.close()
                err = str(e).lower()
                if '10054' in err or 'reset' in err:
                    return TestResult(success=False, error="rst")
                return TestResult(success=False, error="os")
            
            try:
                ssock.settimeout(HTTP_TIMEOUT)
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode())
                data = ssock.recv(64)
                rtt = (time.time() - start) * 1000
                ssock.close()
                
                if data:
                    return TestResult(success=True, response_time_ms=rtt)
                else:
                    return TestResult(success=False, error="empty")
            except Exception:
                rtt = (time.time() - start) * 1000
                try:
                    ssock.close()
                except:
                    pass
                return TestResult(success=False, error="http")
                
        except Exception as e:
            return TestResult(success=False, error=str(e))
    
    async def test_strategy(self, domain: str, params: str) -> TestResult:
        loop = asyncio.get_event_loop()
        timings = {}
        
        t0 = time.time()
        await self.executor.stop_winws()
        
        success, msg, startup_time = await self.executor.start_winws_with_strategy(
            params, domain=domain, measure_startup=False)
        timings['start'] = time.time() - t0
        
        if not success:
            return TestResult(success=False, error=f"winws: {msg}")
        
        await asyncio.sleep(WINWS_INIT_WAIT)
        
        t0 = time.time()
        result = await loop.run_in_executor(None, lambda: self._test_socket(domain))
        timings['test'] = time.time() - t0
        
        t0 = time.time()
        await self.executor.stop_winws()
        timings['kill'] = time.time() - t0
        
        result.details['timings'] = timings
        result.details['domain'] = domain
        
        self.stats["timings"].append({
            "domain": domain,
            "start_ms": timings.get('start', 0) * 1000,
            "test_ms": timings.get('test', 0) * 1000,
            "kill_ms": timings.get('kill', 0) * 1000,
            "total_ms": sum(timings.values()) * 1000,
            "response_ms": result.response_time_ms,
            "success": result.success
        })
        
        return result
    
    async def test_known_strategies(self, domain: str, known: list) -> List[Dict]:
        print(f"\n📋 Проверка {len(known)} известных стратегий для {domain}...")
        print("=" * 70)
        
        working = []
        for idx, (name, params) in enumerate(known, 1):
            print(f"[{idx}/{len(known)}] {name[:50]:<50} ", end="", flush=True)
            
            result = await self.test_strategy(domain, params)
            test_time = sum(result.details.get('timings', {}).values())
            
            if result.success:
                print(f"✓ WORKS! ({result.response_time_ms:.0f}ms, {test_time:.2f}s)")
                working.append({
                    "name": name,
                    "params": params,
                    "response_time_ms": result.response_time_ms,
                    "test_time": test_time,
                    "from_known": True
                })
            else:
                t = result.details.get('timings', {})
                print(f"✗ ({result.error}, {test_time:.2f}s)")
        
        return working
    
    async def find_working(self, domain: str, known: list = None) -> Optional[Dict]:
        print(f"\n🔍 Поиск для {domain}...")
        print("=" * 70)
        print(f"Таймауты: conn={CONNECT_TIMEOUT}s, tls={TLS_TIMEOUT}s, http={HTTP_TIMEOUT}s")
        print(f"WinDivert init: {WINWS_INIT_WAIT}s (было 4.0s)")

        if known:
            working = await self.test_known_strategies(domain, known)
            if working:
                best = min(working, key=lambda x: x['response_time_ms'])
                print(f"\n✅ Лучшая известная стратегия: {best['name']} ({best['response_time_ms']:.0f}ms)")
                return best
            print(f"\nНи одна известная стратегия не сработала, начинаем полный перебор...")

        strategies = self.generator.generate_all()
        total = len(strategies)
        print(f"\nВсего стратегий: {total}")
        print("=" * 70)

        start = time.time()
        for idx, strat in enumerate(strategies, 1):
            name = strat.name
            params = strat.to_params()

            if idx % 10 == 0 or idx == 1:
                elapsed = time.time() - start
                rate = idx / elapsed if elapsed > 0 else 0
                print(f"[{idx:4d}/{total}] {name[:40]:<40} ", end="", flush=True)

            result = await self.test_strategy(domain, params)
            test_time = sum(result.details.get('timings', {}).values())
            self.stats["tested"] += 1
            self.stats["test_times"].append(test_time)

            if result.success:
                elapsed = time.time() - start
                avg = sum(self.stats["test_times"]) / len(self.stats["test_times"])
                print(f"✓ WORKS! ({result.response_time_ms:.0f}ms, {test_time:.2f}s)")
                t = result.details.get('timings', {})
                print(f"   Timings: start={t.get('start',0)*1000:.0f}ms, test={t.get('test',0)*1000:.0f}ms, kill={t.get('kill',0)*1000:.0f}ms")
                print(f"\n⏱ Найдено за {elapsed:.1f} сек")
                print(f"⚡ {idx} стратегий, {avg:.2f} сек/стр ({rate:.1f} стр/сек)")
                return {
                    "name": name, "params": params,
                    "response_time_ms": result.response_time_ms,
                    "test_time": test_time, "from_known": False
                }
            else:
                if idx % 10 == 0 or idx == 1:
                    t = result.details.get('timings', {})
                    print(f"✗ ({result.error}, {test_time:.2f}s [s={t.get('start',0)*1000:.0f}ms t={t.get('test',0)*1000:.0f}ms k={t.get('kill',0)*1000:.0f}ms])")

            await asyncio.sleep(TEST_PAUSE)

        elapsed = time.time() - start
        print(f"\n❌ Не найдено за {elapsed:.1f} сек")
        return None
    
    def print_timing_table(self) -> None:
        timings = self.stats.get("timings", [])
        if not timings:
            return
        
        print("\n" + "=" * 90)
        print("📊 ТАБЛИЦА ТАЙМИНГОВ ВСЕХ ТЕСТОВ:")
        print("=" * 90)
        print(f"{'#':>3} {'Домен':<20} {'Start':>8} {'Test':>8} {'Kill':>6} {'Total':>8} {'RTT':>8} {'Статус':>8}")
        print("-" * 90)
        
        for idx, t in enumerate(timings, 1):
            domain = t['domain'][:20]
            status = "✓" if t['success'] else "✗"
            print(f"{idx:>3} {domain:<20} {t['start_ms']:>6.0f}ms {t['test_ms']:>6.0f}ms {t['kill_ms']:>5.0f}ms {t['total_ms']:>6.0f}ms {t['response_ms']:>6.0f}ms {status:>8}")
        
        print("-" * 90)
        
        successful = [t for t in timings if t['success']]
        if successful:
            avg_start = sum(t['start_ms'] for t in successful) / len(successful)
            avg_test = sum(t['test_ms'] for t in successful) / len(successful)
            avg_kill = sum(t['kill_ms'] for t in successful) / len(successful)
            avg_total = sum(t['total_ms'] for t in successful) / len(successful)
            avg_rtt = sum(t['response_ms'] for t in successful) / len(successful)
            
            max_start = max(t['start_ms'] for t in successful)
            max_test = max(t['test_ms'] for t in successful)
            max_kill = max(t['kill_ms'] for t in successful)
            
            print(f"{'СРЕДНЕЕ':>23} {avg_start:>6.0f}ms {avg_test:>6.0f}ms {avg_kill:>5.0f}ms {avg_total:>6.0f}ms {avg_rtt:>6.0f}ms")
            print(f"{'МАКСИМУМ':>23} {max_start:>6.0f}ms {max_test:>6.0f}ms {max_kill:>5.0f}ms")
        
        print("=" * 90)
    
    def calculate_optimal_timings(self) -> Dict[str, float]:
        timings = self.stats.get("timings", [])
        successful = [t for t in timings if t['success']]
        
        if not successful:
            return {}
        
        max_start = max(t['start_ms'] for t in successful)
        max_test = max(t['test_ms'] for t in successful)
        max_kill = max(t['kill_ms'] for t in successful)
        
        return {
            "WINWS_INIT_WAIT": round((max_start - 50) * 1.33 / 1000, 2),
            "TOTAL_TEST_TIMEOUT": round(max_test * 1.33 / 1000, 2),
            "WINWS_KILL_WAIT": round(max_kill * 1.33 / 1000, 3),
            "CONNECT_TIMEOUT": round(max_test * 0.33 * 1.33 / 1000, 2),
            "TLS_TIMEOUT": round(max_test * 0.50 * 1.33 / 1000, 2),
            "HTTP_TIMEOUT": round(max_test * 0.17 * 1.33 / 1000, 2),
            "TEST_PAUSE": 0.02,
        }
    
    def print_optimal_timings(self) -> None:
        optimal = self.calculate_optimal_timings()
        if not optimal:
            return
        
        print("\n" + "=" * 90)
        print("⚙️  ОПТИМАЛЬНЫЕ ТАЙМИНГИ (максимум × 1.33):")
        print("=" * 90)
        print("Формула: max(измеренное) × 1.33 = оптимальное (запас 33%)")
        print("-" * 90)
        
        print(f"\n  WINWS_INIT_WAIT      = {optimal['WINWS_INIT_WAIT']:.2f}s  (инициализация WinDivert)")
        print(f"  TOTAL_TEST_TIMEOUT   = {optimal['TOTAL_TEST_TIMEOUT']:.2f}s  (общий таймаут)")
        print(f"  CONNECT_TIMEOUT      = {optimal['CONNECT_TIMEOUT']:.2f}s  (TCP подключение)")
        print(f"  TLS_TIMEOUT          = {optimal['TLS_TIMEOUT']:.2f}s  (TLS handshake)")
        print(f"  HTTP_TIMEOUT         = {optimal['HTTP_TIMEOUT']:.2f}s  (HTTP ответ)")
        print(f"  WINWS_KILL_WAIT      = {optimal['WINWS_KILL_WAIT']:.3f}s  (пауза после kill)")
        print(f"  TEST_PAUSE           = {optimal['TEST_PAUSE']:.2f}s  (между тестами)")
        
        print("\n" + "-" * 90)
        print("📋 Готовый код:")
        print("-" * 90)
        print(f"""
WINWS_INIT_WAIT      = {optimal['WINWS_INIT_WAIT']:.2f}
TOTAL_TEST_TIMEOUT   = {optimal['TOTAL_TEST_TIMEOUT']:.2f}
CONNECT_TIMEOUT      = {optimal['CONNECT_TIMEOUT']:.2f}
TLS_TIMEOUT          = {optimal['TLS_TIMEOUT']:.2f}
HTTP_TIMEOUT         = {optimal['HTTP_TIMEOUT']:.2f}
WINWS_KILL_WAIT      = {optimal['WINWS_KILL_WAIT']:.3f}
TEST_PAUSE           = {optimal['TEST_PAUSE']:.2f}
""")
        print("=" * 90)

    async def run(self, domains: list = None) -> None:
        if domains is None:
            domains = TEST_DOMAINS

        total_start = time.time()
        print("\n" + "=" * 70)
        print("🚀 ULTRA FAST BRUTE FORCE - Мульти-домен")
        print("=" * 70)
        print(f"Домены: {', '.join(domains)}")
        print(f"Время: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        all_results = {}
        for domain in domains:
            domain_start = time.time()
            known = KNOWN_STRATEGIES.get(domain)
            result = await self.find_working(domain, known)
            domain_time = time.time() - domain_start

            if result:
                all_results[domain] = result
                print(f"\n✅ {domain}: {result['name']} ({result['response_time_ms']:.0f}ms, {domain_time:.1f}s)")
            else:
                print(f"\n❌ {domain}: не найдено ({domain_time:.1f}s)")
            
            await asyncio.sleep(0.1)

        total_time = time.time() - total_start
        print("\n" + "=" * 70)
        print("📊 ОБЩИЕ ИТОГИ:")
        print("=" * 70)
        print(f"Всего доменов: {len(domains)}")
        print(f"Успешно: {len(all_results)}")
        print(f"Протестировано стратегий: {self.stats['tested']}")

        if self.stats["test_times"]:
            avg_test = sum(self.stats["test_times"]) / len(self.stats["test_times"])
            print(f"Среднее время теста: {avg_test:.2f} сек")

        print(f"Общее время: {total_time:.1f} сек")

        print("\n📝 Найденные стратегии:")
        for domain, result in all_results.items():
            source = "известная" if result.get('from_known') else "найденная"
            print(f"\n  {domain}:")
            print(f"    Стратегия: {result['name']} [{source}]")
            print(f"    Параметры: {result['params']}")
            print(f"    Время ответа: {result['response_time_ms']:.0f}ms")

        self.print_timing_table()
        self.print_optimal_timings()

        await self.executor.stop_winws()


async def main():
    brute = UltraFastBruteForce()
    await brute.run(TEST_DOMAINS)


if __name__ == "__main__":
    asyncio.run(main())
