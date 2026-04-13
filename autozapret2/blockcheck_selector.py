"""
Blockcheck Strategy Selector - Выбор стратегий в порядке blockcheck2.sh (Zapret2)

Отличие от Strategy Generator:
- Генератор создаёт ВСЕ стратегии сразу
- Selector генерирует стратегии ЛЕНЕВО в правильном порядке blockcheck2.sh
- Selector поддерживает ранний выход при успехе (как quick mode в blockcheck2)
- Selector адаптивно пропускает ненужные тесты

Порядок тестирования (как в blockcheck2.sh):

PHASE 10: HTTP basic (lua-desync http_hostcase, http_domcase, http_methodeol, http_unixeol)
PHASE 15: Misc (tcpseg с ip_id=rnd, repeats 1/20/100/260)
PHASE 17: OOB (oob:urp=...)
PHASE 20: Multi split (multisplit/multidisorder с позициями)
PHASE 23: SeqOvl (tcpseg с seqovl)
PHASE 24: Syndata (syndata с blob)
PHASE 25: Fake (fake с TTL/autottl/fooling)
PHASE 30: Fakedsplit (fakedsplit/fakeddisorder)
PHASE 35: Hostfakesplit (hostfakesplit variations)
PHASE 50: Fake+Multi (fake + multisplit/multidisorder)
PHASE 55: Fake+Faked (fake + fakedsplit/fakeddisorder)
PHASE 60: Fake+Hostfake (fake + hostfakesplit)
PHASE 90: QUIC (QUIC fake/repeats/ipfrag)

Zapret2 использует --lua-desync вместо --lua-desync:
  --lua-desync=fake:blob=fake_default_tls:ip4_ttl=3
  --lua-desync=multisplit:pos=method+2
  --lua-desync=wssize:wsize=1:scale=6
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Generator, List, Optional, Dict, Any, Callable
from pathlib import Path

from .utils.profiler import get_profiler
from .helpers import build_lua_desync_params
profiler = get_profiler("blockcheck_selector")

logger = logging.getLogger(__name__)


class ScanLevel(Enum):
    """Уровень сканирования как в blockcheck.sh"""
    QUICK = "quick"      # Быстрый - выход при первом успехе
    STANDARD = "standard"  # Стандартный - исследовать что работает
    FORCE = "force"       # Полный - проверить все стратегии


class ProtocolType(Enum):
    """Тип протокола"""
    HTTP = "http"    # HTTP (sec=0)
    TLS12 = "tls12"  # HTTPS TLS 1.2 (sec=1)
    TLS13 = "tls13"  # HTTPS TLS 1.3 (sec=2)
    QUIC = "quic"    # QUIC/HTTP3 (UDP)


@dataclass
class StrategyResult:
    """Результат тестирования стратегии"""
    params: str
    phase: int
    name: str
    description: str = ""
    should_skip: bool = False  # Адаптивный пропуск


@dataclass
class SelectorState:
    """Состояние selector для адаптивного тестирования"""
    # Флаги что уже найдено работающее (для adaptive skip)
    has_multisplit: bool = False
    has_multidisorder: bool = False
    has_fake: bool = False
    has_fakedsplit: bool = False
    has_fakeddisorder: bool = False
    has_hostfakesplit: bool = False
    has_wssize: bool = False
    
    # Найденная стратегия
    found_strategy: Optional[str] = None
    found_phase: int = 0


class BlockcheckStrategySelector:
    """
    Ленивый генератор стратегий в порядке blockcheck.sh
    
    Использование:
    
        selector = BlockcheckStrategySelector(protocol=ProtocolType.TLS12)
        state = SelectorState()
        
        for strategy in selector.generate(state):
            result = test_strategy(domain, strategy.params)
            if result.works:
                state.found_strategy = strategy.params
                break  # Ранний выход
            
            # Обновляем state для adaptive skip
            update_state(state, strategy)
    """
    
    # Константы из blockcheck.sh
    MIN_TTL = 1
    MAX_TTL = 12
    MIN_AUTOTTL_DELTA = 1
    MAX_AUTOTTL_DELTA = 5
    
    # Позиции split для TLS
    SPLITS_TLS = ["2", "1", "sniext+1", "sniext+4", "host+1", "midsld",
                  "1,midsld", "1,sniext+1,host+1,midsld-2,midsld,midsld+2", "endhost-1"]
    
    # Позиции split для HTTP
    SPLITS_HTTP = ["method+2", "midsld", "method+2,midsld"]
    
    # Fooling методы Zapret2 (расширенный набор)
    FOOLING_METHODS = [
        "tcp_md5", "badsum", "tcp_seq=-3000", "tcp_seq=1000000",
        "tcp_ts=-1000", "tcp_flags_unset=ACK", "tcp_flags_set=SYN"
    ]
    FOOLING_METHODS_LEGACY = ["ts", "md5sig", "badseq", "badsum", "datanoack"]  # для обратной совместимости
    FOOLING_IPV6 = [
        "ip6_hopbyhop", "ip6_hopbyhop:ip6_hopbyhop2", "ip6_destopt",
        "ip6_routing", "ip6_ah"
    ]
    
    # Режимы desync для Phase 3+
    FAKE_MODES = ["fake"]
    FAKE_SPLIT_MODES = ["fakedsplit", "fake,multisplit", "fake,fakedsplit",
                        "hostfakesplit", "fake,hostfakesplit"]
    FAKE_DISORDER_MODES = ["fakeddisorder", "fake,multidisorder", "fake,fakeddisorder"]
    
    @profiler
    def __init__(
        self,
        protocol: ProtocolType = ProtocolType.TLS12,
        scan_level: ScanLevel = ScanLevel.QUICK,
        ipv6: bool = False,
        zapret_base: Optional[str] = None
    ):
        """
        Инициализация selector
        
        Args:
            protocol: Тип протокола (HTTP, TLS12, TLS13, QUIC)
            scan_level: Уровень сканирования
            ipv6: Использовать IPv6 специфичные стратегии
            zapret_base: Путь к директории zapret (для fake файлов)
        """
        self.protocol = protocol
        self.scan_level = scan_level
        self.ipv6 = ipv6
        self.zapret_base = zapret_base
        
        # Определяем sec параметр (0=HTTP, 1=TLS12, 2=TLS13)
        self.sec = {
            ProtocolType.HTTP: 0,
            ProtocolType.TLS12: 1,
            ProtocolType.TLS13: 2,
            ProtocolType.QUIC: 2  # QUIC как TLS13
        }[protocol]
        
        # Выбираем позиции split
        self.splits = self.SPLITS_HTTP if self.sec == 0 else self.SPLITS_TLS

    @profiler
    def count_strategies(self) -> int:
        """
        Подсчет общего количества стратегий
        
        Возвращает:
            Реальное количество стратегий (генерируем и считаем)
        """
        # Генерируем все стратегии и считаем их (точно!)
        state = SelectorState()
        count = 0
        for _ in self.generate(state):
            count += 1
        return count

    @profiler
    def generate(
        self,
        state: Optional[SelectorState] = None
    ) -> Generator[StrategyResult, None, None]:
        """
        Генерация стратегий в порядке blockcheck2.sh

        Args:
            state: Состояние для adaptive skip (опционально)

        Yields:
            StrategyResult с параметрами стратегии
        """
        if state is None:
            state = SelectorState()

        # QUIC имеет свой порядок
        if self.protocol == ProtocolType.QUIC:
            yield from self._generate_quic_strategies(state)
            return

        # PHASE 10: HTTP basic (lua-desync http_hostcase, etc.)
        if self.sec == 0:
            yield from self._phase2_http_modifiers(state)

        # PHASE 15: Misc (tcpseg с ip_id=rnd)
        yield from self._phase15_misc(state)

        # PHASE 17: OOB
        yield from self._phase17_oob(state)

        # PHASE 16: SYN Hide
        yield from self._phase16_synhide(state)

        # PHASE 20: Multi split/multidisorder
        yield from self._phase3_basic_splits(state)

        # PHASE 23: SeqOvl
        yield from self._phase9_seqovl(state)

        # PHASE 24: Syndata
        yield from self._phase10_syndata(state)

        # PHASE 12: SYN-ACK
        yield from self._phase12_synack(state)

        # PHASE 13: TLS ClientHello Clone
        yield from self._phase13_tls_clone(state)

        # PHASE 14: RST
        yield from self._phase14_rst(state)

        # PHASE 25: Fake с TTL
        yield from self._phase3_fake_ttl(state)

        # PHASE 25: Fake с fooling
        yield from self._phase4_fake_fooling(state)

        # PHASE 25: Fake с AutoTTL
        yield from self._phase5_fake_autottl(state)

        # PHASE 30: Fakedsplit/fakeddisorder
        yield from self._phase30_fakedsplit(state)

        # PHASE 18: WireGuard Obfuscation
        yield from self._phase18_wgobfs(state)

        # PHASE 19: IP XOR
        yield from self._phase19_ippxor(state)

        # PHASE 20: UDP to ICMP tunneling
        yield from self._phase20_udp2icmp(state)

        # PHASE 21: Circular Orchestrator
        yield from self._phase21_circular(state)

        # PHASE 22: Condition Orchestrator
        yield from self._phase22_condition(state)

        # PHASE 23: StopIf Orchestrator
        yield from self._phase23_stopif(state)

        # PHASE 24: Repeater Orchestrator
        yield from self._phase24_repeater(state)

        # PHASE 35: Hostfakesplit
        yield from self._phase35_hostfakesplit(state)

        # PHASE 50: Fake + Multi
        yield from self._phase50_fake_multi(state)

        # PHASE 55: Fake + Faked
        yield from self._phase55_fake_faked(state)

        # PHASE 60: Fake + Hostfake
        yield from self._phase60_fake_hostfake(state)

        # PHASE 8: WSSIZE
        yield from self._phase8_wssize(state)

        # PHASE 11: IPv6 специфичные
        if self.ipv6:
            yield from self._phase11_ipv6(state)

        # PHASE 25: IPv6 Extension Header Fooling
        yield from self._phase25_ipv6_fooling(state)

        # PHASE 26: UDP Length Modification
        yield from self._phase26_udplen(state)

        # PHASE 27: IP Fragment Disorder
        yield from self._phase27_ipfrag_disorder(state)
    
    # ══════════════════════════════════════════════════════════
    #                 PHASE GENERATORS
    # ══════════════════════════════════════════════════════════

    @profiler
    def _phase1_wssize_quick(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 1: WSSIZE quick test (как в blockcheck.sh строка 1220)
        
        КРИТИЧНО: Тестируется ПЕРЕД всеми остальными стратегиями.
        Если сработает — выходим сразу (экономия 100+ тестов).
        """
        if state.has_wssize:
            return

        # Тестируем только базовый вариант (как в blockcheck.sh)
        for mode in ["multisplit", "multidisorder"]:
            for pos in ["1", "2"]:
                yield StrategyResult(
                    params=f"--lua-desync={mode} --lua-desync-split-pos={pos} --wssize=1:6",
                    phase=1,
                    name=f"{mode}_{pos}_wssize1_6",
                    description=f"Quick WSSIZE test: {mode} at {pos} with wssize 1:6"
                )

    @profiler
    def _phase2_http_modifiers(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 10: HTTP basic (blockcheck2 10-http-basic.sh)"""
        for mode in ['http_hostcase', 'http_domcase', 'http_methodeol', 'http_unixeol']:
            lua_params = build_lua_desync_params(mode)
            yield StrategyResult(
                params=f"--lua-desync={lua_params} --payload=http_req",
                phase=10,
                name=f"http_basic_{mode}",
                description=f"HTTP basic: {mode}"
            )
        # Also add http_hostcase with spell=hoSt variant
        lua_params = build_lua_desync_params("http_hostcase", spell="hoSt")
        yield StrategyResult(
            params=f"--lua-desync={lua_params} --payload=http_req",
            phase=10,
            name="http_basic_hostcase_spell",
            description="HTTP basic: http_hostcase with spell=hoSt"
        )

    @profiler
    def _phase3_basic_splits(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 2: Multisplit/Multidisorder с позициями"""
        for mode in ["multisplit", "multidisorder"]:
            for pos in self.splits:
                lua_params = build_lua_desync_params(mode, pos=pos)
                payload = "--payload=tls_client_hello" if self.sec != 0 else "--payload=http_req"
                yield StrategyResult(
                    params=f"--lua-desync={lua_params} {payload}",
                    phase=2,
                    name=f"{mode}_{pos.replace(',', '_')}",
                    description=f"Basic {mode} at {pos}"
                )
    
    @profiler
    def _phase3_fake_ttl(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 3: Fake режимы с TTL"""
        modes = ["fake"]
        
        if not state.has_multisplit:
            modes.extend(["fakedsplit", "fake,multisplit", "fake,fakedsplit"])
        if not state.has_multidisorder:
            modes.extend(["fakeddisorder", "fake,multidisorder", "fake,fakeddisorder"])
        
        for mode in modes:
            if mode == "fake" and state.has_fake:
                continue
            if "fakedsplit" in mode and state.has_fakedsplit:
                continue
            if "fakeddisorder" in mode and state.has_fakeddisorder:
                continue
            if "hostfakesplit" in mode and state.has_hostfakesplit:
                continue
            
            for ttl in range(self.MIN_TTL, self.MAX_TTL + 1):
                # Для простых fake режимов
                if mode == "fake":
                    lua_params = build_lua_desync_params("fake", blob="fake_default_tls", ip4_ttl=str(ttl))
                    yield StrategyResult(
                        params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                        phase=3,
                        name=f"{mode}_ttl{ttl}",
                        description=f"{mode} with TTL {ttl}"
                    )
                else:
                    # Для split/disorder режимов
                    for pos in ["1", "midsld"]:
                        lua_params = build_lua_desync_params(mode.replace("fake,", ""), blob="fake_default_tls", pos=pos, ip4_ttl=str(ttl))
                        yield StrategyResult(
                            params=f"--lua-desync=fake:blob=fake_default_tls:ip4_ttl={ttl} --lua-desync={lua_params} --payload=tls_client_hello",
                            phase=3,
                            name=f"{mode}_{pos}_ttl{ttl}",
                            description=f"{mode} at {pos} with TTL {ttl}"
                        )
    
    @profiler
    def _phase4_fake_fooling(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 4: Fake с fooling методами"""
        modes = ["fake"]
        
        if not state.has_multisplit:
            modes.extend(["fakedsplit", "fake,multisplit"])
        if not state.has_multidisorder:
            modes.extend(["fakeddisorder", "fake,multidisorder"])
        
        for mode in modes:
            for fooling in self.FOOLING_METHODS:
                params = f"--lua-desync={mode} --lua-desync-fooling={fooling}"
                
                # Добавляем позицию для split режимов
                if "split" in mode or "disorder" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=4,
                            name=f"{mode}_{pos}_{fooling}",
                            description=f"{mode} at {pos} with {fooling}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=4,
                        name=f"{mode}_{fooling}",
                        description=f"{mode} with {fooling}"
                    )
                
                # badseq с increment=0
                if fooling == "badseq":
                    yield StrategyResult(
                        params=f"{params} --lua-desync-badseq-increment=0",
                        phase=4,
                        name=f"{mode}_{fooling}_inc0",
                        description=f"{mode} with {fooling} (increment=0)"
                    )
                
                # md5sig с dup
                if fooling == "md5sig":
                    yield StrategyResult(
                        params=f"{params} --dup=1 --dup-cutoff=n2 --dup-fooling=md5sig",
                        phase=4,
                        name=f"{mode}_{fooling}_dup",
                        description=f"{mode} with {fooling} + dup"
                    )
    
    @profiler
    def _phase5_fake_autottl(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 5: Fake с AutoTTL"""
        modes = ["fake"]
        
        if not state.has_multisplit:
            modes.extend(["fakedsplit", "fake,multisplit"])
        if not state.has_multidisorder:
            modes.extend(["fakeddisorder", "fake,multidisorder"])
        
        for mode in modes:
            for delta in range(self.MIN_AUTOTTL_DELTA, self.MAX_AUTOTTL_DELTA + 1):
                # С orig-ttl
                params = f"--lua-desync={mode} --lua-desync-ttl=1 --lua-desync-autottl=-{delta} --orig-ttl=1 --orig-mod-start=s1 --orig-mod-cutoff=d1"
                
                # Добавляем позицию для split режимов
                if "split" in mode or "disorder" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=5,
                            name=f"{mode}_{pos}_autottl{delta}",
                            description=f"{mode} at {pos} with AutoTTL -{delta}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=5,
                        name=f"{mode}_autottl{delta}",
                        description=f"{mode} with AutoTTL -{delta}"
                    )
    
    @profiler
    def _phase6_orig_params(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 7: Orig параметры"""
        modes = ["fake", "fake,multisplit"]
        
        for mode in modes:
            # orig-ttl без модификаторов
            for orig_ttl in [1, 2, 3]:
                params = f"--lua-desync={mode} --orig-ttl={orig_ttl}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=7,
                            name=f"{mode}_{pos}_orig_ttl{orig_ttl}",
                            description=f"{mode} at {pos} with orig-ttl={orig_ttl}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=7,
                        name=f"{mode}_orig_ttl{orig_ttl}",
                        description=f"{mode} with orig-ttl={orig_ttl}"
                    )
            
            # orig-autottl
            for orig_delta in [1, 2, 3]:
                params = f"--lua-desync={mode} --orig-ttl=1 --orig-mod-start=s1 --orig-mod-cutoff=d1 --orig-autottl=+{orig_delta}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=7,
                            name=f"{mode}_{pos}_orig_autottl{orig_delta}",
                            description=f"{mode} at {pos} with orig-autottl +{orig_delta}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=7,
                        name=f"{mode}_orig_autottl{orig_delta}",
                        description=f"{mode} with orig-autottl +{orig_delta}"
                    )
    
    @profiler
    def _phase7_dup_params(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 8: Dup параметры"""
        modes = ["fake", "fake,multisplit"]
        
        for mode in modes:
            # dup с разными fooling
            for dup_fooling in ["md5sig", "badsum", "ts"]:
                params = f"--lua-desync={mode} --dup=1 --dup-cutoff=n2 --dup-fooling={dup_fooling}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=8,
                            name=f"{mode}_{pos}_dup_{dup_fooling}",
                            description=f"{mode} at {pos} with dup {dup_fooling}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=8,
                        name=f"{mode}_dup_{dup_fooling}",
                        description=f"{mode} with dup {dup_fooling}"
                    )
            
            # dup-ttl
            for dup_ttl in range(1, 6):
                params = f"--lua-desync={mode} --dup=1 --dup-cutoff=n2 --dup-fooling=md5sig --dup-ttl={dup_ttl}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --lua-desync-split-pos={pos}",
                            phase=8,
                            name=f"{mode}_{pos}_dup_ttl{dup_ttl}",
                            description=f"{mode} at {pos} with dup-ttl {dup_ttl}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=8,
                        name=f"{mode}_dup_ttl{dup_ttl}",
                        description=f"{mode} with dup-ttl {dup_ttl}"
                    )
    
    @profiler
    def _phase8_wssize(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 6: WSSIZE (только для TLS12, после autottl как в blockcheck.sh)"""
        if self.sec != 1:  # Только TLS12
            return
        
        if state.has_wssize:
            return
        
        for mode in ["multisplit", "multidisorder"]:
            for pos in ["1", "2", "sniext+1"]:
                for wssize in ["1:6", "64:6"]:
                    yield StrategyResult(
                        params=f"--lua-desync={mode} --lua-desync-split-pos={pos} --wssize={wssize}",
                        phase=6,
                        name=f"{mode}_{pos}_wssize{wssize.replace(':', '_')}",
                        description=f"{mode} at {pos} with wssize {wssize}"
                    )
    
    @profiler
    def _phase9_seqovl(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 9: SeqOvl (расширенный, как в blockcheck.sh строка 1305-1315)
        """
        # Позиции для HTTP и TLS
        if self.sec == 0:  # HTTP
            seqovl_positions = ["method+2", "method+2,midsld"]
        else:  # TLS
            seqovl_positions = ["10", "10,sniext+1", "10,midsld", "2"]

        # Базовые seqovl тесты
        for mode in ["multisplit", "multidisorder"]:
            for pos in seqovl_positions:
                for seqovl in [1, 2]:
                    lua_params = build_lua_desync_params(mode, pos=pos, seqovl=str(seqovl))
                    yield StrategyResult(
                        params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                        phase=9,
                        name=f"{mode}_{pos}_seqovl{seqovl}",
                        description=f"{mode} at {pos} with seqovl {seqovl}"
                    )
    
    @profiler
    def _phase10_syndata(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 10: Syndata"""
        # Только syndata
        yield StrategyResult(
            params="--lua-desync=syndata",
            phase=10,
            name="syndata",
            description="syndata mode"
        )

        # syndata с split
        for split_mode in ["multisplit", "multidisorder"]:
            for pos in ["1", "2", "sniext+1", "midsld"]:
                lua_params = build_lua_desync_params(split_mode, pos=pos)
                yield StrategyResult(
                    params=f"--lua-desync=syndata --lua-desync={lua_params} --payload=tls_client_hello",
                    phase=10,
                    name=f"syndata_{split_mode}_{pos}",
                    description=f"syndata + {split_mode} at {pos}"
                )

    @profiler
    def _phase12_synack(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 12: SYN-ACK strategies (zapret-antidpi.lua)
        - synack: Send SYN,ACK in response to SYN (NAT punch)
        - synack_split: Split SYN,ACK into separate SYN + ACK packets
        """
        # synack basic
        yield StrategyResult(
            params="--lua-desync=synack --payload=tls_client_hello",
            phase=12,
            name="synack_basic",
            description="Send SYN,ACK in response to SYN"
        )

        # synack_split variants
        for mode in ["syn", "synack", "acksyn"]:
            lua_params = build_lua_desync_params("synack_split", mode=mode)
            yield StrategyResult(
                params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                phase=12,
                name=f"synack_split_{mode}",
                description=f"SYN-ACK split mode={mode}"
            )

    @profiler
    def _phase13_tls_clone(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 13: TLS ClientHello Clone (zapret-antidpi.lua)
        Clone TLS ClientHello with SNI manipulation
        """
        # Clone with SNI add
        for sni_action in ["add", "del", "mod"]:
            lua_params = build_lua_desync_params("tls_client_hello_clone", sni_action=sni_action, sni="example.com")
            yield StrategyResult(
                params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                phase=13,
                name=f"tls_clone_sni_{sni_action}",
                description=f"TLS ClientHello clone with SNI {sni_action}"
            )

        # Clone with different blob files
        blob_files = ["tls_clienthello_iana_org.bin", "tls_clienthello_google_com_tlsrec.bin"]
        for blob in blob_files:
            blob_name = blob.replace(".bin", "")
            lua_params = build_lua_desync_params("tls_client_hello_clone", blob=blob_name)
            yield StrategyResult(
                params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                phase=13,
                name=f"tls_clone_blob_{blob_name[:20]}",
                description=f"TLS ClientHello clone with blob {blob}"
            )

    @profiler
    def _phase14_rst(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 14: RST strategies (zapret-antidpi.lua)
        Send RST or RST,ACK to reset connections
        """
        # Basic RST
        yield StrategyResult(
            params="--lua-desync=rst --payload=tls_client_hello",
            phase=14,
            name="rst_basic",
            description="Send RST to reset connection"
        )

        # RST,ACK
        yield StrategyResult(
            params="--lua-desync=rst:ack=1 --payload=tls_client_hello",
            phase=14,
            name="rst_ack",
            description="Send RST,ACK to reset connection"
        )

    @profiler
    def _phase11_ipv6(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 11: IPv6 специфичные стратегии (как в blockcheck.sh строка 1289-1298)
        
        Включает все комбинации из blockcheck.sh:
        - hopbyhop, hopbyhop,multisplit, hopbyhop,multidisorder
        - destopt, destopt,multisplit, destopt,multidisorder
        - ipfrag1, ipfrag1,multisplit, ipfrag1,multidisorder
        - ipfrag2 (для QUIC)
        """
        # Базовые IPv6 режимы
        base_modes = ["hopbyhop", "destopt"]
        
        # Комбинации со split/disorder
        for mode in base_modes:
            # Одиночный режим
            yield StrategyResult(
                params=f"--lua-desync={mode}",
                phase=11,
                name=f"ipv6_{mode}",
                description=f"IPv6 {mode}"
            )
            
            # С multisplit
            yield StrategyResult(
                params=f"--lua-desync={mode},multisplit",
                phase=11,
                name=f"ipv6_{mode}_multisplit",
                description=f"IPv6 {mode} + multisplit"
            )
            
            # С multidisorder
            yield StrategyResult(
                params=f"--lua-desync={mode},multidisorder",
                phase=11,
                name=f"ipv6_{mode}_multidisorder",
                description=f"IPv6 {mode} + multidisorder"
            )
        
        # ipfrag1 с комбинациями (как в blockcheck.sh)
        ipfrag_modes = ["ipfrag1"]
        for mode in ipfrag_modes:
            # Одиночный режим
            yield StrategyResult(
                params=f"--lua-desync={mode}",
                phase=11,
                name=f"ipv6_{mode}",
                description=f"IPv6 {mode}"
            )
            
            # С multisplit
            yield StrategyResult(
                params=f"--lua-desync={mode},multisplit",
                phase=11,
                name=f"ipv6_{mode}_multisplit",
                description=f"IPv6 {mode} + multisplit"
            )
            
            # С multidisorder
            yield StrategyResult(
                params=f"--lua-desync={mode},multidisorder",
                phase=11,
                name=f"ipv6_{mode}_multidisorder",
                description=f"IPv6 {mode} + multidisorder"
            )
        
        # ipfrag2 (для QUIC)
        yield StrategyResult(
            params="--lua-desync=send:ip6_hopbyhop:ip6_destopt",
            phase=11,
            name="ipv6_ipfrag2",
            description="IPv6 ipfrag2 (для QUIC)"
        )

    # ══════════════════════════════════════════════════════════
    #         НОВЫЕ ФАЗЫ BLOCKCHECK2
    # ══════════════════════════════════════════════════════════

    @profiler
    def _phase15_misc(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 15: Misc (blockcheck2 15-misc.sh)
        tcpseg с ip_id=rnd и repeats 1, 20, 100, 260
        """
        for repeats in [1, 20, 100, 260]:
            lua_desync = build_lua_desync_params("tcpseg", pos="0,method+2", ip_id="rnd", repeats=str(repeats))
            yield StrategyResult(
                params=f"--lua-desync={lua_desync} --payload=tls_client_hello",
                phase=15,
                name=f"misc_tcpseg_R{repeats}",
                description=f"tcpseg ip_id=rnd repeats={repeats}"
            )

    @profiler
    def _phase16_synhide(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 16: SYN Hide (zapret-obfs.lua)
        Hide TCP handshake from DPI using 4 magic modes
        """
        for mode in ["x2", "urp", "opt", "tsecr"]:
            lua_params = build_lua_desync_params("synhide", mode=mode)
            yield StrategyResult(
                params=f"--lua-desync={lua_params} --payload=tls_client_hello",
                phase=16,
                name=f"synhide_{mode}",
                description=f"SYN hide mode={mode}"
            )

    @profiler
    def _phase17_oob(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 17: OOB (blockcheck2 17-oob.sh)
        Out-of-band byte injection с varying URP values
        """
        urp_values = ["midsld", "host", "method+2", "1", "2"]
        for urp in urp_values:
            lua_desync = build_lua_desync_params("oob", urp=urp)
            yield StrategyResult(
                params=f"--lua-desync={lua_desync} --payload=tls_client_hello --in-range=-s1",
                phase=17,
                name=f"oob_urp_{urp}",
                description=f"OOB urp={urp}"
            )

    @profiler
    def _phase30_fakedsplit(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 30: Fakedsplit/fakeddisorder (blockcheck2 30-faked.sh)
        """
        for mode in ["fakedsplit", "fakeddisorder"]:
            for pos in self.SPLITS_TLS:
                lua_params = {"blob": "fake_default_tls", "pos": pos}
                lua_desync = build_lua_desync_params(mode, **lua_params)
                yield StrategyResult(
                    params=f"--lua-desync={lua_desync} --payload=tls_client_hello",
                    phase=30,
                    name=f"faked_{mode}_{pos}",
                    description=f"{mode} pos={pos}"
                )

    @profiler
    def _phase18_wgobfs(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 18: WireGuard Obfuscation (zapret-obfs.lua)
        AES-GCM encrypted padding for WireGuard traffic
        """
        # Basic wgobfs
        yield StrategyResult(
            params="--lua-desync=wgobfs",
            phase=18,
            name="wgobfs_basic",
            description="WireGuard obfuscation basic"
        )

        # wgobfs with different key sizes
        for key_size in [16, 32]:
            lua_params = build_lua_desync_params("wgobfs", key_size=str(key_size))
            yield StrategyResult(
                params=f"--lua-desync={lua_params}",
                phase=18,
                name=f"wgobfs_key{key_size}",
                description=f"WireGuard obfuscation key_size={key_size}"
            )

    @profiler
    def _phase19_ippxor(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 19: IP XOR (zapret-obfs.lua)
        XOR IP protocol number + optional payload XOR
        """
        # Basic ippxor
        yield StrategyResult(
            params="--lua-desync=ippxor",
            phase=19,
            name="ippxor_basic",
            description="XOR IP protocol number"
        )

        # ippxor with payload
        lua_params = build_lua_desync_params("ippxor", payload_xor="1")
        yield StrategyResult(
            params=f"--lua-desync={lua_params}",
            phase=19,
            name="ippxor_payload",
            description="XOR IP protocol + payload"
        )

    @profiler
    def _phase20_udp2icmp(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 20: UDP to ICMP tunneling (zapret-obfs.lua)
        Pack UDP datagram into ICMP echo message
        """
        yield StrategyResult(
            params="--lua-desync=udp2icmp",
            phase=20,
            name="udp2icmp_basic",
            description="UDP to ICMP tunneling"
        )

        # udp2icmp with type/code
        for icmp_type in ["0", "8"]:
            lua_params = build_lua_desync_params("udp2icmp", type=icmp_type)
            yield StrategyResult(
                params=f"--lua-desync={lua_params}",
                phase=20,
                name=f"udp2icmp_type{icmp_type}",
                description=f"UDP to ICMP tunneling type={icmp_type}"
            )

    @profiler
    def _phase21_circular(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 21: Circular Orchestrator (zapret-auto.lua)
        Automatic strategy rotation on failure detection
        """
        # circular with 3 strategies
        strategies = [
            "fake:blob=fake_default_tls:ip4_ttl=3",
            "multisplit:pos=1",
            "fakedsplit:pos=1"
        ]
        circular_params = build_lua_desync_params("circular",
            strategies=",".join(strategies),
            rotate_on_fail="1"
        )
        yield StrategyResult(
            params=f"--lua-desync={circular_params} --payload=tls_client_hello",
            phase=21,
            name="circular_3strategies",
            description="Circular rotation between fake, multisplit, fakedsplit"
        )

        # circular with fail detection
        circular_params2 = build_lua_desync_params("circular",
            strategies="multisplit:pos=1,multidisorder:pos=1,fakedsplit:pos=1",
            rotate_on_fail="1",
            max_rotations="5"
        )
        yield StrategyResult(
            params=f"--lua-desync={circular_params2} --payload=tls_client_hello",
            phase=21,
            name="circular_max5",
            description="Circular with max 5 rotations"
        )

    @profiler
    def _phase22_condition(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 22: Condition Orchestrator (zapret-auto.lua)
        Conditional execution based on iff functions
        """
        # condition with payload check
        cond_params = build_lua_desync_params("condition",
            condition="cond_payload_str:pattern=blocked",
            then_action="multisplit:pos=1",
            else_action="fake:blob=fake_default_tls:ip4_ttl=3"
        )
        yield StrategyResult(
            params=f"--lua-desync={cond_params} --payload=tls_client_hello",
            phase=22,
            name="condition_payload",
            description="Conditional: if blocked then multisplit else fake"
        )

        # condition with TCP timestamp check
        cond_params2 = build_lua_desync_params("condition",
            condition="cond_tcp_has_ts",
            then_action="fake:blob=fake_default_tls:tcp_ts=-1000",
            else_action="multisplit:pos=1"
        )
        yield StrategyResult(
            params=f"--lua-desync={cond_params2} --payload=tls_client_hello",
            phase=22,
            name="condition_tcp_ts",
            description="Conditional: if TCP TS then fake with ts fooling else multisplit"
        )

    @profiler
    def _phase23_stopif(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 23: StopIf Orchestrator (zapret-auto.lua)
        Conditional execution plan termination
        """
        # stopif on failure
        stopif_params = build_lua_desync_params("stopif",
            condition="cond_true",
            action="fake:blob=fake_default_tls:ip4_ttl=3"
        )
        yield StrategyResult(
            params=f"--lua-desync={stopif_params} --payload=tls_client_hello",
            phase=23,
            name="stopif_basic",
            description="Stop execution if condition met"
        )

    @profiler
    def _phase24_repeater(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 24: Repeater Orchestrator (zapret-auto.lua)
        Repeat instance execution N times with optional condition
        """
        # repeater basic
        repeat_params = build_lua_desync_params("repeater",
            count="3",
            action="multisplit:pos=1"
        )
        yield StrategyResult(
            params=f"--lua-desync={repeat_params} --payload=tls_client_hello",
            phase=24,
            name="repeater_3x",
            description="Repeat multisplit 3 times"
        )

        # repeater with condition
        repeat_params2 = build_lua_desync_params("repeater",
            count="5",
            action="fake:blob=fake_default_tls:ip4_ttl=3",
            condition="cond_random:prob=50"
        )
        yield StrategyResult(
            params=f"--lua-desync={repeat_params2} --payload=tls_client_hello",
            phase=24,
            name="repeater_5x_random",
            description="Repeat fake 5 times with 50% probability"
        )

    @profiler
    def _phase35_hostfakesplit(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 35: Hostfakesplit (blockcheck2 35-hostfake.sh)
        """
        for pos in ["midsld", "host", "sniext"]:
            lua_params = {"blob": "fake_default_tls", "host": "example.com", "pos": pos}
            lua_desync = build_lua_desync_params("hostfakesplit", **lua_params)
            yield StrategyResult(
                params=f"--lua-desync={lua_desync} --payload=tls_client_hello",
                phase=35,
                name=f"hostfake_{pos}",
                description=f"hostfakesplit pos={pos}"
            )

    @profiler
    def _phase50_fake_multi(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 50: Fake + Multi (blockcheck2 50-fake-multi.sh)
        fake + multisplit/multidisorder combinations
        """
        for split_mode in ["multisplit", "multidisorder"]:
            for pos in self.SPLITS_TLS[:2]:  # Ограничиваем для экономии
                lua_desync = build_lua_desync_params("fake", blob="fake_default_tls")
                lua_desync2 = build_lua_desync_params(split_mode, pos=pos)
                yield StrategyResult(
                    params=f"--lua-desync={lua_desync} --lua-desync={lua_desync2} --payload=tls_client_hello",
                    phase=50,
                    name=f"fake_multi_{split_mode}_{pos}",
                    description=f"fake + {split_mode} pos={pos}"
                )

    @profiler
    def _phase55_fake_faked(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 55: Fake + Faked (blockcheck2 55-fake-faked.sh)
        fake + fakedsplit/fakeddisorder combinations
        """
        for faked_mode in ["fakedsplit", "fakeddisorder"]:
            for pos in self.SPLITS_TLS[:2]:
                lua_desync = build_lua_desync_params("fake", blob="fake_default_tls")
                lua_desync2 = build_lua_desync_params(faked_mode, blob="fake_default_tls", pos=pos)
                yield StrategyResult(
                    params=f"--lua-desync={lua_desync} --lua-desync={lua_desync2} --payload=tls_client_hello",
                    phase=55,
                    name=f"fake_faked_{faked_mode}_{pos}",
                    description=f"fake + {faked_mode} pos={pos}"
                )

    @profiler
    def _phase60_fake_hostfake(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 60: Fake + Hostfake (blockcheck2 60-fake-hostfake.sh)
        fake + hostfakesplit combinations
        """
        for pos in ["midsld", "host"]:
            lua_desync = build_lua_desync_params("fake", blob="fake_default_tls")
            lua_desync2 = build_lua_desync_params("hostfakesplit", blob="fake_default_tls", host="example.com", pos=pos)
            yield StrategyResult(
                params=f"--lua-desync={lua_desync} --lua-desync={lua_desync2} --payload=tls_client_hello",
                phase=60,
                name=f"fake_hostfake_{pos}",
                description=f"fake + hostfakesplit pos={pos}"
            )

    @profiler
    def _phase25_ipv6_fooling(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 25: IPv6 Extension Header Fooling
        ip6_routing, ip6_ah headers for DPI bypass
        """
        # ip6_routing
        yield StrategyResult(
            params="--lua-desync=send:ip6_routing --payload=tls_client_hello",
            phase=25,
            name="ipv6_routing",
            description="IPv6 routing extension header"
        )

        # ip6_ah
        yield StrategyResult(
            params="--lua-desync=send:ip6_ah --payload=tls_client_hello",
            phase=25,
            name="ipv6_ah",
            description="IPv6 authentication header"
        )

        # Combined with multisplit
        yield StrategyResult(
            params="--lua-desync=send:ip6_routing --lua-desync=multisplit:pos=1 --payload=tls_client_hello",
            phase=25,
            name="ipv6_routing_multi",
            description="IPv6 routing + multisplit"
        )

    @profiler
    def _phase26_udplen(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 26: UDP Length Modification (zapret-antidpi.lua)
        Grow/shrink UDP payload length
        """
        # udplen grow with pattern
        for length in ["100", "200", "500"]:
            lua_params = build_lua_desync_params("udplen", length=length, pattern="random")
            yield StrategyResult(
                params=f"--lua-desync={lua_params}",
                phase=26,
                name=f"udplen_grow_{length}",
                description=f"UDP length grow to {length}"
            )

        # udplen shrink
        lua_params = build_lua_desync_params("udplen", action="shrink")
        yield StrategyResult(
            params=f"--lua-desync={lua_params}",
            phase=26,
            name="udplen_shrink",
            description="UDP length shrink"
        )

    @profiler
    def _phase27_ipfrag_disorder(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 27: IP Fragment Disorder
        Send fragments from last to first
        """
        # ipfrag_disorder basic
        yield StrategyResult(
            params="--lua-desync=ipfrag_disorder --payload=tls_client_hello",
            phase=27,
            name="ipfrag_disorder_basic",
            description="IP fragment disorder"
        )

        # ipfrag_disorder with custom next protocol
        lua_params = build_lua_desync_params("ipfrag_disorder", next_proto="17")
        yield StrategyResult(
            params=f"--lua-desync={lua_params} --payload=tls_client_hello",
            phase=27,
            name="ipfrag_disorder_next17",
            description="IP fragment disorder with next_proto=17"
        )

    @profiler
    def _generate_quic_strategies(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """Генерация стратегий для QUIC/UDP"""
        # Fake с repeats
        for rep in [1, 2, 4, 5, 6, 8, 10, 15, 20]:
            yield StrategyResult(
                params=f"--lua-desync=fake --lua-desync-repeats={rep}",
                phase=1,
                name=f"quic_fake_R{rep}",
                description=f"QUIC fake with {rep} repeats"
            )
        
        # Fake с TTL
        for ttl in range(1, 7):
            yield StrategyResult(
                params=f"--lua-desync=fake --lua-desync-repeats=4 --lua-desync-ttl={ttl}",
                phase=2,
                name=f"quic_fake_ttl{ttl}",
                description=f"QUIC fake with TTL {ttl}"
            )
        
        # Fake с fooling
        for fooling in ["ts", "md5sig"]:
            yield StrategyResult(
                params=f"--lua-desync=fake --lua-desync-repeats=4 --lua-desync-fooling={fooling}",
                phase=3,
                name=f"quic_fake_{fooling}",
                description=f"QUIC fake with {fooling}"
            )
        
        # ipfrag2 с позициями
        for frag_pos in [8, 16, 24, 32, 40, 64]:
            yield StrategyResult(
                params=f"--lua-desync=ipfrag2 --lua-desync-ipfrag-pos-udp={frag_pos}",
                phase=4,
                name=f"quic_ipfrag2_pos{frag_pos}",
                description=f"QUIC ipfrag2 at pos {frag_pos}"
            )
        
        # hopbyhop для QUIC (IPv6)
        if self.ipv6:
            yield StrategyResult(
                params="--lua-desync=hopbyhop",
                phase=5,
                name="quic_hopbyhop",
                description="QUIC hopbyhop"
            )
            yield StrategyResult(
                params="--lua-desync=destopt",
                phase=5,
                name="quic_destopt",
                description="QUIC destopt"
            )


# ══════════════════════════════════════════════════════════
#                 HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════

@profiler
def update_selector_state(state: SelectorState, strategy: StrategyResult, success: bool) -> None:
    """
    Обновление состояния selector после тестирования стратегии
    
    Args:
        state: Текущее состояние
        strategy: Протестированная стратегия
        success: Успешность стратегии
    """
    if not success:
        return
    
    params = strategy.params.lower()
    
    # Обновляем флаги
    if "multisplit" in params:
        state.has_multisplit = True
    if "multidisorder" in params:
        state.has_multidisorder = True
    if "--lua-desync=fake" in params or params.startswith("--lua-desync=fake"):
        state.has_fake = True
    if "fakedsplit" in params:
        state.has_fakedsplit = True
    if "fakeddisorder" in params:
        state.has_fakeddisorder = True
    if "hostfakesplit" in params:
        state.has_hostfakesplit = True
    if "wssize" in params:
        state.has_wssize = True


# Глобальный экземпляр
_selector: Optional[BlockcheckStrategySelector] = None
_selector_params: Dict[str, Any] = {}


@profiler
def get_selector(
    protocol: ProtocolType = ProtocolType.TLS12,
    scan_level: ScanLevel = ScanLevel.QUICK,
    ipv6: bool = False,
    zapret_base: Optional[str] = None
) -> BlockcheckStrategySelector:
    """Получить глобальный экземпляр selector"""
    global _selector, _selector_params
    
    current_params = {
        'protocol': protocol,
        'scan_level': scan_level,
        'ipv6': ipv6,
        'zapret_base': zapret_base
    }
    
    if _selector is None or _selector_params != current_params:
        _selector = BlockcheckStrategySelector(
            protocol=protocol,
            scan_level=scan_level,
            ipv6=ipv6,
            zapret_base=zapret_base
        )
        _selector_params = current_params
    
    return _selector
