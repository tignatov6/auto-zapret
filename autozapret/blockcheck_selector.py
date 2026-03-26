"""
Blockcheck Strategy Selector - Выбор стратегий в порядке blockcheck.sh

Отличие от Strategy Generator:
- Генератор создаёт ВСЕ стратегии сразу (3000+)
- Selector генерирует стратегии ЛЕНЕВО в правильном порядке blockcheck.sh
- Selector поддерживает ранний выход при успехе (как quick mode в blockcheck)
- Selector адаптивно пропускает ненужные тесты

Порядок тестирования (как в blockcheck.sh):

PHASE 1: HTTP модификаторы (только для HTTP, sec=0)
  --hostcase, --hostspell=hoSt, --hostnospace, --domcase, --methodeol

PHASE 2: Multisplit/Multidisorder с позициями
  multisplit/multidisorder с splits_tls/splits_http позициями

PHASE 3: Fake режимы с TTL
  fake, fakedsplit, fake,multisplit, etc. с TTL 1-12

PHASE 4: Fake с fooling
  ts, md5sig, badseq, badsum, datanoack

PHASE 5: Fake с AutoTTL
  autottl с delta 1-5

PHASE 6: Orig параметры
  --orig-ttl, --orig-mod-start, --orig-mod-cutoff

PHASE 7: Dup параметры
  --dup, --dup-cutoff, --dup-fooling

PHASE 8: WSSIZE
  --wssize=1:6, --wssize=64:6

PHASE 9: SeqOvl
  --dpi-desync-split-seqovl

PHASE 10: Syndata
  syndata, syndata,multisplit

PHASE 11: IPv6 специфичные (только для IPv6)
  hopbyhop, destopt, ipfrag1, ipfrag2

PHASE 12: QUIC/UDP (только для UDP)
  fake с repeats, ipfrag2
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Generator, List, Optional, Dict, Any, Callable
from pathlib import Path

from .utils.profiler import get_profiler
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
    
    # Fooling методы
    FOOLING_METHODS = ["ts", "md5sig", "badseq", "badsum", "datanoack"]
    FOOLING_IPV6 = ["hopbyhop", "hopbyhop2"]
    
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
            Примерное количество стратегий для текущего протокола
        """
        count = 0
        
        # QUIC
        if self.protocol == ProtocolType.QUIC:
            # Fake repeats: 9 вариантов
            count += 9
            # Fake TTL: 6 вариантов
            count += 6
            # Fake fooling: 2 варианта
            count += 2
            # ipfrag2: 6 позиций
            count += 6
            return count
        
        # WSSIZE quick (только TLS12)
        if self.sec == 1:
            count += 4  # 2 mode × 2 pos
        
        # HTTP модификаторы (только HTTP)
        if self.sec == 0:
            count += 5
        
        # Multisplit/Multidisorder
        count += 2 * len(self.splits)  # 2 mode × len(splits)
        
        # Fake с TTL (приблизительно)
        # 8 режимов × 12 TTL × 2 pos (для split/disorder)
        count += 96 + 192
        
        # Fake с fooling
        count += 8 * 5 + 16 * 5  # 8 режимов × 5 fooling + split/disorder
        
        # AutoTTL
        count += 8 * 5 * 2  # 8 режимов × 5 delta × 2 pos
        
        # Orig параметры
        count += 3 + 3 + 6 + 6  # fake + fake,multisplit × (3 ttl + 3 autottl)
        
        # Dup параметры
        count += 3 * 3 + 3 * 5  # 3 fooling + 5 dup-ttl
        
        # SeqOvl
        count += len(self.splits) * 2 * 2 * 2  # mode × pos × seqovl × (normal+badseq)
        if self.sec != 0:
            count += 1  # pattern 336
        
        # Syndata
        count += 1 + 2 * 4  # syndata + syndata,split × 4 pos
        
        # IPv6 (если включен)
        if self.ipv6:
            count += 11  # 9 base + ipfrag2
        
        return count

    @profiler
    def generate(
        self,
        state: Optional[SelectorState] = None
    ) -> Generator[StrategyResult, None, None]:
        """
        Генерация стратегий в порядке blockcheck.sh
        
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

        # PHASE 1: HTTP модификаторы (только для HTTP)
        if self.sec == 0:
            yield from self._phase2_http_modifiers(state)

        # PHASE 2: Multisplit/Multidisorder
        yield from self._phase3_basic_splits(state)

        # PHASE 3: Fake с TTL
        yield from self._phase3_fake_ttl(state)

        # PHASE 4: Fake с fooling
        yield from self._phase4_fake_fooling(state)

        # PHASE 5: Fake с AutoTTL
        yield from self._phase5_fake_autottl(state)

        # PHASE 6: WSSIZE (ПОСЛЕ autottl, как в blockcheck.sh)
        yield from self._phase8_wssize(state)

        # PHASE 7: Orig параметры
        yield from self._phase6_orig_params(state)

        # PHASE 8: Dup параметры
        yield from self._phase7_dup_params(state)

        # PHASE 9: SeqOvl (расширенный)
        yield from self._phase9_seqovl(state)

        # PHASE 10: Syndata
        yield from self._phase10_syndata(state)

        # PHASE 11: IPv6 специфичные
        if self.ipv6:
            yield from self._phase11_ipv6(state)
    
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
                    params=f"--dpi-desync={mode} --dpi-desync-split-pos={pos} --wssize=1:6",
                    phase=1,
                    name=f"{mode}_{pos}_wssize1_6",
                    description=f"Quick WSSIZE test: {mode} at {pos} with wssize 1:6"
                )

    @profiler
    def _phase2_http_modifiers(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 1: HTTP модификаторы (только для HTTP) - как в blockcheck.sh"""
        modifiers = [
            ("--hostcase", "hostcase"),
            ("--hostspell=hoSt", "hostspell"),
            ("--hostdot", "hostdot"),
            ("--hosttab", "hosttab"),
            ("--hostnospace", "hostnospace"),
            ("--domcase", "domcase"),
            ("--methodeol", "methodeol"),
        ]

        for params, name in modifiers:
            yield StrategyResult(
                params=params,
                phase=1,
                name=f"http_{name}",
                description=f"HTTP modifier: {name}"
            )

    @profiler
    def _phase3_basic_splits(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 2: Multisplit/Multidisorder с позициями"""
        for mode in ["multisplit", "multidisorder"]:
            for pos in self.splits:
                yield StrategyResult(
                    params=f"--dpi-desync={mode} --dpi-desync-split-pos={pos}",
                    phase=2,
                    name=f"{mode}_{pos.replace(',', '_')}",
                    description=f"Basic {mode} at {pos}"
                )
    
    @profiler
    def _phase3_fake_ttl(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 3: Fake режимы с TTL"""
        # Сначала простые fake режимы с TTL
        modes = ["fake"]
        
        # Добавляем комбо если split/disorder ещё не найдены
        if not state.has_multisplit:
            modes.extend(["fakedsplit", "fake,multisplit", "fake,fakedsplit"])
        if not state.has_multidisorder:
            modes.extend(["fakeddisorder", "fake,multidisorder", "fake,fakeddisorder"])
        
        for mode in modes:
            # Адаптивный skip
            if mode == "fake" and state.has_fake:
                continue
            if "fakedsplit" in mode and state.has_fakedsplit:
                continue
            if "fakeddisorder" in mode and state.has_fakeddisorder:
                continue
            if "hostfakesplit" in mode and state.has_hostfakesplit:
                continue
            
            for ttl in range(self.MIN_TTL, self.MAX_TTL + 1):
                params = f"--dpi-desync={mode} --dpi-desync-ttl={ttl}"
                
                # Добавляем позицию для split режимов
                if "split" in mode or "disorder" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
                            phase=3,
                            name=f"{mode}_{pos}_ttl{ttl}",
                            description=f"{mode} at {pos} with TTL {ttl}"
                        )
                else:
                    yield StrategyResult(
                        params=params,
                        phase=3,
                        name=f"{mode}_ttl{ttl}",
                        description=f"{mode} with TTL {ttl}"
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
                params = f"--dpi-desync={mode} --dpi-desync-fooling={fooling}"
                
                # Добавляем позицию для split режимов
                if "split" in mode or "disorder" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                        params=f"{params} --dpi-desync-badseq-increment=0",
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
                params = f"--dpi-desync={mode} --dpi-desync-ttl=1 --dpi-desync-autottl=-{delta} --orig-ttl=1 --orig-mod-start=s1 --orig-mod-cutoff=d1"
                
                # Добавляем позицию для split режимов
                if "split" in mode or "disorder" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                params = f"--dpi-desync={mode} --orig-ttl={orig_ttl}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                params = f"--dpi-desync={mode} --orig-ttl=1 --orig-mod-start=s1 --orig-mod-cutoff=d1 --orig-autottl=+{orig_delta}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                params = f"--dpi-desync={mode} --dup=1 --dup-cutoff=n2 --dup-fooling={dup_fooling}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                params = f"--dpi-desync={mode} --dup=1 --dup-cutoff=n2 --dup-fooling=md5sig --dup-ttl={dup_ttl}"
                
                if "split" in mode:
                    for pos in ["1", "midsld"]:
                        yield StrategyResult(
                            params=f"{params} --dpi-desync-split-pos={pos}",
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
                        params=f"--dpi-desync={mode} --dpi-desync-split-pos={pos} --wssize={wssize}",
                        phase=6,
                        name=f"{mode}_{pos}_wssize{wssize.replace(':', '_')}",
                        description=f"{mode} at {pos} with wssize {wssize}"
                    )
    
    @profiler
    def _phase9_seqovl(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """
        PHASE 9: SeqOvl (расширенный, как в blockcheck.sh строка 1305-1315)
        
        Включает:
        - Базовые seqovl тесты с increment=0
        - Специфичный тест с 336 байтами и TLS паттерном
        - SeqOvl для HTTP (method+2) и TLS (10, sniext+1)
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
                    yield StrategyResult(
                        params=f"--dpi-desync={mode} --dpi-desync-split-pos={pos} --dpi-desync-split-seqovl={seqovl}",
                        phase=9,
                        name=f"{mode}_{pos}_seqovl{seqovl}",
                        description=f"{mode} at {pos} with seqovl {seqovl}"
                    )

                # SeqOvl с badseq и increment=0 (как в blockcheck.sh)
                yield StrategyResult(
                    params=f"--dpi-desync={mode} --dpi-desync-split-pos={pos} --dpi-desync-split-seqovl=badseq --dpi-desync-badseq-increment=0",
                    phase=9,
                    name=f"{mode}_{pos}_seqovl_badseq_inc0",
                    description=f"{mode} at {pos} with seqovl badseq (increment=0)"
                )

        # Специфичный тест с 336 байтами и TLS паттерном (только для TLS)
        if self.sec != 0 and self.zapret_base:
            pattern_file = f"{self.zapret_base}/files/fake/tls_clienthello_iana_org.bin"
            yield StrategyResult(
                params=f"--dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=336 --dpi-desync-split-seqovl-pattern={pattern_file}",
                phase=9,
                name="multisplit_seqovl336_pattern",
                description="multisplit with seqovl 336 and TLS pattern (как в blockcheck.sh)"
            )
    
    @profiler
    def _phase10_syndata(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """PHASE 10: Syndata"""
        # Только syndata
        yield StrategyResult(
            params="--dpi-desync=syndata",
            phase=10,
            name="syndata",
            description="syndata mode"
        )

        # syndata с split
        for split_mode in ["multisplit", "multidisorder"]:
            for pos in ["1", "2", "sniext+1", "midsld"]:
                yield StrategyResult(
                    params=f"--dpi-desync=syndata,{split_mode} --dpi-desync-split-pos={pos}",
                    phase=10,
                    name=f"syndata_{split_mode}_{pos}",
                    description=f"syndata + {split_mode} at {pos}"
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
                params=f"--dpi-desync={mode}",
                phase=11,
                name=f"ipv6_{mode}",
                description=f"IPv6 {mode}"
            )
            
            # С multisplit
            yield StrategyResult(
                params=f"--dpi-desync={mode},multisplit",
                phase=11,
                name=f"ipv6_{mode}_multisplit",
                description=f"IPv6 {mode} + multisplit"
            )
            
            # С multidisorder
            yield StrategyResult(
                params=f"--dpi-desync={mode},multidisorder",
                phase=11,
                name=f"ipv6_{mode}_multidisorder",
                description=f"IPv6 {mode} + multidisorder"
            )
        
        # ipfrag1 с комбинациями (как в blockcheck.sh)
        ipfrag_modes = ["ipfrag1"]
        for mode in ipfrag_modes:
            # Одиночный режим
            yield StrategyResult(
                params=f"--dpi-desync={mode}",
                phase=11,
                name=f"ipv6_{mode}",
                description=f"IPv6 {mode}"
            )
            
            # С multisplit
            yield StrategyResult(
                params=f"--dpi-desync={mode},multisplit",
                phase=11,
                name=f"ipv6_{mode}_multisplit",
                description=f"IPv6 {mode} + multisplit"
            )
            
            # С multidisorder
            yield StrategyResult(
                params=f"--dpi-desync={mode},multidisorder",
                phase=11,
                name=f"ipv6_{mode}_multidisorder",
                description=f"IPv6 {mode} + multidisorder"
            )
        
        # ipfrag2 (для QUIC)
        yield StrategyResult(
            params="--dpi-desync=ipfrag2",
            phase=11,
            name="ipv6_ipfrag2",
            description="IPv6 ipfrag2 (для QUIC)"
        )
    
    @profiler
    def _generate_quic_strategies(self, state: SelectorState) -> Generator[StrategyResult, None, None]:
        """Генерация стратегий для QUIC/UDP"""
        # Fake с repeats
        for rep in [1, 2, 4, 5, 6, 8, 10, 15, 20]:
            yield StrategyResult(
                params=f"--dpi-desync=fake --dpi-desync-repeats={rep}",
                phase=1,
                name=f"quic_fake_R{rep}",
                description=f"QUIC fake with {rep} repeats"
            )
        
        # Fake с TTL
        for ttl in range(1, 7):
            yield StrategyResult(
                params=f"--dpi-desync=fake --dpi-desync-repeats=4 --dpi-desync-ttl={ttl}",
                phase=2,
                name=f"quic_fake_ttl{ttl}",
                description=f"QUIC fake with TTL {ttl}"
            )
        
        # Fake с fooling
        for fooling in ["ts", "md5sig"]:
            yield StrategyResult(
                params=f"--dpi-desync=fake --dpi-desync-repeats=4 --dpi-desync-fooling={fooling}",
                phase=3,
                name=f"quic_fake_{fooling}",
                description=f"QUIC fake with {fooling}"
            )
        
        # ipfrag2 с позициями
        for frag_pos in [8, 16, 24, 32, 40, 64]:
            yield StrategyResult(
                params=f"--dpi-desync=ipfrag2 --dpi-desync-ipfrag-pos-udp={frag_pos}",
                phase=4,
                name=f"quic_ipfrag2_pos{frag_pos}",
                description=f"QUIC ipfrag2 at pos {frag_pos}"
            )
        
        # hopbyhop для QUIC (IPv6)
        if self.ipv6:
            yield StrategyResult(
                params="--dpi-desync=hopbyhop",
                phase=5,
                name="quic_hopbyhop",
                description="QUIC hopbyhop"
            )
            yield StrategyResult(
                params="--dpi-desync=destopt",
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
    if "--dpi-desync=fake" in params or params.startswith("--dpi-desync=fake"):
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
