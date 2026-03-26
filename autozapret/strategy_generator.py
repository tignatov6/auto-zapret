"""
Strategy Generator - Генерация стратегий для перебора

Основан на логике blockcheck.sh из zapret
Генерирует 3000+ стратегий для DPI обхода

Включает все режимы из blockcheck.sh:
- Phase 0: syndata
- Phase 1: fake
- Phase 2: multisplit, multidisorder, fakedsplit, fakeddisorder, hostfakesplit
- IPv6: hopbyhop, destopt, ipfrag1, ipfrag2
- UDP/QUIC: fake, ipfrag2
- Orig: orig-ttl, orig-mod-*, orig-autottl
- Dup: dup, dup-cutoff, dup-fooling, dup-ttl, dup-autottl
"""

import logging
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from .utils.profiler import get_profiler
profiler = get_profiler("strategy_generator")

logger = logging.getLogger(__name__)


@dataclass
class StrategyConfig:
    """Конфигурация стратегии"""
    name: str
    mode: str  # fake, multisplit, multidisorder, fakedsplit, fakeddisorder, hostfakesplit, syndata, hopbyhop, etc.
    pos: Optional[str] = None  # позиция split: 1, 2, sniext+1, midsld, method+2, etc.
    fool: Optional[str] = None  # fooling: ts, md5sig, badsum, badseq, datanoack
    rep: int = 1  # повторения
    wssize: Optional[str] = None  # window size: None, "1:6", "64:6"
    ttl: Optional[int] = None  # TTL: None, 1-16
    autottl: Optional[str] = None  # AutoTTL: "-1" .. "-8"
    
    # Sequence overlap
    seqovl: Optional[int] = None  # 1, 2, 336
    seqovl_pattern: Optional[str] = None  # путь к файлу паттерна
    
    # Fake модификаторы
    fake_tls_mod: Optional[str] = None  # "rnd,rndsni,dupsid", "padencap"
    fake_tcp_mod: Optional[str] = None  # "seq"
    fakedsplit_mod: Optional[str] = None  # "altorder=1", "altorder=2"
    
    # HostFakeSplit модификаторы
    hostfakesplit_mod: Optional[str] = None  # "altorder=1"
    hostfakesplit_midhost: Optional[str] = None  # "midsld"
    
    # Orig параметры (для модификации оригинального пакета)
    orig_ttl: Optional[int] = None  # orig-ttl=1
    orig_mod_start: Optional[str] = None  # "s1"
    orig_mod_cutoff: Optional[str] = None  # "d1"
    orig_autottl: Optional[str] = None  # "+1", "+2", "+3"
    
    # Dup параметры (дублирование пакетов)
    dup: Optional[int] = None  # 1
    dup_cutoff: Optional[str] = None  # "n2"
    dup_fooling: Optional[str] = None  # "md5sig"
    dup_ttl: Optional[int] = None
    dup_autottl: Optional[str] = None
    
    # BadSeq параметр
    badseq_increment: Optional[int] = None  # 0
    
    # IP Frag параметры (для UDP/QUIC)
    ipfrag_pos_udp: Optional[int] = None  # 8, 16, 24, 32, 40, 64
    
    # HTTP модификаторы
    hostcase: bool = False
    hostspell: Optional[str] = None  # "hoSt"
    hostnospace: bool = False
    domcase: bool = False
    methodeol: bool = False
    
    # Дополнительные параметры
    extra: List[str] = field(default_factory=list)

    @profiler
    def to_params(self) -> str:
        """Преобразовать в параметры командной строки"""
        params = []

        if self.mode:
            params.append(f"--dpi-desync={self.mode}")

        if self.pos:
            params.append(f"--dpi-desync-split-pos={self.pos}")

        if self.fool:
            params.append(f"--dpi-desync-fooling={self.fool}")

        if self.rep and self.rep > 1:
            params.append(f"--dpi-desync-repeats={self.rep}")

        if self.wssize:
            params.append(f"--wssize={self.wssize}")

        if self.ttl:
            params.append(f"--dpi-desync-ttl={self.ttl}")

        if self.autottl:
            params.append(f"--dpi-desync-autottl={self.autottl}")

        if self.seqovl:
            params.append(f"--dpi-desync-split-seqovl={self.seqovl}")

        if self.seqovl_pattern:
            params.append(f"--dpi-desync-split-seqovl-pattern={self.seqovl_pattern}")

        if self.fake_tls_mod:
            params.append(f"--dpi-desync-fake-tls-mod={self.fake_tls_mod}")

        if self.fake_tcp_mod:
            params.append(f"--dpi-desync-fake-tcp-mod={self.fake_tcp_mod}")

        if self.fakedsplit_mod:
            params.append(f"--dpi-desync-fakedsplit-mod={self.fakedsplit_mod}")

        if self.hostfakesplit_mod:
            params.append(f"--dpi-desync-hostfakesplit-mod={self.hostfakesplit_mod}")

        if self.hostfakesplit_midhost:
            params.append(f"--dpi-desync-hostfakesplit-midhost={self.hostfakesplit_midhost}")

        # Orig параметры
        if self.orig_ttl:
            params.append(f"--orig-ttl={self.orig_ttl}")

        if self.orig_mod_start:
            params.append(f"--orig-mod-start={self.orig_mod_start}")

        if self.orig_mod_cutoff:
            params.append(f"--orig-mod-cutoff={self.orig_mod_cutoff}")

        if self.orig_autottl:
            params.append(f"--orig-autottl={self.orig_autottl}")

        # Dup параметры
        if self.dup:
            params.append(f"--dup={self.dup}")

        if self.dup_cutoff:
            params.append(f"--dup-cutoff={self.dup_cutoff}")

        if self.dup_fooling:
            params.append(f"--dup-fooling={self.dup_fooling}")

        if self.dup_ttl:
            params.append(f"--dup-ttl={self.dup_ttl}")

        if self.dup_autottl:
            params.append(f"--dup-autottl={self.dup_autottl}")

        # BadSeq
        if self.badseq_increment is not None:
            params.append(f"--dpi-desync-badseq-increment={self.badseq_increment}")

        # IP Frag UDP
        if self.ipfrag_pos_udp:
            params.append(f"--dpi-desync-ipfrag-pos-udp={self.ipfrag_pos_udp}")

        # HTTP модификаторы
        if self.hostcase:
            params.append("--hostcase")

        if self.hostspell:
            params.append(f"--hostspell={self.hostspell}")

        if self.hostnospace:
            params.append("--hostnospace")

        if self.domcase:
            params.append("--domcase")

        if self.methodeol:
            params.append("--methodeol")

        if self.extra:
            params.extend(self.extra)

        return " ".join(params)


class StrategyGenerator:
    """Генератор стратегий для перебора - полный набор из blockcheck.sh"""

    # Диапазоны из blockcheck.sh
    MIN_TTL = 1
    MAX_TTL = 12  # blockcheck.sh использует 1-12
    MIN_AUTOTTL_DELTA = 1
    MAX_AUTOTTL_DELTA = 5  # blockcheck.sh использует 1-5

    # Split позиции из blockcheck.sh (TLS)
    SPLITS_TLS = [
        "1", "2",
        "sniext+1", "sniext+4",
        "host+1", "midsld",
        "1,midsld",
        "1,sniext+1,host+1,midsld",
        "endhost-1",
        "midsld-2", "midsld+2",
    ]

    # Расширенные split позиции (для seqovl)
    SPLITS_TLS_EXTENDED = [
        "10",
        "10,sniext+1",
        "10,sniext+4",
        "10,midsld",
    ]

    # Split позиции для HTTP
    SPLITS_HTTP = [
        "method+2", "midsld", "method+2,midsld"
    ]

    # Приоритетные позиции (тестируются первыми)
    PRIORITY_SPLITS = ["sniext+1", "1", "midsld", "1,midsld"]

    # Fooling методы из blockcheck.sh
    FOOLS_SINGLE = ["ts", "md5sig", "badseq", "badsum", "datanoack"]
    FOOLS_IPV6 = ["hopbyhop", "hopbyhop2"]  # Только для IPv6

    # Режимы DPI desync
    FAKE_MODES = ["fake"]

    # Режимы с split
    SPLIT_MODES = ["multisplit", "multidisorder"]

    # Режимы fake + split (комбо)
    FAKE_SPLIT_MODES = [
        "fakedsplit",
        "fakeddisorder",
        "fake,multisplit",
        "fake,fakedsplit",
        "fake,multidisorder",
        "fake,fakeddisorder",
    ]

    # HostFakeSplit режимы
    HOSTFAKESPLIT_MODES = ["hostfakesplit", "fake,hostfakesplit"]

    # Phase 0 режимы
    PHASE0_MODES = ["syndata"]

    # IPv6 режимы (только для IPv6)
    IPV6_MODES = [
        "hopbyhop",
        "hopbyhop,multisplit",
        "hopbyhop,multidisorder",
        "destopt",
        "destopt,multisplit",
        "destopt,multidisorder",
    ]

    # IPv6 IP fragment режимы
    IPV6_FRAG_MODES = ["ipfrag1", "ipfrag2"]
    IPV6_FRAG_COMBO = [
        "ipfrag1,multisplit",
        "ipfrag1,multidisorder",
        "hopbyhop,ipfrag2",
        "destopt,ipfrag2",
    ]

    # QUIC/UDP параметры
    QUIC_FRAG_POSITIONS = [8, 16, 24, 32, 40, 64]

    # fakedsplit модификаторы
    FAKEDSPLIT_MODS = ["altorder=1", "altorder=2"]

    # Fake TLS модификаторы
    FAKE_TLS_MODS = ["rnd,rndsni,dupsid", "padencap"]

    # Fake TCP модификаторы
    FAKE_TCP_MODS = ["seq"]

    @profiler
    def __init__(self, has_fake_files: bool = False, ultimate_strategies_path: Optional[str] = None,
                 zapret_base: Optional[str] = None):
        """
        Инициализация генератора

        Args:
            has_fake_files: Есть ли файлы фейков (.bin)
            ultimate_strategies_path: Путь к файлу с приоритетными стратегиями
            zapret_base: Путь к директории zapret (для fake файлов)
        """
        self.has_fake_files = has_fake_files
        self.ultimate_strategies = []
        self.zapret_base = zapret_base

        # Загружаем приоритетные стратегии из файла
        if ultimate_strategies_path:
            self.ultimate_strategies = self._load_ultimate_strategies(ultimate_strategies_path)

    @profiler
    def _load_ultimate_strategies(self, path: str) -> List[Dict]:
        """Загрузить приоритетные стратегии из JSON файла"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.info(f"Loaded {len(data)} ultimate strategies from {path}")
                return data
        except Exception as e:
            logger.warning(f"Failed to load ultimate strategies: {e}")
            return []

    @profiler
    def generate_all(self, include_ipv6: bool = True) -> List[StrategyConfig]:
        """
        Генерация всех стратегий

        Args:
            include_ipv6: Включать ли IPv6 специфичные стратегии

        Returns:
            Список стратегий (3000+)
        """
        strategies = []

        logger.info("Generating strategies (full blockcheck.sh coverage)...")

        # ПРИОРИТЕТ 0: Ultimate стратегии из файла (самые важные!)
        strategies.extend(self._generate_ultimate_strategies())

        # ПРИОРИТЕТ 1: fakedsplit/fakeddisorder (КРИТИЧЕСКИ ВАЖНО!)
        strategies.extend(self._generate_fakedsplit_strategies())

        # ПРИОРИТЕТ 2: HostFakeSplit
        strategies.extend(self._generate_hostfakesplit_strategies())

        # ПРИОРИТЕТ 3: Базовые Split стратегии
        strategies.extend(self._generate_basic_splits())

        # ПРИОРИТЕТ 4: Fake режимы с fooling
        strategies.extend(self._generate_fake_fooling_strategies())

        # ПРИОРИТЕТ 5: Phase 0 (syndata)
        strategies.extend(self._generate_phase0_strategies())

        # ПРИОРИТЕТ 6: Orig параметры (--orig-ttl, --orig-mod-*)
        strategies.extend(self._generate_orig_strategies())

        # ПРИОРИТЕТ 7: Dup параметры (--dup, --dup-cutoff, --dup-fooling)
        strategies.extend(self._generate_dup_strategies())

        # ПРИОРИТЕТ 8: BadSeq стратегии
        strategies.extend(self._generate_badseq_strategies())

        # ПРИОРИТЕТ 9: WSSIZE стратегии
        strategies.extend(self._generate_wssize_strategies())

        # ПРИОРИТЕТ 10: SeqOvl стратегии
        strategies.extend(self._generate_seqovl_strategies())

        # ПРИОРИТЕТ 11: SeqOvl с паттернами
        strategies.extend(self._generate_seqovl_pattern_strategies())

        # ПРИОРИТЕТ 12: Расширенные split позиции (с seqovl)
        strategies.extend(self._generate_extended_split_strategies())

        # ПРИОРИТЕТ 13: Fake TLS модификаторы
        strategies.extend(self._generate_fake_tls_mods())

        # ПРИОРИТЕТ 14: Fake TCP модификаторы
        strategies.extend(self._generate_fake_tcp_mods())

        # ПРИОРИТЕТ 15: Fake режимы с TTL
        strategies.extend(self._generate_fake_ttl_strategies())

        # ПРИОРИТЕТ 16: HTTP модификаторы (только для HTTP)
        strategies.extend(self._generate_http_modifier_strategies())

        # ПРИОРИТЕТ 17: HTTP split стратегии
        strategies.extend(self._generate_http_mods())

        # ПРИОРИТЕТ 18: QUIC/UDP стратегии
        strategies.extend(self._generate_quic_strategies())

        # ПРИОРИТЕТ 19: IPv6 стратегии (опционально)
        if include_ipv6:
            strategies.extend(self._generate_ipv6_strategies())
            strategies.extend(self._generate_ipv6_frag_strategies())

        logger.info(f"Generated {len(strategies)} strategies")

        return strategies

    @profiler
    def _generate_ultimate_strategies(self) -> List[StrategyConfig]:
        """Генерация стратегий из Ultimate F.bat"""
        strategies = []

        for ult in self.ultimate_strategies:
            params = ult.get('params', '')

            strategy = StrategyConfig(
                name=ult.get('name', 'ultimate'),
                mode='multisplit',
                extra=[]
            )

            # Парсим параметры
            for part in params.split():
                if part.startswith('--dpi-desync='):
                    strategy.mode = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-split-pos='):
                    strategy.pos = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-fooling='):
                    strategy.fool = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-repeats='):
                    strategy.rep = int(part.split('=', 1)[1])
                elif part.startswith('--dpi-desync-ttl='):
                    strategy.ttl = int(part.split('=', 1)[1])
                elif part.startswith('--dpi-desync-autottl='):
                    strategy.autottl = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-split-seqovl='):
                    strategy.seqovl = int(part.split('=', 1)[1])
                elif part.startswith('--wssize='):
                    strategy.wssize = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-fake-tls-mod='):
                    strategy.fake_tls_mod = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-fakedsplit-mod='):
                    strategy.fakedsplit_mod = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-hostfakesplit-mod='):
                    strategy.hostfakesplit_mod = part.split('=', 1)[1]
                elif part.startswith('--dpi-desync-hostfakesplit-midhost='):
                    strategy.hostfakesplit_midhost = part.split('=', 1)[1]
                elif part.startswith('--orig-ttl='):
                    strategy.orig_ttl = int(part.split('=', 1)[1])
                elif part.startswith('--orig-mod-start='):
                    strategy.orig_mod_start = part.split('=', 1)[1]
                elif part.startswith('--orig-mod-cutoff='):
                    strategy.orig_mod_cutoff = part.split('=', 1)[1]
                elif part.startswith('--orig-autottl='):
                    strategy.orig_autottl = part.split('=', 1)[1]
                elif part.startswith('--'):
                    strategy.extra.append(part)

            strategies.append(strategy)

        return strategies

    @profiler
    def _generate_fakedsplit_strategies(self) -> List[StrategyConfig]:
        """
        Генерация fakedsplit/fakeddisorder стратегий

        КРИТИЧЕСКИ ВАЖНО! Эти режимы часто работают когда обычный multisplit не работает.
        """
        strategies = []

        # fakedsplit и fakeddisorder с приоритетными позициями
        for mode in ["fakedsplit", "fakeddisorder"]:
            for pos in self.PRIORITY_SPLITS:
                # Без модификатора
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos}_R1",
                    mode=mode,
                    pos=pos,
                    rep=1
                ))

                # С ts fooling
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos}_ts_R1",
                    mode=mode,
                    pos=pos,
                    fool="ts",
                    rep=1
                ))

                # С разными altorder
                for mod in self.FAKEDSPLIT_MODS:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_{mod.replace('=', '_')}",
                        mode=mode,
                        pos=pos,
                        rep=1,
                        fakedsplit_mod=mod
                    ))

        # fake,multisplit и fake,fakedsplit комбинации
        for mode in ["fake,multisplit", "fake,fakedsplit", "fake,multidisorder", "fake,fakeddisorder"]:
            for pos in self.PRIORITY_SPLITS:
                for fool in ["ts", "md5sig"]:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_{fool}_R2",
                        mode=mode,
                        pos=pos,
                        fool=fool,
                        rep=2
                    ))

        return strategies

    @profiler
    def _generate_hostfakesplit_strategies(self) -> List[StrategyConfig]:
        """Генерация HostFakeSplit стратегий"""
        strategies = []

        for mode in self.HOSTFAKESPLIT_MODES:
            # Базовый с ts
            strategies.append(StrategyConfig(
                name=f"{mode}_ts_R2",
                mode=mode,
                fool="ts",
                rep=2
            ))

            # С midhost
            strategies.append(StrategyConfig(
                name=f"{mode}_midhost_R2",
                mode=mode,
                fool="ts",
                rep=2,
                hostfakesplit_midhost="midsld"
            ))

            # С altorder
            strategies.append(StrategyConfig(
                name=f"{mode}_altorder1_R2",
                mode=mode,
                fool="ts",
                rep=2,
                hostfakesplit_mod="altorder=1"
            ))

            # С midhost + altorder
            strategies.append(StrategyConfig(
                name=f"{mode}_midhost_altorder1_R2",
                mode=mode,
                fool="ts",
                rep=2,
                hostfakesplit_midhost="midsld",
                hostfakesplit_mod="altorder=1"
            ))

        return strategies

    @profiler
    def _generate_basic_splits(self) -> List[StrategyConfig]:
        """Генерация базовых Split стратегий"""
        strategies = []

        for mode in self.SPLIT_MODES:
            # Приоритетные позиции с fooling
            for pos in self.PRIORITY_SPLITS:
                for fool in ["ts", "md5sig"]:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_{fool}_R1",
                        mode=mode,
                        pos=pos,
                        fool=fool,
                        rep=1
                    ))

            # Остальные позиции
            for pos in self.SPLITS_TLS:
                if pos not in self.PRIORITY_SPLITS:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_R1",
                        mode=mode,
                        pos=pos,
                        rep=1
                    ))

        return strategies

    @profiler
    def _generate_fake_fooling_strategies(self) -> List[StrategyConfig]:
        """Генерация fake стратегий с разными fooling"""
        strategies = []

        # Простые fake с fooling
        for fool in self.FOOLS_SINGLE:
            strategies.append(StrategyConfig(
                name=f"fake_{fool}_R2",
                mode="fake",
                fool=fool,
                rep=2
            ))

        return strategies

    @profiler
    def _generate_phase0_strategies(self) -> List[StrategyConfig]:
        """
        Генерация Phase 0 стратегий (syndata)

        Работает на этапе установки соединения, до отправки данных.
        """
        strategies = []

        for mode in self.PHASE0_MODES:
            # Только syndata
            strategies.append(StrategyConfig(
                name=f"{mode}_R2",
                mode=mode,
                rep=2
            ))

            # syndata с split
            for split_mode in ["multisplit", "multidisorder"]:
                for pos in ["1", "2", "sniext+1", "midsld"]:
                    strategies.append(StrategyConfig(
                        name=f"{mode},{split_mode}_{pos}_R1",
                        mode=f"{mode},{split_mode}",
                        pos=pos,
                        rep=1
                    ))

        return strategies

    @profiler
    def _generate_orig_strategies(self) -> List[StrategyConfig]:
        """
        Генерация стратегий с --orig параметрами

        orig-ttl=1 с start/cutoff limiter drops empty ACK packet.
        orig-autottl позволяет автоматически вычислять TTL для оригинального пакета.
        """
        strategies = []

        # Orig TTL с fake режимами
        for mode in ["fake"] + self.FAKE_SPLIT_MODES[:2]:
            has_pos = "split" in mode or "disorder" in mode
            positions = ["1", "midsld"] if has_pos else [None]

            for pos in positions:
                # С orig-ttl=1 и модификаторами
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos or 'nopos'}_orig_mod_R2",
                    mode=mode,
                    pos=pos,
                    fool="ts",
                    rep=2,
                    orig_ttl=1,
                    orig_mod_start="s1",
                    orig_mod_cutoff="d1"
                ))

                # С разными TTL
                for ttl in range(self.MIN_TTL, min(5, self.MAX_TTL) + 1):
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos or 'nopos'}_TTL{ttl}_orig_R2",
                        mode=mode,
                        pos=pos,
                        fool="ts",
                        rep=2,
                        ttl=ttl,
                        orig_ttl=1,
                        orig_mod_start="s1",
                        orig_mod_cutoff="d1"
                    ))

                # С orig-autottl (автоматический TTL для оригинального пакета)
                for autottl_delta in range(1, 4):  # +1, +2, +3
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos or 'nopos'}_orig_autottl+{autottl_delta}_R2",
                        mode=mode,
                        pos=pos,
                        fool="ts",
                        rep=2,
                        orig_ttl=1,
                        orig_mod_start="s1",
                        orig_mod_cutoff="d1",
                        orig_autottl=f"+{autottl_delta}"
                    ))

                # С orig-ttl без модификаторов (простой вариант)
                for orig_ttl_val in [1, 2, 3]:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos or 'nopos'}_orig_ttl{orig_ttl_val}_R2",
                        mode=mode,
                        pos=pos,
                        fool="ts",
                        rep=2,
                        orig_ttl=orig_ttl_val
                    ))

                # Комбо: ttl + orig_autottl
                for ttl in range(1, 4):
                    for autottl_delta in [1, 2]:
                        strategies.append(StrategyConfig(
                            name=f"{mode}_{pos or 'nopos'}_TTL{ttl}_orig_autottl+{autottl_delta}_R2",
                            mode=mode,
                            pos=pos,
                            fool="ts",
                            rep=2,
                            ttl=ttl,
                            orig_ttl=1,
                            orig_mod_start="s1",
                            orig_mod_cutoff="d1",
                            orig_autottl=f"+{autottl_delta}"
                        ))

        return strategies

    @profiler
    def _generate_dup_strategies(self) -> List[StrategyConfig]:
        """
        Генерация стратегий с --dup параметрами

        Dup дублирует пакеты с fooling для обхода DPI.
        dup_ttl и dup_autottl контролируют TTL дублированного пакета.
        """
        strategies = []

        # Dup с md5sig (для обхода 1 сек задержки сервера)
        for mode in ["fake"] + self.FAKE_SPLIT_MODES[:2]:
            has_pos = "split" in mode or "disorder" in mode
            positions = ["1", "midsld"] if has_pos else [None]

            for pos in positions:
                # Dup с md5sig
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos or 'nopos'}_dup_md5sig_R2",
                    mode=mode,
                    pos=pos,
                    fool="md5sig",
                    rep=2,
                    dup=1,
                    dup_cutoff="n2",
                    dup_fooling="md5sig"
                ))

                # Dup с разными TTL для дубликата
                for dup_ttl in range(self.MIN_TTL, min(6, self.MAX_TTL) + 1):
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos or 'nopos'}_dup_md5sig_ttl{dup_ttl}_R2",
                        mode=mode,
                        pos=pos,
                        fool="md5sig",
                        rep=2,
                        dup=1,
                        dup_cutoff="n2",
                        dup_fooling="md5sig",
                        dup_ttl=dup_ttl
                    ))

                # Dup с autottl для дубликата
                for delta in range(self.MIN_AUTOTTL_DELTA, self.MAX_AUTOTTL_DELTA + 1):
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos or 'nopos'}_dup_md5sig_autottl{delta}_R2",
                        mode=mode,
                        pos=pos,
                        fool="md5sig",
                        rep=2,
                        dup=1,
                        dup_cutoff="n2",
                        dup_fooling="md5sig",
                        dup_autottl=f"-{delta}"
                    ))

                # Dup с ts fooling
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos or 'nopos'}_dup_ts_R2",
                    mode=mode,
                    pos=pos,
                    fool="ts",
                    rep=2,
                    dup=1,
                    dup_cutoff="n2",
                    dup_fooling="ts"
                ))

                # Dup с badsum fooling
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos or 'nopos'}_dup_badsum_R2",
                    mode=mode,
                    pos=pos,
                    fool="badsum",
                    rep=2,
                    dup=1,
                    dup_cutoff="n2",
                    dup_fooling="badsum"
                ))

        return strategies

    @profiler
    def _generate_badseq_strategies(self) -> List[StrategyConfig]:
        """Генерация стратегий с --badseq-increment"""
        strategies = []

        for mode in ["fake"] + self.FAKE_SPLIT_MODES[:2]:
            has_pos = "split" in mode or "disorder" in mode
            positions = ["1", "midsld"] if has_pos else [None]

            for pos in positions:
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos or 'nopos'}_badseq_inc0_R2",
                    mode=mode,
                    pos=pos,
                    fool="badseq",
                    rep=2,
                    badseq_increment=0
                ))

        return strategies

    @profiler
    def _generate_wssize_strategies(self) -> List[StrategyConfig]:
        """Генерация WSSIZE стратегий"""
        strategies = []

        for mode in self.SPLIT_MODES:
            for pos in ["1", "2", "sniext+1"]:
                for wssize in ["1:6", "64:6"]:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_wssize{wssize.replace(':', '_')}_R1",
                        mode=mode,
                        pos=pos,
                        fool="ts",
                        rep=1,
                        wssize=wssize
                    ))

        return strategies

    @profiler
    def _generate_seqovl_strategies(self) -> List[StrategyConfig]:
        """Генерация SeqOvl стратегий"""
        strategies = []

        for mode in self.SPLIT_MODES:
            for pos in ["1", "2", "sniext+1"]:
                for seqovl in [1, 2]:
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos}_seqovl{seqovl}_R1",
                        mode=mode,
                        pos=pos,
                        rep=1,
                        seqovl=seqovl
                    ))

        return strategies

    @profiler
    def _generate_seqovl_pattern_strategies(self) -> List[StrategyConfig]:
        """Генерация SeqOvl стратегий с паттернами"""
        strategies = []

        # Если указан путь к zapret
        if self.zapret_base:
            pattern_file = f"{self.zapret_base}/files/fake/tls_clienthello_iana_org.bin"

            for mode in self.SPLIT_MODES:
                strategies.append(StrategyConfig(
                    name=f"{mode}_seqovl336_pattern_R1",
                    mode=mode,
                    pos="2",
                    rep=1,
                    seqovl=336,
                    seqovl_pattern=pattern_file
                ))

        return strategies

    @profiler
    def _generate_extended_split_strategies(self) -> List[StrategyConfig]:
        """Генерация стратегий с расширенными split позициями (для seqovl)"""
        strategies = []

        for mode in self.SPLIT_MODES:
            for pos in self.SPLITS_TLS_EXTENDED:
                strategies.append(StrategyConfig(
                    name=f"{mode}_{pos.replace(',', '_')}_seqovl1_R1",
                    mode=mode,
                    pos=pos,
                    rep=1,
                    seqovl=1
                ))

        # Multidisorder с seqovl для разных позиций
        disorder_combos = [
            ("1", "2"),
            ("sniext", "sniext+1"),
            ("sniext+3", "sniext+4"),
            ("midsld-1", "midsld"),
        ]

        for split_pos, seqovl_pos in disorder_combos:
            strategies.append(StrategyConfig(
                name=f"multidisorder_{split_pos.replace('+', '_')}_seqovl_R1",
                mode="multidisorder",
                pos=seqovl_pos,
                rep=1,
                seqovl=1,
                extra=[f"--dpi-desync-split-seqovl={split_pos}"] if split_pos != seqovl_pos else []
            ))

        return strategies

    @profiler
    def _generate_fake_tls_mods(self) -> List[StrategyConfig]:
        """Генерация Fake TLS модификаторов"""
        strategies = []

        for mod in self.FAKE_TLS_MODS:
            strategies.append(StrategyConfig(
                name=f"fake_tls_{mod.replace(',', '_')}_R2",
                mode="fake",
                fool="ts",
                rep=2,
                fake_tls_mod=mod
            ))

        return strategies

    @profiler
    def _generate_fake_tcp_mods(self) -> List[StrategyConfig]:
        """Генерация Fake TCP модификаторов"""
        strategies = []

        for mod in self.FAKE_TCP_MODS:
            strategies.append(StrategyConfig(
                name=f"fake_tcp_{mod}_R2",
                mode="fake",
                fool="ts",
                rep=2,
                fake_tcp_mod=mod
            ))

        return strategies

    @profiler
    def _generate_fake_ttl_strategies(self) -> List[StrategyConfig]:
        """Генерация Fake стратегий с TTL циклом"""
        strategies = []

        for mode in ["fake"] + self.FAKE_SPLIT_MODES[:2]:
            has_pos = "split" in mode or "disorder" in mode
            positions = ["1", "midsld"] if has_pos else [None]

            for pos in positions:
                pos_str = pos or "nopos"

                # TTL цикл
                for ttl in range(self.MIN_TTL, self.MAX_TTL + 1):
                    for fool in ["ts", "md5sig"]:
                        strategies.append(StrategyConfig(
                            name=f"{mode}_{pos_str}_TTL{ttl}_{fool}_R2",
                            mode=mode,
                            pos=pos,
                            fool=fool,
                            rep=2,
                            ttl=ttl
                        ))

                # AutoTTL
                for delta in range(self.MIN_AUTOTTL_DELTA, self.MAX_AUTOTTL_DELTA + 1):
                    strategies.append(StrategyConfig(
                        name=f"{mode}_{pos_str}_autottl-{delta}_R2",
                        mode=mode,
                        pos=pos,
                        fool="ts",
                        rep=2,
                        ttl=1,
                        autottl=f"-{delta}"
                    ))

        return strategies

    @profiler
    def _generate_http_modifier_strategies(self) -> List[StrategyConfig]:
        """
        Генерация HTTP модификаторов

        Эти стратегии работают только для HTTP (не TLS)
        """
        strategies = []

        # hostcase
        strategies.append(StrategyConfig(
            name="http_hostcase",
            mode="multisplit",
            pos="method+2",
            rep=1,
            hostcase=True
        ))

        # hostspell=hoSt
        strategies.append(StrategyConfig(
            name="http_hostspell",
            mode="multisplit",
            pos="method+2",
            rep=1,
            hostspell="hoSt"
        ))

        # hostnospace
        strategies.append(StrategyConfig(
            name="http_hostnospace",
            mode="multisplit",
            pos="method+2",
            rep=1,
            hostnospace=True
        ))

        # domcase
        strategies.append(StrategyConfig(
            name="http_domcase",
            mode="multisplit",
            pos="method+2",
            rep=1,
            domcase=True
        ))

        # methodeol
        strategies.append(StrategyConfig(
            name="http_methodeol",
            mode="multisplit",
            pos="method+2",
            rep=1,
            methodeol=True
        ))

        return strategies

    @profiler
    def _generate_http_mods(self) -> List[StrategyConfig]:
        """Генерация HTTP split стратегий"""
        strategies = []

        for mode in self.SPLIT_MODES:
            for pos in self.SPLITS_HTTP:
                strategies.append(StrategyConfig(
                    name=f"http_{mode}_{pos.replace(',', '_')}",
                    mode=mode,
                    pos=pos,
                    rep=1
                ))

        return strategies

    @profiler
    def _generate_quic_strategies(self) -> List[StrategyConfig]:
        """
        Генерация QUIC/UDP стратегий

        Для HTTP3/QUIC протокола. Включает:
        - fake с разными repeats
        - ipfrag2 с разными позициями фрагментации
        - Комбинации с TTL и fooling
        """
        strategies = []

        # Fake для QUIC с разными repeats
        for rep in [1, 2, 4, 5, 6, 8, 10, 15, 20]:
            strategies.append(StrategyConfig(
                name=f"quic_fake_R{rep}",
                mode="fake",
                rep=rep
            ))

        # Fake для QUIC с TTL
        for ttl in range(1, 7):
            strategies.append(StrategyConfig(
                name=f"quic_fake_ttl{ttl}_R4",
                mode="fake",
                rep=4,
                ttl=ttl
            ))

        # Fake для QUIC с fooling
        for fool in ["ts", "md5sig"]:
            strategies.append(StrategyConfig(
                name=f"quic_fake_{fool}_R4",
                mode="fake",
                rep=4,
                fool=fool
            ))

        # ipfrag2 для QUIC с разными позициями
        for frag_pos in self.QUIC_FRAG_POSITIONS:
            strategies.append(StrategyConfig(
                name=f"quic_ipfrag2_pos{frag_pos}",
                mode="ipfrag2",
                ipfrag_pos_udp=frag_pos
            ))

        # ipfrag1 для QUIC (меньший offset)
        for frag_pos in [8, 16, 24]:
            strategies.append(StrategyConfig(
                name=f"quic_ipfrag1_pos{frag_pos}",
                mode="ipfrag1",
                ipfrag_pos_udp=frag_pos
            ))

        # hopbyhop,ipfrag2 и destopt,ipfrag2 для IPv6 QUIC
        for mode in ["hopbyhop,ipfrag2", "destopt,ipfrag2"]:
            for frag_pos in self.QUIC_FRAG_POSITIONS:
                strategies.append(StrategyConfig(
                    name=f"quic_{mode.replace(',', '_')}_pos{frag_pos}",
                    mode=mode,
                    ipfrag_pos_udp=frag_pos
                ))

        # hopbyhop для QUIC (без ipfrag)
        strategies.append(StrategyConfig(
            name="quic_hopbyhop_R1",
            mode="hopbyhop",
            rep=1
        ))

        # destopt для QUIC (без ipfrag)
        strategies.append(StrategyConfig(
            name="quic_destopt_R1",
            mode="destopt",
            rep=1
        ))

        # Комбо: fake,ipfrag2 для QUIC
        for frag_pos in [16, 24, 32]:
            strategies.append(StrategyConfig(
                name=f"quic_fake_ipfrag2_pos{frag_pos}_R2",
                mode="fake,ipfrag2",
                rep=2,
                ipfrag_pos_udp=frag_pos
            ))

        return strategies

    @profiler
    def _generate_ipv6_strategies(self) -> List[StrategyConfig]:
        """
        Генерация IPv6 специфичных стратегий

        hopbyhop и destopt - расширения IPv6 заголовка.
        hopbyhop2 - двойной hopbyhop заголовок.
        """
        strategies = []

        for mode in self.IPV6_MODES:
            if "multisplit" in mode or "multidisorder" in mode:
                for pos in self.PRIORITY_SPLITS:
                    strategies.append(StrategyConfig(
                        name=f"ipv6_{mode.replace(',', '_')}_{pos}_R1",
                        mode=mode,
                        pos=pos,
                        rep=1
                    ))
            else:
                strategies.append(StrategyConfig(
                    name=f"ipv6_{mode}_R1",
                    mode=mode,
                    rep=1
                ))

        # hopbyhop2 - двойной hopbyhop для обхода более сложных DPI
        strategies.append(StrategyConfig(
            name="ipv6_hopbyhop2_R1",
            mode="hopbyhop2",
            rep=1
        ))

        # hopbyhop2 с multisplit
        for pos in self.PRIORITY_SPLITS[:3]:
            strategies.append(StrategyConfig(
                name=f"ipv6_hopbyhop2_multisplit_{pos}_R1",
                mode="hopbyhop2,multisplit",
                pos=pos,
                rep=1
            ))

        # destopt с fooling (дополнительные комбинации)
        for pos in ["sniext+1", "midsld"]:
            strategies.append(StrategyConfig(
                name=f"ipv6_destopt_multisplit_{pos}_R1",
                mode="destopt,multisplit",
                pos=pos,
                rep=1
            ))

        return strategies

    @profiler
    def _generate_ipv6_frag_strategies(self) -> List[StrategyConfig]:
        """
        Генерация IPv6 fragment стратегий

        ipfrag1 и ipfrag2 - фрагментация IPv6 пакетов.
        ipfrag1 = первый фрагмент маленький, ipfrag2 = второй фрагмент маленький.
        """
        strategies = []

        # Базовые ipfrag режимы
        for mode in self.IPV6_FRAG_MODES:
            strategies.append(StrategyConfig(
                name=f"ipv6_{mode}_R1",
                mode=mode,
                rep=1
            ))

        # ipfrag с multisplit/multidisorder
        for mode in self.IPV6_FRAG_COMBO:
            if "multisplit" in mode or "multidisorder" in mode:
                for pos in self.PRIORITY_SPLITS[:2]:  # Только приоритетные
                    strategies.append(StrategyConfig(
                        name=f"ipv6_{mode.replace(',', '_')}_{pos}_R1",
                        mode=mode,
                        pos=pos,
                        rep=1
                    ))
            else:
                strategies.append(StrategyConfig(
                    name=f"ipv6_{mode.replace(',', '_')}_R1",
                    mode=mode,
                    rep=1
                ))

        # hopbyhop + ipfrag1 комбинации
        for pos in ["sniext+1", "midsld"]:
            strategies.append(StrategyConfig(
                name=f"ipv6_hopbyhop_ipfrag1_multisplit_{pos}_R1",
                mode="hopbyhop,ipfrag1,multisplit",
                pos=pos,
                rep=1
            ))

        # destopt + ipfrag1 комбинации
        for pos in ["sniext+1", "midsld"]:
            strategies.append(StrategyConfig(
                name=f"ipv6_destopt_ipfrag1_multisplit_{pos}_R1",
                mode="destopt,ipfrag1,multisplit",
                pos=pos,
                rep=1
            ))

        # hopbyhop2 + ipfrag2 (особый случай - двойной hopbyhop + фрагментация)
        strategies.append(StrategyConfig(
            name="ipv6_hopbyhop2_ipfrag2_R1",
            mode="hopbyhop2,ipfrag2",
            rep=1
        ))

        return strategies


# ══════════════════════════════════════════════════════════
#                     SINGLETON
# ══════════════════════════════════════════════════════════

_generator: Optional[StrategyGenerator] = None


@profiler
def get_generator(has_fake_files: bool = False, ultimate_strategies_path: Optional[str] = None,
                  zapret_base: Optional[str] = None) -> StrategyGenerator:
    """Получение singleton экземпляра StrategyGenerator"""
    global _generator
    if _generator is None:
        _generator = StrategyGenerator(has_fake_files, ultimate_strategies_path, zapret_base)
    return _generator
