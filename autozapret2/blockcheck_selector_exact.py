"""
Exact Strategy Selector - Точная генерация ВСЕХ комбинаций blockcheck2.sh

Генерирует ~21,540 тестовых комбинаций для TLS точно как blockcheck2.sh.
Поддерживает ранний выход (first_working) и сбор всех работающих (all_best).

Порядок фаз точно как в blockcheck2.d/standard/:
  15: Misc (tcpseg)
  17: OOB
  20: Multi (multisplit/multidisorder)
  23: SeqOvl
  24: Syndata
  25: Fake (TTL, fooling, autottl)
  30: Faked (fakedsplit/fakeddisorder)
  35: Hostfake
  50: Fake+Multi
  55: Fake+Faked
  60: Fake+Hostfake

Каждая фаза генерирует ВСЕ комбинации без агрегации.
"""

import logging
from dataclasses import dataclass, field
from typing import Generator, List, Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════

@dataclass
class ExactStrategyResult:
    """Результат одной тестовой комбинации"""
    params: str          # Полная строка параметров
    phase: int           # Номер фазы (15, 17, 20, 23, 24, 25, 30, 35, 50, 55, 60)
    name: str            # Описательное имя
    description: str = ""
    has_wssize: bool = False  # Это тест из wssize-прохода


@dataclass
class ExactSelectorState:
    """Состояние селектора для early-break и all_best"""
    found_working: bool = False
    found_strategy_params: str = ""
    found_phase: int = 0
    total_tested: int = 0
    working_strategies: list = field(default_factory=list)  # Для all_best


# ══════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════

MIN_TTL = 1
MAX_TTL = 12
MIN_AUTOTTL_DELTA = 1
MAX_AUTOTTL_DELTA = 5
FAKE_REPEATS = 4

# TLS split positions из 20-multi.sh
SPLITS_TLS = [
    "2", "1", "sniext+1", "sniext+4", "host+1", "midsld",
    "1,midsld", "1,midsld,1220",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"
]

# Fooling methods из def.inc (FOOLINGS46_TCP)
FOOLINGS_TCP = [
    "tcp_md5", "badsum", "tcp_seq=-3000", "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up", "tcp_ts=-1000",
    "tcp_flags_unset=ACK", "tcp_flags_set=SYN"
]

# Wssize prelude
WSSIZE_PRE = "--lua-desync=wssize:wsize=1:scale=6"

# Fake blob
FAKE_DEFAULT_TLS = "fake_default_tls"

# 5 вариантов pktws_fake_https_vary_
FAKE_VARY_NAMES = [
    "fake_blob_fake",
    "fake_blob_zeros",
    "fake_blob_zeros_plus_fake_rnd_dupsid",
    "multisplit_blob_fake_pos2_nodrop",
    "fake_blob_fake_rnd_dupsid_padencap",
]


# ══════════════════════════════════════════════════════════
# EXACT STRATEGY SELECTOR
# ══════════════════════════════════════════════════════════

class ExactStrategySelector:
    """
    EXACT port of blockcheck2.sh strategy generation.
    Generates ALL test combinations (no aggregation).
    Supports early break via state.found_working.
    """

    def __init__(self, protocol: str = "tls12", mode: str = "first_working"):
        """
        Args:
            protocol: "tls12", "tls13", "http", "quic"
            mode: "first_working" или "all_best"
        """
        self.protocol = protocol
        self.mode = mode

    def generate(self, state: Optional[ExactSelectorState] = None) -> Generator[ExactStrategyResult, None, None]:
        """
        Generate ALL strategies in exact blockcheck2.sh order.
        Yields each test combination one by one.
        Supports early break via state.found_working.
        """
        if state is None:
            state = ExactSelectorState()

        if self.protocol in ("tls12", "tls13"):
            yield from self._generate_tls(state)
        elif self.protocol == "http":
            yield from self._generate_http(state)
        elif self.protocol == "quic":
            yield from self._generate_quic(state)

    def _generate_tls(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """TLS (12/13) full generation"""
        # Phase 15: Misc
        yield from self._phase15_misc(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 17: OOB
        yield from self._phase17_oob(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 20: Multi
        yield from self._phase20_multi(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 23: SeqOvl
        yield from self._phase23_seqovl(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 24: Syndata
        yield from self._phase24_syndata(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 25: Fake
        yield from self._phase25_fake(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 30: Faked
        yield from self._phase30_faked(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 35: Hostfake
        yield from self._phase35_hostfake(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 50: Fake+Multi
        yield from self._phase50_fake_multi(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 55: Fake+Faked
        yield from self._phase55_fake_faked(state)
        if state.found_working and self.mode == "first_working":
            return

        # Phase 60: Fake+Hostfake
        yield from self._phase60_fake_hostfake(state)

    def _generate_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """HTTP generation (subset of TLS logic with HTTP-specific params)"""
        # For now, focus on TLS. HTTP uses similar structure but with http_req payload.
        yield from self._phase15_misc_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase17_oob_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase20_multi_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase23_seqovl_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase24_syndata_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase25_fake_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase30_faked_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase35_hostfake_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase50_fake_multi_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase55_fake_faked_http(state)
        if state.found_working and self.mode == "first_working":
            return
        yield from self._phase60_fake_hostfake_http(state)

    def _generate_quic(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """QUIC generation (minimal - QUIC has its own phase 90)"""
        # QUIC tests are in 90-quic.sh, not covered here yet
        pass

    def count_strategies(self) -> int:
        """Count total strategies (exact, no early break)"""
        count = 0
        state = ExactSelectorState()
        for _ in self.generate(state):
            count += 1
        return count

    # ══════════════════════════════════════════════════════════
    # HELPER: yield with state tracking
    # ══════════════════════════════════════════════════════════

    def _yield(self, state: ExactSelectorState, result: ExactStrategyResult) -> Generator[ExactStrategyResult, None, None]:
        """Yield a result and update state counters"""
        state.total_tested += 1
        yield result

    def _yield_with_wssize(self, state: ExactSelectorState, base_params: str, phase: int, name: str, description: str = "") -> Generator[ExactStrategyResult, None, None]:
        """Yield both normal and wssize variants"""
        # Normal
        yield from self._yield(state, ExactStrategyResult(
            params=base_params,
            phase=phase,
            name=name,
            description=description,
            has_wssize=False
        ))
        if state.found_working and self.mode == "first_working":
            return
        # Wssize
        yield from self._yield(state, ExactStrategyResult(
            params=f"{WSSIZE_PRE} {base_params}",
            phase=phase,
            name=f"{name}_wssize",
            description=f"{description} (wssize)",
            has_wssize=True
        ))

    # ══════════════════════════════════════════════════════════
    # PHASE 15: Misc (15-misc.sh)
    # ══════════════════════════════════════════════════════════

    def _phase15_misc(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 15: Misc tcpseg tests
        for repeats in 1 20 100 260:
            pktws_curl_test_update ... tcpseg:pos=0,1:ip_id=rnd:repeats=$repeats
            pktws_curl_test_update ... tcpseg:pos=0,midsld:ip_id=rnd:repeats=$repeats
        """
        repeats_list = [1, 20, 100, 260]
        positions = ["0,1", "0,midsld"]

        for repeats in repeats_list:
            if state.found_working and self.mode == "first_working":
                return
            for pos in positions:
                params = f"--lua-desync=tcpseg:pos={pos}:ip_id=rnd:repeats={repeats} --payload=tls_client_hello"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=15,
                    name=f"tcpseg_pos_{pos.replace(',', '_')}_repeats_{repeats}",
                    description=f"tcpseg at pos={pos}, repeats={repeats}"
                ))
                if state.found_working and self.mode == "first_working":
                    return

    def _phase15_misc_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 15 HTTP variant"""
        repeats_list = [1, 20, 100, 260]
        positions = ["0,method+2", "0,midsld"]

        for repeats in repeats_list:
            if state.found_working and self.mode == "first_working":
                return
            for pos in positions:
                params = f"--lua-desync=tcpseg:pos={pos}:ip_id=rnd:repeats={repeats} --payload=http_req"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=15,
                    name=f"tcpseg_pos_{pos.replace(',', '_')}_repeats_{repeats}",
                    description=f"tcpseg at pos={pos}, repeats={repeats}"
                ))
                if state.found_working and self.mode == "first_working":
                    return

    # ══════════════════════════════════════════════════════════
    # PHASE 17: OOB (17-oob.sh)
    # ══════════════════════════════════════════════════════════

    def _phase17_oob(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 17: OOB tests
        for urp in b 0 2 midsld:
            pktws_curl_test_update ... --in-range=-s1 --lua-desync=oob:urp=$urp
        """
        urp_values = ["b", "0", "2", "midsld"]

        for urp in urp_values:
            if state.found_working and self.mode == "first_working":
                return
            params = f"--in-range=-s1 --lua-desync=oob:urp={urp} --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=17,
                name=f"oob_urp_{urp}",
                description=f"OOB with urp={urp}"
            ))
            if state.found_working and self.mode == "first_working":
                return

    def _phase17_oob_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 17 HTTP variant (same urp values)"""
        urp_values = ["b", "0", "2", "midsld"]

        for urp in urp_values:
            if state.found_working and self.mode == "first_working":
                return
            params = f"--in-range=-s1 --lua-desync=oob:urp={urp} --payload=http_req"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=17,
                name=f"oob_urp_{urp}",
                description=f"OOB with urp={urp}"
            ))
            if state.found_working and self.mode == "first_working":
                return

    # ══════════════════════════════════════════════════════════
    # PHASE 20: Multi (20-multi.sh)
    # ══════════════════════════════════════════════════════════

    def _phase20_multi(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 20: Multi split tests
        First pass: multisplit/multidisorder with all TLS positions
        Second pass: same with wssize pre
        """
        split_funcs = ["multisplit", "multidisorder"]

        # First pass
        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for pos in SPLITS_TLS:
                params = f"--lua-desync={splitf}:pos={pos} --payload=tls_client_hello"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=20,
                    name=f"{splitf}_pos_{pos.replace(',', '_')}",
                    description=f"{splitf} at pos={pos}"
                ))
                if state.found_working and self.mode == "first_working":
                    return

        # Second pass with wssize
        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for pos in SPLITS_TLS:
                params = f"{WSSIZE_PRE} --lua-desync={splitf}:pos={pos} --payload=tls_client_hello"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=20,
                    name=f"{splitf}_pos_{pos.replace(',', '_')}_wssize",
                    description=f"{splitf} at pos={pos} (wssize)",
                    has_wssize=True
                ))
                if state.found_working and self.mode == "first_working":
                    return

    def _phase20_multi_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 20 HTTP variant"""
        split_funcs = ["multisplit", "multidisorder"]
        splits_http = ["method+2", "midsld", "method+2,midsld"]

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for pos in splits_http:
                params = f"--lua-desync={splitf}:pos={pos} --payload=http_req"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=20,
                    name=f"{splitf}_pos_{pos.replace(',', '_')}",
                    description=f"{splitf} at pos={pos}"
                ))
                if state.found_working and self.mode == "first_working":
                    return

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for pos in splits_http:
                params = f"{WSSIZE_PRE} --lua-desync={splitf}:pos={pos} --payload=http_req"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=20,
                    name=f"{splitf}_pos_{pos.replace(',', '_')}_wssize",
                    description=f"{splitf} at pos={pos} (wssize)",
                    has_wssize=True
                ))
                if state.found_working and self.mode == "first_working":
                    return

    # ══════════════════════════════════════════════════════════
    # PHASE 23: SeqOvl (23-seqovl.sh)
    # ══════════════════════════════════════════════════════════

    def _phase23_seqovl(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 23: SeqOvl tests
        Block 1: tcpseg+seqovl (3 tests)
        Block 2: multisplit+seqovl (4 positions x 3 variants)
        Block 3: multidisorder+seqovl (5 positions x 2 variants)
        Then repeat all with wssize
        """
        # Block 1: tcpseg+seqovl (3 tests)
        tcpseg_seqovl_tests = [
            (
                "--lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop --payload=tls_client_hello",
                "tcpseg_seqovl_1_drop"
            ),
            (
                f"--lua-desync=tcpseg:pos=0,-1:seqovl=#{FAKE_DEFAULT_TLS}:seqovl_pattern={FAKE_DEFAULT_TLS} --lua-desync=drop --payload=tls_client_hello",
                "tcpseg_seqovl_fake_drop"
            ),
            (
                "--lua-desync=luaexec:code=desync.patmod=tls_mod(fake_default_tls,'rnd,dupsid,padencap',desync.reasm_data) --lua-desync=tcpseg:pos=0,-1:seqovl=#patmod:seqovl_pattern=patmod --lua-desync=drop --payload=tls_client_hello",
                "tcpseg_seqovl_patmod_drop"
            ),
        ]

        for params, name in tcpseg_seqovl_tests:
            if state.found_working and self.mode == "first_working":
                return
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=name,
                description=f"tcpseg+seqovl: {name}"
            ))
            if state.found_working and self.mode == "first_working":
                return

        # Block 2: multisplit+seqovl (4 positions x 3 variants)
        multisplit_seqovl_positions = ["10", "10,sniext+1", "10,sniext+4", "10,midsld"]

        for pos in multisplit_seqovl_positions:
            if state.found_working and self.mode == "first_working":
                return
            # Variant 1: seqovl=1
            params = f"--lua-desync=multisplit:pos={pos}:seqovl=1 --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=f"multisplit_seqovl_1_pos_{pos.replace(',', '_')}",
                description=f"multisplit+seqovl=1 at pos={pos}"
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Variant 2: seqovl with fake_default_tls pattern
            params = f"--lua-desync=multisplit:pos={pos}:seqovl=#{FAKE_DEFAULT_TLS}:seqovl_pattern={FAKE_DEFAULT_TLS} --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=f"multisplit_seqovl_fake_pos_{pos.replace(',', '_')}",
                description=f"multisplit+seqovl=fake at pos={pos}"
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Variant 3: seqovl with patmod
            params = f"--lua-desync=multisplit:pos={pos}:seqovl=#patmod:seqovl_pattern=patmod --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=f"multisplit_seqovl_patmod_pos_{pos.replace(',', '_')}",
                description=f"multisplit+seqovl=patmod at pos={pos}"
            ))
            if state.found_working and self.mode == "first_working":
                return

        # Block 3: multidisorder+seqovl (5 positions x 2 variants)
        # split pairs: (seqovl_pos, split_pos)
        multidisorder_seqovl_pairs = [
            ("2", "1"),
            ("sniext+1", "sniext"),
            ("sniext+4", "sniext+3"),
            ("midsld", "midsld-1"),
            ("2,midsld", "1"),
        ]

        for seqovl_pos, split_pos in multidisorder_seqovl_pairs:
            if state.found_working and self.mode == "first_working":
                return
            # Variant 1: basic seqovl
            params = f"--lua-desync=multidisorder:pos={seqovl_pos}:seqovl={split_pos} --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=f"multidisorder_seqovl_{split_pos.replace(',', '_')}_pos_{seqovl_pos.replace(',', '_')}",
                description=f"multidisorder seqovl={split_pos} at pos={seqovl_pos}"
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Variant 2: seqovl with fake_default_tls pattern
            params = f"--lua-desync=multidisorder:pos={seqovl_pos}:seqovl={split_pos}:seqovl_pattern={FAKE_DEFAULT_TLS} --payload=tls_client_hello"
            yield from self._yield(state, ExactStrategyResult(
                params=params,
                phase=23,
                name=f"multidisorder_seqovl_fake_{split_pos.replace(',', '_')}_pos_{seqovl_pos.replace(',', '_')}",
                description=f"multidisorder seqovl=fake at pos={seqovl_pos}"
            ))
            if state.found_working and self.mode == "first_working":
                return

        # Second pass with wssize - repeat ALL tests above
        # tcpseg+seqovl
        for params, name in tcpseg_seqovl_tests:
            if state.found_working and self.mode == "first_working":
                return
            yield from self._yield(state, ExactStrategyResult(
                params=f"{WSSIZE_PRE} {params}",
                phase=23,
                name=f"{name}_wssize",
                description=f"tcpseg+seqovl: {name} (wssize)",
                has_wssize=True
            ))
            if state.found_working and self.mode == "first_working":
                return

        # multisplit+seqovl with wssize
        for pos in multisplit_seqovl_positions:
            if state.found_working and self.mode == "first_working":
                return
            for variant_params_suffix, variant_name in [
                (f"multisplit:pos={pos}:seqovl=1 --payload=tls_client_hello", f"multisplit_seqovl_1_pos_{pos.replace(',', '_')}_wssize"),
                (f"multisplit:pos={pos}:seqovl=#{FAKE_DEFAULT_TLS}:seqovl_pattern={FAKE_DEFAULT_TLS} --payload=tls_client_hello", f"multisplit_seqovl_fake_pos_{pos.replace(',', '_')}_wssize"),
                (f"multisplit:pos={pos}:seqovl=#patmod:seqovl_pattern=patmod --payload=tls_client_hello", f"multisplit_seqovl_patmod_pos_{pos.replace(',', '_')}_wssize"),
            ]:
                params = f"{WSSIZE_PRE} --lua-desync={variant_params_suffix}"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=23,
                    name=variant_name,
                    description=f"multisplit+seqovl (wssize)",
                    has_wssize=True
                ))
                if state.found_working and self.mode == "first_working":
                    return

        # multidisorder+seqovl with wssize
        for seqovl_pos, split_pos in multidisorder_seqovl_pairs:
            if state.found_working and self.mode == "first_working":
                return
            for variant_params_suffix, variant_name in [
                (f"multidisorder:pos={seqovl_pos}:seqovl={split_pos} --payload=tls_client_hello", f"multidisorder_seqovl_{split_pos.replace(',', '_')}_pos_{seqovl_pos.replace(',', '_')}_wssize"),
                (f"multidisorder:pos={seqovl_pos}:seqovl={split_pos}:seqovl_pattern={FAKE_DEFAULT_TLS} --payload=tls_client_hello", f"multidisorder_seqovl_fake_{split_pos.replace(',', '_')}_pos_{seqovl_pos.replace(',', '_')}_wssize"),
            ]:
                params = f"{WSSIZE_PRE} --lua-desync={variant_params_suffix}"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=23,
                    name=variant_name,
                    description=f"multidisorder+seqovl (wssize)",
                    has_wssize=True
                ))
                if state.found_working and self.mode == "first_working":
                    return

    def _phase23_seqovl_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 23 HTTP variant"""
        # HTTP seqovl tests
        pat = "fake_default_http"

        # tcpseg+seqovl
        params = "--lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop --payload=http_req"
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=23, name="tcpseg_seqovl_1_drop_http"
        ))
        if state.found_working and self.mode == "first_working":
            return

        params = f"--lua-desync=tcpseg:pos=0,-1:seqovl=#{pat}:seqovl_pattern={pat} --lua-desync=drop --payload=http_req"
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=23, name="tcpseg_seqovl_fake_drop_http"
        ))
        if state.found_working and self.mode == "first_working":
            return

        # multisplit+seqovl
        for split in ["method+2", "method+2,midsld"]:
            if state.found_working and self.mode == "first_working":
                return
            params = f"--lua-desync=multisplit:pos={split}:seqovl=1 --payload=http_req"
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=23, name=f"multisplit_seqovl_1_pos_{split.replace(',', '_')}_http"
            ))
            if state.found_working and self.mode == "first_working":
                return

            params = f"--lua-desync=multisplit:pos={split}:seqovl=#{pat}:seqovl_pattern={pat} --payload=http_req"
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=23, name=f"multisplit_seqovl_fake_pos_{split.replace(',', '_')}_http"
            ))
            if state.found_working and self.mode == "first_working":
                return

        # multidisorder+seqovl
        for split in ["method+2 method+1", "midsld midsld-1", "method+2,midsld method+1"]:
            parts = split.split()
            f2 = parts[0]
            f = parts[1]
            if state.found_working and self.mode == "first_working":
                return
            params = f"--lua-desync=multidisorder:pos={f2}:seqovl={f} --payload=http_req"
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=23, name=f"multidisorder_seqovl_{f}_pos_{f2}_http"
            ))
            if state.found_working and self.mode == "first_working":
                return

            params = f"--lua-desync=multidisorder:pos={f2}:seqovl={f}:seqovl_pattern={pat} --payload=http_req"
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=23, name=f"multidisorder_seqovl_fake_{f}_pos_{f2}_http"
            ))
            if state.found_working and self.mode == "first_working":
                return

    # ══════════════════════════════════════════════════════════
    # PHASE 24: Syndata (24-syndata.sh)
    # ══════════════════════════════════════════════════════════

    def _phase24_syndata(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 24: Syndata tests
        for split in '' multisplit multidisorder:
            for blob in '' ':blob=0x1603' ':blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni' ':blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com':
                pktws_curl_test_update ... --lua-desync=syndata{blob} {split:+$PAYLOAD --lua-desync=$split}
        """
        splits = ["", "multisplit", "multidisorder"]
        blobs = [
            ("", "syndata"),
            (":blob=0x1603", "syndata_blob_0x1603"),
            (f":blob={FAKE_DEFAULT_TLS}:tls_mod=rnd,dupsid,rndsni", "syndata_blob_fake_rnd_dupsid_rndsni"),
            (f":blob={FAKE_DEFAULT_TLS}:tls_mod=rnd,dupsid,sni=google.com", "syndata_blob_fake_rnd_dupsid_sni_google"),
        ]

        for split in splits:
            if state.found_working and self.mode == "first_working":
                return
            for blob_suffix, blob_name in blobs:
                base = f"--lua-desync=syndata{blob_suffix}"
                if split:
                    params = f"{base} --lua-desync={split} --payload=tls_client_hello"
                else:
                    params = base
                name = f"{blob_name}" if not split else f"{blob_name}_{split}"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=24,
                    name=name,
                    description=f"syndata{blob_suffix}" + (f" + {split}" if split else "")
                ))
                if state.found_working and self.mode == "first_working":
                    return

        # Second pass with wssize
        for split in splits:
            if state.found_working and self.mode == "first_working":
                return
            for blob_suffix, blob_name in blobs:
                base = f"--lua-desync=syndata{blob_suffix}"
                if split:
                    params = f"{WSSIZE_PRE} {base} --lua-desync={split} --payload=tls_client_hello"
                else:
                    params = f"{WSSIZE_PRE} {base}"
                name = f"{blob_name}_wssize" if not split else f"{blob_name}_{split}_wssize"
                yield from self._yield(state, ExactStrategyResult(
                    params=params,
                    phase=24,
                    name=name,
                    description=f"syndata{blob_suffix}" + (f" + {split}" if split else "") + " (wssize)",
                    has_wssize=True
                ))
                if state.found_working and self.mode == "first_working":
                    return

    def _phase24_syndata_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 24 HTTP variant"""
        splits = ["", "multisplit", "multidisorder"]
        blobs = [
            ("", "syndata"),
            (":blob=fake_default_http", "syndata_blob_fake_http"),
        ]

        for split in splits:
            if state.found_working and self.mode == "first_working":
                return
            for blob_suffix, blob_name in blobs:
                base = f"--lua-desync=syndata{blob_suffix}"
                if split:
                    params = f"{base} --lua-desync={split} --payload=http_req"
                else:
                    params = base
                name = f"{blob_name}" if not split else f"{blob_name}_{split}"
                yield from self._yield(state, ExactStrategyResult(
                    params=params, phase=24, name=name
                ))
                if state.found_working and self.mode == "first_working":
                    return

    # ══════════════════════════════════════════════════════════
    # PHASE 25: Fake (25-fake.sh) - THE BIGGEST
    # ══════════════════════════════════════════════════════════

    def _phase25_fake(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 25: Fake tests (TTL, fooling, autottl)
        Three loops: TTL, fooling, autottl
        Each uses pktws_fake_https_vary_ which yields 5 variants
        Then repeat all with wssize
        """
        # TTL loop
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from self._fake_https_vary(
                    state, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Fooling loop
        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from self._fake_https_vary(
                state, fooling, "", "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}"
            )
            if state.found_working and self.mode == "first_working":
                return

        # AutoTTL loop
        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from self._fake_https_vary(
                    state, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Second pass with wssize - repeat ALL above
        # TTL loop wssize
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from self._fake_https_vary(
                    state, f"ip4_ttl={ttl}", WSSIZE_PRE, f_suffix, f"_ttl{ttl}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Fooling loop wssize
        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from self._fake_https_vary(
                state, fooling, WSSIZE_PRE, "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize", has_wssize=True
            )
            if state.found_working and self.mode == "first_working":
                return

        # AutoTTL loop wssize
        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from self._fake_https_vary(
                    state, f"ip4_autottl=-{delta},3-20", WSSIZE_PRE, f_suffix, f"_autottl_{delta}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

    def _fake_https_vary(self, state: ExactSelectorState, fooling: str, pre: str, post: str,
                         name_suffix: str, has_wssize: bool = False,
                         include_md5_dup: bool = True) -> Generator[ExactStrategyResult, None, None]:
        """
        pktws_fake_https_vary_ - 5 variants of fake tests
        Then pktws_fake_https_vary adds MD5 duplicate if fooling contains tcp_md5
        """
        phase = 25
        payload = "--payload=tls_client_hello"

        # Variant 1: fake:blob=fake_default_tls:$fooling:repeats=4
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_default_tls{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake blob={FAKE_DEFAULT_TLS} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 2: fake:blob=0x00000000:$fooling:repeats=4
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_zeros{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake blob=0x00000000 {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 3: fake:blob=0x00000000:$fooling + fake:blob=fake_default_tls:$fooling:tls_mod=rnd,dupsid
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid:repeats={FAKE_REPEATS} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_zeros_plus_fake_rnd_dupsid{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake blob=0x00000000 + fake blob={FAKE_DEFAULT_TLS} rnd,dupsid {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 4: multisplit:blob=fake_default_tls:$fooling:pos=2:nodrop:repeats=4
        params = f"{pre} {payload} --lua-desync=multisplit:blob={FAKE_DEFAULT_TLS}:{fooling}:pos=2:nodrop:repeats={FAKE_REPEATS} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"multisplit_fake_pos2_nodrop{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"multisplit blob={FAKE_DEFAULT_TLS} pos=2 nodrop {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 5: fake:blob=fake_default_tls:$fooling:tls_mod=rnd,dupsid,padencap:repeats=4
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats={FAKE_REPEATS} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_default_tls_rnd_dupsid_padencap{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake blob={FAKE_DEFAULT_TLS} rnd,dupsid,padencap {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # MD5 duplicate: if fooling contains "tcp_md5", add extra test
        if include_md5_dup and "tcp_md5" in fooling:
            params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_default_tls{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake blob={FAKE_DEFAULT_TLS} {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Also MD5 dup for variant 2
            params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} {post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_zeros{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake blob=0x00000000 {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Also MD5 dup for variant 3
            params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid:repeats={FAKE_REPEATS} {post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_zeros_plus_fake_rnd_dupsid{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake blob=0x00000000 + fake rnd,dupsid {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Also MD5 dup for variant 4
            params = f"{pre} {payload} --lua-desync=multisplit:blob={FAKE_DEFAULT_TLS}:{fooling}:pos=2:nodrop:repeats={FAKE_REPEATS} {post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"multisplit_fake_pos2_nodrop{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"multisplit blob={FAKE_DEFAULT_TLS} pos=2 nodrop {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

            # Also MD5 dup for variant 5
            params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats={FAKE_REPEATS} {post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_default_tls_rnd_dupsid_padencap{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake blob={FAKE_DEFAULT_TLS} rnd,dupsid,padencap {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

    def _phase25_fake_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 25 HTTP variant"""
        fake_http = "fake_default_http"

        # TTL loop
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for ff in [fake_http, "0x00000000"]:
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} {f_suffix}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=25,
                        name=f"fake_http_{ff.replace('.', '_')}_{ttl}{f_name}",
                        description=f"fake HTTP blob={ff} ttl={ttl}"
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        # Fooling loop
        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            for ff in [fake_http, "0x00000000"]:
                if state.found_working and self.mode == "first_working":
                    return
                params = f"--payload=http_req --lua-desync=fake:blob={ff}:{fooling}:repeats={FAKE_REPEATS}"
                yield from self._yield(state, ExactStrategyResult(
                    params=params, phase=25,
                    name=f"fake_http_{ff.replace('.', '_')}_{fooling.replace('=', '_')}",
                    description=f"fake HTTP blob={ff} {fooling}"
                ))
                if state.found_working and self.mode == "first_working":
                    return

                # MD5 dup
                if "tcp_md5" in fooling:
                    params = f"--payload=http_req --lua-desync=fake:blob={ff}:{fooling}:repeats={FAKE_REPEATS} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=25,
                        name=f"fake_http_{ff.replace('.', '_')}_{fooling.replace('=', '_')}_md5dup",
                        description=f"fake HTTP blob={ff} {fooling} + MD5 dup"
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        # AutoTTL loop
        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for ff in [fake_http, "0x00000000"]:
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} {f_suffix}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=25,
                        name=f"fake_http_{ff.replace('.', '_')}_autottl_{delta}{f_name}",
                        description=f"fake HTTP blob={ff} autottl=-{delta}"
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

    # ══════════════════════════════════════════════════════════
    # PHASE 30: Faked (30-faked.sh)
    # ══════════════════════════════════════════════════════════

    def _phase30_faked(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 30: Faked tests (fakedsplit/fakeddisorder)
        For each splitf in [fakedsplit, fakeddisorder]:
            TTL loop: for ttl in 1..12, for f in ['', pktmod], for pos in SPLITS_TLS
            Fooling loop: for fooling in FOOLINGS_TCP, for pos in SPLITS_TLS
            AutoTTL loop: for delta in 1..5, for f in ['', pktmod], for pos in SPLITS_TLS
        Then repeat with wssize
        """
        split_funcs = ["fakedsplit", "fakeddisorder"]

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return

            # TTL loop
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in SPLITS_TLS:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} --payload=tls_client_hello {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_ttl{ttl}{f_name}",
                            description=f"{splitf} at pos={pos} ttl={ttl}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            # Fooling loop
            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for pos in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"--lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:{fooling} --payload=tls_client_hello"
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=30,
                        name=f"{splitf}_pos_{pos.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}",
                        description=f"{splitf} at pos={pos} {fooling}"
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

                    # MD5 dup
                    if "tcp_md5" in fooling:
                        params = f"--lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:{fooling}:repeats={FAKE_REPEATS} --payload=tls_client_hello --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_md5dup",
                            description=f"{splitf} at pos={pos} {fooling} + MD5 dup"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            # AutoTTL loop
            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in SPLITS_TLS:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} --payload=tls_client_hello {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_autottl_{delta}{f_name}",
                            description=f"{splitf} at pos={pos} autottl=-{delta}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

        # Second pass with wssize
        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return

            # TTL loop wssize
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in SPLITS_TLS:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"{WSSIZE_PRE} --lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} --payload=tls_client_hello {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_ttl{ttl}{f_name}_wssize",
                            description=f"{splitf} at pos={pos} ttl={ttl} (wssize)",
                            has_wssize=True
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            # Fooling loop wssize
            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for pos in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"{WSSIZE_PRE} --lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:{fooling} --payload=tls_client_hello"
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=30,
                        name=f"{splitf}_pos_{pos.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize",
                        description=f"{splitf} at pos={pos} {fooling} (wssize)",
                        has_wssize=True
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

                    if "tcp_md5" in fooling:
                        params = f"{WSSIZE_PRE} --lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:{fooling}:repeats={FAKE_REPEATS} --payload=tls_client_hello --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_md5dup_wssize",
                            description=f"{splitf} at pos={pos} {fooling} + MD5 dup (wssize)",
                            has_wssize=True
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            # AutoTTL loop wssize
            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [
                    ("", ""),
                    (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                ]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in SPLITS_TLS:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"{WSSIZE_PRE} --lua-desync={splitf}:blob={FAKE_DEFAULT_TLS}:pos={pos}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} --payload=tls_client_hello {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_pos_{pos.replace(',', '_')}_autottl_{delta}{f_name}_wssize",
                            description=f"{splitf} at pos={pos} autottl=-{delta} (wssize)",
                            has_wssize=True
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

    def _phase30_faked_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 30 HTTP variant"""
        split_funcs = ["fakedsplit", "fakeddisorder"]
        splits_http = ["method+2", "midsld", "method+2,midsld"]

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in splits_http:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--lua-desync={splitf}:blob=fake_default_http:pos={pos}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} --payload=http_req {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_http_pos_{pos.replace(',', '_')}_ttl{ttl}{f_name}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for pos in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"--lua-desync={splitf}:blob=fake_default_http:pos={pos}:{fooling} --payload=http_req"
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=30,
                        name=f"{splitf}_http_pos_{pos.replace(',', '_')}_{fooling.replace('=', '_')}"
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                    if state.found_working and self.mode == "first_working":
                        return
                    for pos in splits_http:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--lua-desync={splitf}:blob=fake_default_http:pos={pos}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} --payload=http_req {f_suffix}".strip()
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=30,
                            name=f"{splitf}_http_pos_{pos.replace(',', '_')}_autottl_{delta}{f_name}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

    # ══════════════════════════════════════════════════════════
    # PHASE 35: Hostfake (35-hostfake.sh)
    # ══════════════════════════════════════════════════════════

    def _phase35_hostfake(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 35: Hostfake tests
        pktws_hostfake_vary_ yields 6 variants x 2 disorder = 12 tests per fooling
        Then TTL, fooling, autottl loops
        Then repeat with wssize
        """
        host_positions = ["midsld", "host", "sniext"]

        def _hostfake_vary(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            """pktws_hostfake_vary_ - 6 variants x 2 disorder = 12 tests"""
            for disorder in ["", "disorder_after:"]:
                if state.found_working and self.mode == "first_working":
                    return
                disorder_label = disorder.rstrip(":") if disorder else "normal"

                # 6 variants
                variants = [
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_{disorder_label}"),
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake1:{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_nofake1_{disorder_label}"),
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake2:{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_nofake2_{disorder_label}"),
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_midhost_{disorder_label}"),
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake1:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_nofake1_midhost_{disorder_label}"),
                    (f"hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake2:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"hostfake_nofake2_midhost_{disorder_label}"),
                ]

                for params_suffix, name_prefix in variants:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"{pre} --payload=tls_client_hello --lua-desync={params_suffix} {post}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=35,
                        name=f"{name_prefix}{name_suffix}",
                        description=f"hostfakesplit {name_prefix} {fooling}",
                        has_wssize=has_wssize
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        def _hostfake_vary_with_md5(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            """pktws_hostfake_vary - calls vary_ then adds MD5 dup if tcp_md5"""
            yield from _hostfake_vary(state, fooling, pre, post, name_suffix, has_wssize)
            if state.found_working and self.mode == "first_working":
                return

            if "tcp_md5" in fooling:
                md5_post = f"{post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
                yield from _hostfake_vary(state, fooling, pre, md5_post, f"{name_suffix}_md5dup", has_wssize)

        # TTL loop
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_with_md5(
                    state, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Fooling loop
        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _hostfake_vary_with_md5(
                state, fooling, "", "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}"
            )
            if state.found_working and self.mode == "first_working":
                return

        # AutoTTL loop
        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_with_md5(
                    state, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Second pass with wssize
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_with_md5(
                    state, f"ip4_ttl={ttl}", WSSIZE_PRE, f_suffix, f"_ttl{ttl}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _hostfake_vary_with_md5(
                state, fooling, WSSIZE_PRE, "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize", has_wssize=True
            )
            if state.found_working and self.mode == "first_working":
                return

        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [
                ("", ""),
                (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
            ]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_with_md5(
                    state, f"ip4_autottl=-{delta},3-20", WSSIZE_PRE, f_suffix, f"_autottl_{delta}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

    def _phase35_hostfake_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 35 HTTP variant"""
        def _hostfake_vary_http(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            for disorder in ["", "disorder_after:"]:
                if state.found_working and self.mode == "first_working":
                    return
                disorder_label = disorder.rstrip(":") if disorder else "normal"
                variants = [
                    (f"hostfakesplit:host=example.com:{disorder}{fooling}:repeats={FAKE_REPEATS}", f"hostfake_{disorder_label}"),
                    (f"hostfakesplit:host=example.com:{disorder}nofake1:{fooling}:repeats={FAKE_REPEATS}", f"hostfake_nofake1_{disorder_label}"),
                    (f"hostfakesplit:host=example.com:{disorder}nofake2:{fooling}:repeats={FAKE_REPEATS}", f"hostfake_nofake2_{disorder_label}"),
                    (f"hostfakesplit:host=example.com:{disorder}midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"hostfake_midhost_{disorder_label}"),
                    (f"hostfakesplit:host=example.com:{disorder}nofake1:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"hostfake_nofake1_midhost_{disorder_label}"),
                    (f"hostfakesplit:host=example.com:{disorder}nofake2:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"hostfake_nofake2_midhost_{disorder_label}"),
                ]
                for params_suffix, name_prefix in variants:
                    if state.found_working and self.mode == "first_working":
                        return
                    params = f"{pre} --payload=http_req --lua-desync={params_suffix} {post}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=params, phase=35,
                        name=f"{name_prefix}{name_suffix}", has_wssize=has_wssize
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_http(state, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}")
                if state.found_working and self.mode == "first_working":
                    return

        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _hostfake_vary_http(state, fooling, "", "", f"_{fooling.replace('=', '_')}")
            if state.found_working and self.mode == "first_working":
                return

        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _hostfake_vary_http(state, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}")
                if state.found_working and self.mode == "first_working":
                    return

    # ══════════════════════════════════════════════════════════
    # PHASE 50: Fake+Multi (50-fake-multi.sh)
    # ══════════════════════════════════════════════════════════

    def _phase50_fake_multi(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 50: Fake + Multi split
        Same structure as fake.sh but each test is combined with multisplit/multidisorder
        For each splitf in [multisplit, multidisorder]:
            TTL loop: for ttl, for split in SPLITS_TLS, for f in ['', pktmod] -> pktws_fake_https_vary
            Fooling loop: for fooling, for split in SPLITS_TLS -> pktws_fake_https_vary
            AutoTTL loop: for delta, for split in SPLITS_TLS, for f in ['', pktmod] -> pktws_fake_https_vary
        """
        split_funcs = ["multisplit", "multidisorder"]

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return

            # TTL loop
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [
                        ("", ""),
                        (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                    ]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_multi(
                            state, splitf, split, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}"
                        )
                        if state.found_working and self.mode == "first_working":
                            return

            # Fooling loop
            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    yield from self._fake_https_vary_multi(
                        state, splitf, split, fooling, "", "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}"
                    )
                    if state.found_working and self.mode == "first_working":
                        return

            # AutoTTL loop
            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [
                        ("", ""),
                        (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1"),
                    ]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_multi(
                            state, splitf, split, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}"
                        )
                        if state.found_working and self.mode == "first_working":
                            return

        # Second pass with wssize
        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return

            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_multi(
                            state, splitf, split, f"ip4_ttl={ttl}", WSSIZE_PRE, f_suffix, f"_ttl{ttl}{f_name}_wssize", has_wssize=True
                        )
                        if state.found_working and self.mode == "first_working":
                            return

            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    yield from self._fake_https_vary_multi(
                        state, splitf, split, fooling, WSSIZE_PRE, "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize", has_wssize=True
                    )
                    if state.found_working and self.mode == "first_working":
                        return

            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_multi(
                            state, splitf, split, f"ip4_autottl=-{delta},3-20", WSSIZE_PRE, f_suffix, f"_autottl_{delta}{f_name}_wssize", has_wssize=True
                        )
                        if state.found_working and self.mode == "first_working":
                            return

    def _fake_https_vary_multi(self, state: ExactStrategyState, splitf: str, split: str,
                               fooling: str, pre: str, post: str, name_suffix: str,
                               has_wssize: bool = False) -> Generator[ExactStrategyResult, None, None]:
        """
        pktws_fake_https_vary_ for fake+multi - 5 variants with splitf:pos=$split appended
        """
        phase = 50
        payload = "--payload=tls_client_hello"
        split_suffix = f"--lua-desync={splitf}:pos={split}"

        # Variant 1
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_multi_{splitf}_{split.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 2
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_multi_{splitf}_{split.replace(',', '_')}_zeros_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob=0x00000000 pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 3
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_multi_{splitf}_{split.replace(',', '_')}_zeros_plus_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob=0x00000000+fake rnd,dupsid pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 4
        params = f"{pre} {payload} --lua-desync=multisplit:blob={FAKE_DEFAULT_TLS}:{fooling}:pos=2:nodrop:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_multi_{splitf}_{split.replace(',', '_')}_ms_pos2_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} multisplit pos=2 nodrop pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 5
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_multi_{splitf}_{split.replace(',', '_')}_padencap_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} rnd,dupsid,padencap pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # MD5 dup
        if "tcp_md5" in fooling:
            md5_post = f"{post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            # Variant 1 md5
            params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {md5_post}".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_multi_{splitf}_{split.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} pos={split} {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

    def _phase50_fake_multi_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 50 HTTP variant"""
        split_funcs = ["multisplit", "multidisorder"]
        splits_http = ["method+2", "midsld", "method+2,midsld"]
        fake_http = "fake_default_http"

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                            if state.found_working and self.mode == "first_working":
                                return
                            params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split} {f_suffix}".strip()
                            yield from self._yield(state, ExactStrategyResult(
                                params=params, phase=50,
                                name=f"fake_multi_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_{ttl}{f_name}"
                            ))
                            if state.found_working and self.mode == "first_working":
                                return

            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--payload=http_req --lua-desync=fake:blob={ff}:{fooling}:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split}"
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=50,
                            name=f"fake_multi_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_{fooling.replace('=', '_')}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                            if state.found_working and self.mode == "first_working":
                                return
                            params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split} {f_suffix}".strip()
                            yield from self._yield(state, ExactStrategyResult(
                                params=params, phase=50,
                                name=f"fake_multi_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_autottl_{delta}{f_name}"
                            ))
                            if state.found_working and self.mode == "first_working":
                                return

    # ══════════════════════════════════════════════════════════
    # PHASE 55: Fake+Faked (55-fake-faked.sh)
    # ══════════════════════════════════════════════════════════

    def _phase55_fake_faked(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 55: Fake + Faked
        Same as fake+multi but with fakedsplit/fakeddisorder
        """
        split_funcs = ["fakedsplit", "fakeddisorder"]

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return

            # TTL loop
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_faked(
                            state, splitf, split, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}"
                        )
                        if state.found_working and self.mode == "first_working":
                            return

            # Fooling loop
            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    yield from self._fake_https_vary_faked(
                        state, splitf, split, fooling, "", "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}"
                    )
                    if state.found_working and self.mode == "first_working":
                        return

            # AutoTTL loop
            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_faked(
                            state, splitf, split, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}"
                        )
                        if state.found_working and self.mode == "first_working":
                            return

        # Second pass with wssize
        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_faked(
                            state, splitf, split, f"ip4_ttl={ttl}", WSSIZE_PRE, f_suffix, f"_ttl{ttl}{f_name}_wssize", has_wssize=True
                        )
                        if state.found_working and self.mode == "first_working":
                            return

            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    yield from self._fake_https_vary_faked(
                        state, splitf, split, fooling, WSSIZE_PRE, "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize", has_wssize=True
                    )
                    if state.found_working and self.mode == "first_working":
                        return

            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in SPLITS_TLS:
                    if state.found_working and self.mode == "first_working":
                        return
                    for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                        if state.found_working and self.mode == "first_working":
                            return
                        yield from self._fake_https_vary_faked(
                            state, splitf, split, f"ip4_autottl=-{delta},3-20", WSSIZE_PRE, f_suffix, f"_autottl_{delta}{f_name}_wssize", has_wssize=True
                        )
                        if state.found_working and self.mode == "first_working":
                            return

    def _fake_https_vary_faked(self, state: ExactSelectorState, splitf: str, split: str,
                               fooling: str, pre: str, post: str, name_suffix: str,
                               has_wssize: bool = False) -> Generator[ExactStrategyResult, None, None]:
        """
        pktws_fake_https_vary_ for fake+faked - 5 variants with faked splitf:pos=$split:$fooling appended
        """
        phase = 55
        payload = "--payload=tls_client_hello"
        split_suffix = f"--lua-desync={splitf}:pos={split}:{fooling}"

        # Variant 1
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_faked_{splitf}_{split.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 2
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_faked_{splitf}_{split.replace(',', '_')}_zeros_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob=0x00000000 pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 3
        params = f"{pre} {payload} --lua-desync=fake:blob=0x00000000:{fooling}:repeats={FAKE_REPEATS} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_faked_{splitf}_{split.replace(',', '_')}_zeros_plus_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob=0x00000000+fake rnd,dupsid pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 4
        params = f"{pre} {payload} --lua-desync=multisplit:blob={FAKE_DEFAULT_TLS}:{fooling}:pos=2:nodrop:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_faked_{splitf}_{split.replace(',', '_')}_ms_pos2_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} multisplit pos=2 nodrop pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # Variant 5
        params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats={FAKE_REPEATS} {split_suffix} {post}".strip()
        yield from self._yield(state, ExactStrategyResult(
            params=params, phase=phase,
            name=f"fake_faked_{splitf}_{split.replace(',', '_')}_padencap_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}",
            description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} rnd,dupsid,padencap pos={split} {fooling}",
            has_wssize=has_wssize
        ))
        if state.found_working and self.mode == "first_working":
            return

        # MD5 dup
        if "tcp_md5" in fooling:
            md5_post = f"{post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
            params = f"{pre} {payload} --lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS} {split_suffix} {md5_post}".strip()
            yield from self._yield(state, ExactStrategyResult(
                params=params, phase=phase,
                name=f"fake_faked_{splitf}_{split.replace(',', '_')}_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}{name_suffix}_md5dup",
                description=f"fake+{splitf} blob={FAKE_DEFAULT_TLS} pos={split} {fooling} + MD5 dup",
                has_wssize=has_wssize
            ))
            if state.found_working and self.mode == "first_working":
                return

    def _phase55_fake_faked_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 55 HTTP variant"""
        split_funcs = ["fakedsplit", "fakeddisorder"]
        splits_http = ["method+2", "midsld", "method+2,midsld"]
        fake_http = "fake_default_http"

        for splitf in split_funcs:
            if state.found_working and self.mode == "first_working":
                return
            for ttl in range(MIN_TTL, MAX_TTL + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                            if state.found_working and self.mode == "first_working":
                                return
                            params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split}:ip4_ttl={ttl}:repeats={FAKE_REPEATS} {f_suffix}".strip()
                            yield from self._yield(state, ExactStrategyResult(
                                params=params, phase=55,
                                name=f"fake_faked_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_{ttl}{f_name}"
                            ))
                            if state.found_working and self.mode == "first_working":
                                return

            for fooling in FOOLINGS_TCP:
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        params = f"--payload=http_req --lua-desync=fake:blob={ff}:{fooling}:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split}:{fooling}:repeats={FAKE_REPEATS}"
                        yield from self._yield(state, ExactStrategyResult(
                            params=params, phase=55,
                            name=f"fake_faked_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_{fooling.replace('=', '_')}"
                        ))
                        if state.found_working and self.mode == "first_working":
                            return

            for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
                if state.found_working and self.mode == "first_working":
                    return
                for split in splits_http:
                    if state.found_working and self.mode == "first_working":
                        return
                    for ff in [fake_http, "0x00000000"]:
                        if state.found_working and self.mode == "first_working":
                            return
                        for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                            if state.found_working and self.mode == "first_working":
                                return
                            params = f"--payload=http_req --lua-desync=fake:blob={ff}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} --lua-desync={splitf}:pos={split}:ip4_autottl=-{delta},3-20:repeats={FAKE_REPEATS} {f_suffix}".strip()
                            yield from self._yield(state, ExactStrategyResult(
                                params=params, phase=55,
                                name=f"fake_faked_http_{splitf}_{split.replace(',', '_')}_{ff.replace('.', '_')}_autottl_{delta}{f_name}"
                            ))
                            if state.found_working and self.mode == "first_working":
                                return

    # ══════════════════════════════════════════════════════════
    # PHASE 60: Fake+Hostfake (60-fake-hostfake.sh)
    # ══════════════════════════════════════════════════════════

    def _phase60_fake_hostfake(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """
        Phase 60: Fake + Hostfake
        Same as hostfake but with fake prefix
        pktws_hostfake_vary_ - 6 variants x 2 disorder = 12 tests per fooling
        With fake:blob=fake_default_tls:$fooling:repeats=4 prepended
        """
        def _fake_hostfake_vary(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            """pktws_hostfake_vary_ for fake+hostfake"""
            for disorder in ["", "disorder_after:"]:
                if state.found_working and self.mode == "first_working":
                    return
                disorder_label = disorder.rstrip(":") if disorder else "normal"

                fake_prefix = f"--lua-desync=fake:blob={FAKE_DEFAULT_TLS}:{fooling}:repeats={FAKE_REPEATS}"

                variants = [
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake1:{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_nofake1_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake2:{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_nofake2_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_midhost_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake1:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_nofake1_midhost_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:blob={FAKE_DEFAULT_TLS}:host=example.com:{disorder}nofake2:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}",
                     f"fake_hostfake_nofake2_midhost_{disorder_label}"),
                ]

                for params, name_prefix in variants:
                    if state.found_working and self.mode == "first_working":
                        return
                    full_params = f"{pre} --payload=tls_client_hello {params} {post}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=full_params, phase=60,
                        name=f"{name_prefix}{name_suffix}",
                        description=f"fake+hostfakesplit {name_prefix} {fooling}",
                        has_wssize=has_wssize
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        def _fake_hostfake_vary_with_md5(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            yield from _fake_hostfake_vary(state, fooling, pre, post, name_suffix, has_wssize)
            if state.found_working and self.mode == "first_working":
                return

            if "tcp_md5" in fooling:
                md5_post = f"{post} --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5".strip()
                yield from _fake_hostfake_vary(state, fooling, pre, md5_post, f"{name_suffix}_md5dup", has_wssize)

        # TTL loop
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_with_md5(
                    state, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Fooling loop
        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _fake_hostfake_vary_with_md5(
                state, fooling, "", "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}"
            )
            if state.found_working and self.mode == "first_working":
                return

        # AutoTTL loop
        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_with_md5(
                    state, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}"
                )
                if state.found_working and self.mode == "first_working":
                    return

        # Second pass with wssize
        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_with_md5(
                    state, f"ip4_ttl={ttl}", WSSIZE_PRE, f_suffix, f"_ttl{ttl}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _fake_hostfake_vary_with_md5(
                state, fooling, WSSIZE_PRE, "", f"_{fooling.replace('=', '_').replace('-', '_').replace(':', '_')}_wssize", has_wssize=True
            )
            if state.found_working and self.mode == "first_working":
                return

        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod_ttl1")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_with_md5(
                    state, f"ip4_autottl=-{delta},3-20", WSSIZE_PRE, f_suffix, f"_autottl_{delta}{f_name}_wssize", has_wssize=True
                )
                if state.found_working and self.mode == "first_working":
                    return

    def _phase60_fake_hostfake_http(self, state: ExactSelectorState) -> Generator[ExactStrategyResult, None, None]:
        """Phase 60 HTTP variant"""
        fake_http = "fake_default_http"

        def _fake_hostfake_vary_http(state, fooling: str, pre: str, post: str, name_suffix: str, has_wssize: bool = False):
            for disorder in ["", "disorder_after:"]:
                if state.found_working and self.mode == "first_working":
                    return
                disorder_label = disorder.rstrip(":") if disorder else "normal"
                fake_prefix = f"--lua-desync=fake:blob={fake_http}:{fooling}:repeats={FAKE_REPEATS}"
                variants = [
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}nofake1:{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_nofake1_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}nofake2:{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_nofake2_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_midhost_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}nofake1:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_nofake1_midhost_{disorder_label}"),
                    (f"{fake_prefix} --lua-desync=hostfakesplit:host=example.com:{disorder}nofake2:midhost=midsld:{fooling}:repeats={FAKE_REPEATS}", f"fake_hostfake_nofake2_midhost_{disorder_label}"),
                ]
                for params, name_prefix in variants:
                    if state.found_working and self.mode == "first_working":
                        return
                    full_params = f"{pre} --payload=http_req {params} {post}".strip()
                    yield from self._yield(state, ExactStrategyResult(
                        params=full_params, phase=60,
                        name=f"{name_prefix}{name_suffix}", has_wssize=has_wssize
                    ))
                    if state.found_working and self.mode == "first_working":
                        return

        for ttl in range(MIN_TTL, MAX_TTL + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_http(state, f"ip4_ttl={ttl}", "", f_suffix, f"_ttl{ttl}{f_name}")
                if state.found_working and self.mode == "first_working":
                    return

        for fooling in FOOLINGS_TCP:
            if state.found_working and self.mode == "first_working":
                return
            yield from _fake_hostfake_vary_http(state, fooling, "", "", f"_{fooling.replace('=', '_')}")
            if state.found_working and self.mode == "first_working":
                return

        for delta in range(MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA + 1):
            if state.found_working and self.mode == "first_working":
                return
            for f_suffix, f_name in [("", ""), (" --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=1", "_pktmod")]:
                if state.found_working and self.mode == "first_working":
                    return
                yield from _fake_hostfake_vary_http(state, f"ip4_autottl=-{delta},3-20", "", f_suffix, f"_autottl_{delta}{f_name}")
                if state.found_working and self.mode == "first_working":
                    return


# ══════════════════════════════════════════════════════════
# FACTORY FUNCTION
# ══════════════════════════════════════════════════════════

def get_exact_selector(protocol: str = "tls12", mode: str = "first_working"):
    """
    Factory function to get exact blockcheck2 selector.

    Args:
        protocol: "tls12", "tls13", "http", "quic"
        mode: "first_working" or "all_best"

    Returns:
        ExactStrategySelector instance
    """
    return ExactStrategySelector(protocol=protocol, mode=mode)
