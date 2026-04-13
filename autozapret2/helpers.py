"""
Общие утилиты для Auto-Zapret
"""

from pathlib import Path

from .utils.profiler import get_profiler

profiler = get_profiler("utils")


# ══════════════════════════════════════════════════════════
# КОНСТАНТЫ ZAPRET2
# ══════════════════════════════════════════════════════════

# Типы payload для --payload
ZAPRET2_PAYLOAD_TYPES = [
    "http_req", "tls_client_hello", "quic_initial", "empty"
]

# L7 протоколы Zapret2
ZAPRET2_L7_PROTOCOLS = [
    "http", "tls", "dtls", "quic", "wireguard", "dht", "discord",
    "stun", "xmpp", "dns", "mtproto", "bt", "utp_bt"
]

# Fooling методы Zapret2 (расширенный набор)
ZAPRET2_FOOLINGS_TCP = [
    "tcp_md5", "badsum", "tcp_seq=-3000", "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up", "tcp_ts=-1000", "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN"
]

ZAPRET2_FOOLINGS_IPV6 = [
    "ip6_hopbyhop", "ip6_hopbyhop:ip6_hopbyhop2", "ip6_destopt",
    "ip6_routing", "ip6_ah"
]

ZAPRET2_FOOLINGS_UDP = ["badsum"]

# Все fooling методы
ZAPRET2_ALL_FOOLINGS = (
    ZAPRET2_FOOLINGS_TCP +
    ZAPRET2_FOOLINGS_IPV6 +
    ZAPRET2_FOOLINGS_UDP
)

# Типы десинхронизации Zapret2 (lua-desync)
ZAPRET2_DESYNC_TYPES = [
    # Basic desync
    "drop", "send", "pktmod", "fake", "syndata", "rst",
    "multisplit", "multidisorder", "multidisorder_legacy",
    "fakedsplit", "fakeddisorder", "hostfakesplit",
    "tcpseg", "oob", "wssize", "wsize",

    # HTTP modifiers
    "http_hostcase", "http_domcase", "http_methodeol", "http_unixeol",

    # SYN-ACK
    "synack", "synack_split",

    # TLS
    "tls_client_hello_clone",

    # Obfuscation (zapret-obfs.lua)
    "wgobfs", "ippxor", "udp2icmp", "synhide",

    # UDP
    "udplen", "dht_dn",

    # IP fragmentation
    "ipfrag_disorder",

    # Orchestrators (zapret-auto.lua)
    "circular", "condition", "stopif", "repeater",

    # IPv6
    "ip6_hopbyhop", "ip6_destopt", "ip6_routing", "ip6_ah",
]

# Позиции split для Zapret2
ZAPRET2_SPLIT_POSITIONS = [
    "0", "1", "2", "method", "method+2", "host", "endhost",
    "sld", "endsld", "midsld", "sniext", "-1"
]

# TLS модификаторы Zapret2
ZAPRET2_TLS_MODS = ["rnd", "rndsni", "dupsid", "padencap"]

# Blob имена по умолчанию
ZAPRET2_DEFAULT_BLOBS = {
    "tls": "fake_default_tls",
    "http": "fake_default_http",
    "quic": "fake_default_quic",
    "syndata": "fake_default_syndata"
}


@profiler
def normalize_domain(domain: str) -> str:
    """
    Нормализация домена: lower-case, убирание точки в конце, trim пробелов

    Args:
        domain: Домен для нормализации

    Returns:
        Нормализованный домен
    """
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    return domain


@profiler
def canonicalize_params(params: str) -> str:
    """
    Канонизация строки параметров zapret для сравнения

    Args:
        params: Строка параметров

    Returns:
        Канонизированная строка (части отсортированы)
    """
    parts = params.strip().split()
    parts.sort()
    return ' '.join(parts)


@profiler
def build_lua_desync_params(desync_type: str, **kwargs) -> str:
    """
    Построение строки --lua-desync для Zapret2

    Args:
        desync_type: Тип десинхронизации (fake, multisplit, и т.д.)
        **kwargs: Дополнительные параметры

    Returns:
        Строка параметров в формате Zapret2 lua-desync

    Examples:
        build_lua_desync_params("fake", blob="fake_default_tls", ip4_ttl=3)
        -> "fake:blob=fake_default_tls:ip4_ttl=3"

        build_lua_desync_params("multisplit", pos="method+2")
        -> "multisplit:pos=method+2"
    """
    parts = [desync_type]

    for key, value in kwargs.items():
        if value is not None and value != "":
            parts.append(f"{key}={value}")

    return ":".join(parts)


@profiler
def parse_lua_desync_params(lua_desync: str) -> dict:
    """
    Парсинг строки --lua-desync Zapret2

    Args:
        lua_desync: Строка вида "fake:blob=fake_tls:ip4_ttl=3"

    Returns:
        Dict с параметрами
    """
    parts = lua_desync.split(":")
    result = {"type": parts[0] if parts else ""}

    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            result[key] = value

    return result


@profiler
def get_all_fake_files(base_dir: str = None) -> dict:
    """
    Get all available fake files from Zapret2 files/fake/ directory

    Returns dict organized by category:
    {
        "tls": ["tls_clienthello_iana_org.bin", "tls_clienthello_google_com_tlsrec.bin", ...],
        "quic": ["quic_initial_www_google_com.bin", ...],
        "http": ["http_iana_org.bin"],
        "dtls": ["dtls_clienthello_w3_org.bin", ...],
        "dns": [...],
        "other": [...]
    }
    """
    if base_dir is None:
        # Try both possible locations
        base_dir = str(Path(__file__).parent.parent / "bin" / "zapret2" / "files" / "fake")
        if not Path(base_dir).exists():
            base_dir = str(Path(__file__).parent.parent / "files" / "fake")

    result = {"tls": [], "quic": [], "http": [], "dtls": [], "dns": [], "other": []}

    fake_dir = Path(base_dir)
    if not fake_dir.exists():
        return result

    for f in fake_dir.glob("*.bin"):
        name = f.name
        if name.startswith("tls_"):
            result["tls"].append(name)
        elif name.startswith("quic"):
            result["quic"].append(name)
        elif name.startswith("http_"):
            result["http"].append(name)
        elif name.startswith("dtls_"):
            result["dtls"].append(name)
        elif name.startswith("dns"):
            result["dns"].append(name)
        else:
            result["other"].append(name)

    return result
