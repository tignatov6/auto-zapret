# Research: Monitoring TCP Connection Problems on Windows for DPI Detection

## Overview

This document evaluates 6 approaches for detecting DPI-induced connection problems
(retransmissions, connection failures, timeouts) from Python on Windows. Each
approach includes working code, pros/cons, and a reliability assessment.

---

## 1. Windows TCP Performance Counters (PDH)

### Approach A: Using `win32pdh`

Windows exposes TCP counters via the Performance Data Helper (PDH) API:

| Counter Path | Description |
|---|---|
| `\TCPv4\Segments Retransmitted/sec` | Rate of retransmitted TCP segments |
| `\TCPv4\Segments Received/sec` | Rate of received segments |
| `\TCPv4\Segments Sent/sec` | Rate of sent segments |
| `\TCPv4\Connection Failures/sec` | Rate of failed connection attempts |
| `\TCPv4\Connections Established` | Total established connections |
| `\TCPv4\Connections Active` | Active (outbound) connections |
| `\TCPv4\Connections Passive` | Passive (inbound) connections |
| `\TCPv4\Connection Failures` | Cumulative connection failures |

```python
import win32pdh
import time

class TCPCounterMonitor:
    """Monitor global TCP retransmission and failure rates via PDH."""

    COUNTERS = [
        r"\TCPv4\Segments Retransmitted/sec",
        r"\TCPv4\Connection Failures/sec",
        r"\TCPv4\Segments Sent/sec",
        r"\TCPv4\Connections Established",
    ]

    def __init__(self):
        self.query = None
        self.handles = {}
        self._setup()

    def _setup(self):
        self.query = win32pdh.OpenQuery()
        for counter_path in self.COUNTERS:
            h = win32pdh.AddCounter(self.query, counter_path)
            self.handles[counter_path] = h

    def collect(self) -> dict:
        """Collect one sample. Returns dict of counter_name -> value."""
        win32pdh.CollectQueryData(self.query)
        results = {}
        for name, h in self.handles.items():
            try:
                _, value = win32pdh.GetFormattedCounterValue(
                    h, win32pdh.PDH_FMT_DOUBLE
                )
                results[name] = value
            except:
                results[name] = 0.0
        return results

    def collect_rate(self, interval_sec: float = 2.0) -> dict:
        """Collect two samples and compute delta rate."""
        sample1 = self.collect()
        time.sleep(interval_sec)
        sample2 = self.collect()
        return {
            k: sample2[k] - sample1[k]
            for k in sample1
        }

    def close(self):
        win32pdh.CloseQuery(self.query)


# Usage
monitor = TCPCounterMonitor()
try:
    # Baseline
    baseline = monitor.collect_rate(interval_sec=5.0)
    print(f"Retransmitted/sec: {baseline[r'\TCPv4\Segments Retransmitted/sec']:.1f}")
    print(f"Connection Failures/sec: {baseline[r'\TCPv4\Connection Failures/sec']:.1f}")
finally:
    monitor.close()
```

**Requirements:** `pip install pywin32`

**Pros:**
- Official Windows API, very reliable
- Real-time delta rates available
- No parsing required, structured numeric data
- Low overhead

**Cons:**
- Requires `pywin32` (heavy dependency)
- **Global only** -- cannot attribute to specific process or remote IP
- Retransmissions/sec alone does not prove DPI blocking (could be packet loss)
- Counter paths may differ on non-English Windows (use PDH paths, not localized names)

**Reliability for DPI detection:** Medium. High retransmission rate is a useful *signal*
but needs correlation with specific target IPs/domains to confirm DPI blocking.

---

### Approach B: WMI equivalent (no pywin32)

```python
import subprocess
import re

def get_tcp_perf_counters_wmic():
    """Alternative: use wmic to read performance data."""
    # Win32_PerfRawData_Tcpip_TCPv4 contains raw TCP counters
    result = subprocess.run(
        ["wmic", "path", "Win32_PerfRawData_Tcpip_TCPv4",
         "get", "SegmentsRetransmitted,ConnectionFailures,SegmentsSent,SegmentsReceived"],
        capture_output=True, text=True
    )
    # Parse output -- format is CSV-like
    print(result.stdout)
```

---

## 2. Windows API via ctypes: GetTcpStatistics + GetExtendedTcpTable

### 2a. GetTcpStatistics2 -- Global Retransmission Counts

The `GetTcpStatistics2` function returns `MIB_TCPSTATS2` which includes
`dwRetransSegs` (total retransmitted segments).

```python
import ctypes
from ctypes import wintypes
from ctypes import Structure, POINTER, byref

# Constants
AF_INET = 2
AF_INET6 = 23

class MIB_TCPSTATS2(Structure):
    """
    MIB_TCPSTATS2 structure from tcpmib.h
    Contains cumulative TCP statistics for IPv4 or IPv6.
    """
    _fields_ = [
        ("RtoAlgorithm", wintypes.ULONG),     # TCP_RTO_ALGORITHM enum
        ("dwRtoMin", wintypes.ULONG),          # Min RTO (ms)
        ("dwRtoMax", wintypes.ULONG),          # Max RTO (ms)
        ("dwMaxConn", wintypes.ULONG),         # Max connections (-1 = variable)
        ("dw64ActiveOpens", wintypes.ULONG64), # Active opens (client-side)
        ("dw64PassiveOpens", wintypes.ULONG64),# Passive opens (server-side)
        ("dw64AttemptFails", wintypes.ULONG64),# Failed connection attempts
        ("dw64EstabResets", wintypes.ULONG64), # Established connections reset
        ("dw64CurrEstab", wintypes.ULONG64),   # Currently established connections
        ("dw64InSegs", wintypes.ULONG64),      # Segments received
        ("dw64OutSegs", wintypes.ULONG64),     # Segments sent (excl. retransmits)
        ("dwRetransSegs", wintypes.ULONG64),   # Segments retransmitted
        ("dwInErrs", wintypes.ULONG),          # Errors received
        ("dwOutRsts", wintypes.ULONG),         # RST segments sent
        ("dwNumConns", wintypes.ULONG),        # Total connections (non-LISTEN)
    ]


def get_tcp_stats_ipv4() -> dict:
    """Get TCP statistics for IPv4 using GetTcpStatistics2."""
    stats = MIB_TCPSTATS2()
    # ULONG GetTcpStatistics2(PMIB_TCPSTATS2 pStats, ADDRESS_FAMILY Family)
    ret = ctypes.windll.iphlpapi.GetTcpStatistics2(
        byref(stats),
        AF_INET
    )
    if ret != 0:
        raise OSError(f"GetTcpStatistics2 failed with error code {ret}")
    return {
        "retrans_segs": stats.dwRetransSegs,
        "attempt_fails": stats.dw64AttemptFails,
        "estab_resets": stats.dw64EstabResets,
        "in_errors": stats.dwInErrs,
        "out_rsts": stats.dwOutRsts,
        "active_opens": stats.dw64ActiveOpens,
        "curr_estab": stats.dw64CurrEstab,
        "in_segs": stats.dw64InSegs,
        "out_segs": stats.dw64OutSegs,
    }


def monitor_retransmissions(interval_sec: float = 5.0, iterations: int = 10):
    """Monitor retransmission rate over time."""
    import time
    prev = get_tcp_stats_ipv4()
    prev_retrans = prev["retrans_segs"]
    prev_fails = prev["attempt_fails"]

    for i in range(iterations):
        time.sleep(interval_sec)
        curr = get_tcp_stats_ipv4()
        delta_retrans = curr["retrans_segs"] - prev_retrans
        delta_fails = curr["attempt_fails"] - prev_fails
        rate_retrans = delta_retrans / interval_sec
        rate_fails = delta_fails / interval_sec

        print(f"[{i+1}] Retrans rate: {rate_retrans:.1f}/s, "
              f"Fail rate: {rate_fails:.1f}/s")

        prev_retrans = curr["retrans_segs"]
        prev_fails = curr["attempt_fails"]
```

**Pros:**
- No external dependencies (pure ctypes + stdlib)
- Lightweight, fast
- 64-bit counters won't overflow
- `dwAttemptFails` is the most direct indicator of connection blocking

**Cons:**
- **Global only** -- no per-connection or per-process breakdown
- Cumulative counters -- must track deltas
- Retransmissions can come from any application, not just Discord

**Reliability for DPI detection:** Medium-High. `dwAttemptFails` increasing rapidly
while Discord is connecting is a strong signal of DPI interference. Retransmissions
alone could be normal network issues.

---

### 2b. GetExtendedTcpTable -- Per-Connection State with PID

This function returns the full TCP connection table including:
- Local/remote IP and port
- Connection state (ESTABLISHED, SYN_SENT, etc.)
- Owning process ID

```python
import ctypes
from ctypes import wintypes
from ctypes import Structure, POINTER, byref, sizeof, create_string_buffer
import socket
import struct

# Constants
NO_ERROR = 0
AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_CONNECTIONS = 4  # Only active connections with PID

TCP_STATES = {
    1: "CLOSED",
    2: "LISTENING",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


def _unpack_ipv4(addr_dword) -> str:
    """Convert DWORD (little-endian packed IP) to dotted string."""
    packed = struct.pack("<I", addr_dword)
    return socket.inet_ntoa(packed)


def _decode_port(port_dword) -> int:
    """Port is stored in network byte order -- swap bytes."""
    return ((port_dword & 0xFF) << 8) | ((port_dword >> 8) & 0xFF)


def get_tcp_connections() -> list:
    """
    Get all TCP connections with PID using GetExtendedTcpTable.
    Returns list of dicts with connection info.
    """
    connections = []

    # Step 1: Determine required buffer size
    dw_size = wintypes.DWORD(0)
    ret = ctypes.windll.iphlpapi.GetExtendedTcpTable(
        None,                # pTcpTable (NULL to get size)
        byref(dw_size),      # pdwSize
        False,               # bOrder
        AF_INET,             # dwFamily
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,                   # dwReserved
    )
    # ret should be ERROR_INSUFFICIENT_BUFFER (122)

    # Step 2: Allocate buffer and call again
    buf = create_string_buffer(dw_size.value)
    ret = ctypes.windll.iphlpapi.GetExtendedTcpTable(
        buf,
        byref(dw_size),
        False,
        AF_INET,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if ret != NO_ERROR:
        raise OSError(f"GetExtendedTcpTable failed: {ret}")

    # Step 3: Parse the table
    # Buffer layout: DWORD dwNumEntries, then MIB_TCPROW_OWNER_PID entries
    num_entries = ctypes.cast(buf, POINTER(wintypes.DWORD)).contents.value
    row_size = sizeof(MIB_TCPROW_OWNER_PID)
    offset = sizeof(wintypes.DWORD)  # Skip dwNumEntries

    for i in range(num_entries):
        row_ptr = ctypes.cast(
            ctypes.addressof(buf) + offset + i * row_size,
            POINTER(MIB_TCPROW_OWNER_PID)
        )
        row = row_ptr.contents

        local_ip = _unpack_ipv4(row.dwLocalAddr)
        remote_ip = _unpack_ipv4(row.dwRemoteAddr)
        local_port = _decode_port(row.dwLocalPort)
        remote_port = _decode_port(row.dwRemotePort)

        connections.append({
            "local_addr": f"{local_ip}:{local_port}",
            "remote_addr": f"{remote_ip}:{remote_port}",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": TCP_STATES.get(row.dwState, f"UNKNOWN({row.dwState})"),
            "pid": row.dwOwningPid,
            "state_code": row.dwState,
        })

    return connections


def find_discord_connections(discord_pids: set = None) -> list:
    """
    Find TCP connections belonging to Discord processes.
    If discord_pids is None, returns ALL connections (filter manually).
    """
    all_conns = get_tcp_connections()

    if discord_pids is None:
        return all_conns

    return [c for c in all_conns if c["pid"] in discord_pids]


def detect_stuck_syn_sent(target_pids: set = None) -> list:
    """
    Detect connections stuck in SYN_SENT state.
    This is a strong DPI blocking indicator -- the SYN packet is being
    silently dropped, so the connection never progresses.
    """
    all_conns = get_tcp_connections()

    stuck = []
    for c in all_conns:
        if c["state"] == "SYN_SENT":
            if target_pids is None or c["pid"] in target_pids:
                stuck.append(c)

    return stuck


def find_discord_process_pids() -> set:
    """Find PIDs of Discord processes by name."""
    import psutil

    pids = set()
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            name = proc.info["name"] or ""
            if name.lower() in ("discord.exe", "discord.pt"):
                pids.add(proc.info["pid"])
            # Also check child processes
            if name.lower() == "discord.exe":
                for child in proc.children(recursive=True):
                    try:
                        pids.add(child.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return pids


# Usage: Monitor for DPI blocking
if __name__ == "__main__":
    import time

    discord_pids = find_discord_process_pids()
    print(f"Found Discord PIDs: {discord_pids}")

    while True:
        # Check for SYN_SENT connections (DPI blocking indicator)
        stuck = detect_stuck_syn_sent(discord_pids)
        if stuck:
            print(f"WARNING: {len(stuck)} connections stuck in SYN_SENT!")
            for c in stuck:
                print(f"  -> {c['remote_addr']} (PID {c['pid']})")

        # Also check all connections for state analysis
        conns = find_discord_connections(discord_pids)
        states = {}
        for c in conns:
            states[c["state"]] = states.get(c["state"], 0) + 1
        print(f"Connection states: {states}")

        time.sleep(5)
```

**Pros:**
- No external dependencies (pure ctypes + stdlib, psutil optional for PID lookup)
- **Per-connection state** -- can identify exactly which connections are failing
- SYN_SENT detection is the **most reliable DPI indicator** without packet capture
- Includes PID for process attribution
- Works for both IPv4 (use `AF_INET6` and different struct for IPv6)

**Cons:**
- Does NOT include retransmission counts per connection (only state)
- Need to poll periodically to detect changes
- For IPv6, need `MIB_TCP6ROW_OWNER_PID` (different structure with 16-byte IP)

**Reliability for DPI detection:** High. Connections stuck in SYN_SENT
specifically for Discord processes strongly indicates DPI blocking.

---

### 2c. GetPerTcpConnectionEStats -- Per-Connection Retransmissions (Advanced)

This is the most detailed API but requires:
- Administrator privileges
- Enabling collection per-connection first (via `SetPerTcpConnectionEStats`)
- Complex structure definitions

```python
import ctypes
from ctypes import wintypes
from ctypes import Structure, POINTER, byref, sizeof

# TCP_ESTATS_TYPE enum
TcpConnectionEstatsData = 3
TcpConnectionEstatsSndCong = 4

class TCP_ESTATS_DATA_RW_v0(Structure):
    _fields_ = [
        ("EnableCollection", wintypes.BOOLEAN),
    ]

class TCP_ESTATS_DATA_ROD_v0(Structure):
    """Read-only dynamic data -- includes retransmission info."""
    _fields_ = [
        ("FastRetran", wintypes.ULONG),       # Fast retransmissions
        ("SlowStartRetran", wintypes.ULONG),   # Slow-start retransmissions
        ("OtherRetran", wintypes.ULONG),       # Other retransmissions
        ("TotalRetran", wintypes.ULONG),       # Total retransmissions
        # ... more fields for timeouts, etc.
    ]


def enable_estats_collection(tcp_row) -> bool:
    """
    Enable EStats collection for a specific TCP connection.
    tcp_row should be a MIB_TCPROW_OWNER_PID (without PID field for this API).

    Requires administrator privileges.
    """
    # Build MIB_TCPROW (without PID) from MIB_TCPROW_OWNER_PID
    class MIB_TCPROW(Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
        ]

    row = MIB_TCPROW()
    row.dwState = tcp_row.dwState
    row.dwLocalAddr = tcp_row.dwLocalAddr
    row.dwLocalPort = tcp_row.dwLocalPort
    row.dwRemoteAddr = tcp_row.dwRemoteAddr
    row.dwRemotePort = tcp_row.dwRemotePort

    # Set up Rw buffer with EnableCollection = TRUE
    rw = TCP_ESTATS_DATA_RW_v0()
    rw.EnableCollection = True

    ret = ctypes.windll.iphlpapi.SetPerTcpConnectionEStats(
        byref(row),
        TcpConnectionEstatsData,
        byref(rw),
        0,           # RwVersion
        sizeof(rw),  # RwSize
        0,           # Reserved
    )
    return ret == 0


def get_connection_estats(tcp_row) -> dict:
    """
    Get extended statistics for a specific TCP connection.
    Returns retransmission counts if collection is enabled.
    """
    class MIB_TCPROW(Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
        ]

    row = MIB_TCPROW()
    row.dwState = tcp_row.dwState
    row.dwLocalAddr = tcp_row.dwLocalAddr
    row.dwLocalPort = tcp_row.dwLocalPort
    row.dwRemoteAddr = tcp_row.dwRemoteAddr
    row.dwRemotePort = tcp_row.dwRemotePort

    rw = TCP_ESTATS_DATA_RW_v0()
    rod = TCP_ESTATS_DATA_ROD_v0()

    ret = ctypes.windll.iphlpapi.GetPerTcpConnectionEStats(
        byref(row),
        TcpConnectionEstatsData,
        byref(rw),
        0,
        sizeof(rw),
        None, 0, 0,  # Ros (static) -- not needed
        byref(rod),
        0,
        sizeof(rod),
    )
    if ret != 0:
        return None

    if not rw.EnableCollection:
        return None

    return {
        "fast_retrans": rod.FastRetran,
        "slow_start_retrans": rod.SlowStartRetran,
        "other_retrans": rod.OtherRetran,
        "total_retrans": rod.TotalRetran,
    }
```

**Pros:**
- **Per-connection retransmission data** -- the most detailed signal available
- Can distinguish fast retransmit (packet loss) from slow-start (connection startup)
- Exact attribution to specific remote IP and process

**Cons:**
- **Requires administrator privileges**
- Must enable collection per-connection before data is available
- Complex API with many structure definitions
- Collection must be enabled early -- cannot retroactively get data
- Structure definitions in `tcpestats.h` are not fully documented
- May not work reliably on all Windows versions

**Reliability for DPI detection:** Very High (if it works). Per-connection retransmission
counts for Discord connections would be the smoking gun for DPI blocking.

---

## 3. Netstat Parsing

### 3a. `netstat -s` -- Protocol Statistics

Windows `netstat -s` outputs cumulative TCP statistics similar to
`GetTcpStatistics2`.

```python
import subprocess
import re

def parse_netstat_s() -> dict:
    """
    Parse 'netstat -s' output for TCP statistics.
    Works on both English and Russian Windows (with locale adaptation).

    NOTE: Output is locale-dependent. On Russian Windows, labels are in Russian.
    Use 'netstat -s -p tcp' to limit to TCP only.
    """
    result = subprocess.run(
        ["netstat", "-s", "-p", "tcp"],
        capture_output=True, text=True, encoding="cp866"
    )
    output = result.stdout

    stats = {}

    # English patterns
    patterns = {
        "retrans_segs": r"Segments Retransmitted\s*[:=]\s*(\d+)",
        "attempt_fails": r"Connection attempt failures\s*[:=]\s*(\d+)",
        "active_opens": r"Active Opens\s*[:=]\s*(\d+)",
        "passive_opens": r"Passive Opens\s*[:=]\s*(\d+)",
        "estab_resets": r"Established Resets\s*[:=]\s*(\d+)",
        "curr_estab": r"Current Establishments\s*[:=]\s*(\d+)",
        "in_errors": r"Receive Errors\s*[:=]\s*(\d+)",
        "out_rsts": r"Output Resets\s*[:=]\s*(\d+)",
    }

    # Russian patterns (for Russian Windows)
    patterns_ru = {
        "retrans_segs": r"Повторно переданные сегменты\s*[:=]\s*(\d+)",
        "attempt_fails": r"Сбои соединения\s*[:=]\s*(\d+)",
        "active_opens": r"Активные открытия\s*[:=]\s*(\d+)",
        "passive_opens": r"Пассивные открытия\s*[:=]\s*(\d+)",
    }

    for key, pattern in {**patterns, **patterns_ru}.items():
        match = re.search(pattern, output)
        if match:
            stats[key] = int(match.group(1))

    return stats


def monitor_netstat(interval_sec: float = 5.0, iterations: int = 10):
    """Monitor TCP stats by diffing netstat -s output."""
    import time

    prev = parse_netstat_s()
    prev_retrans = prev.get("retrans_segs", 0)
    prev_fails = prev.get("attempt_fails", 0)

    for i in range(iterations):
        time.sleep(interval_sec)
        curr = parse_netstat_s()
        delta_retrans = curr.get("retrans_segs", 0) - prev_retrans
        delta_fails = curr.get("attempt_fails", 0) - prev_fails

        print(f"[{i+1}] Retrans in interval: {delta_retrans}, "
              f"Failures: {delta_fails}")

        prev_retrans = curr.get("retrans_segs", 0)
        prev_fails = curr.get("attempt_fails", 0)
```

**Pros:**
- No external dependencies
- Works on any Windows version
- Easy to implement

**Cons:**
- **Locale-dependent output** -- different label text on non-English Windows
- Global stats only -- no per-process or per-connection breakdown
- Slower than ctypes API (spawns subprocess)
- Output format can change between Windows versions
- Brittle regex parsing

**Reliability for DPI detection:** Medium. Same fundamental limitation as
`GetTcpStatistics2` -- global only, no attribution.

---

### 3b. `netstat -n` -- Active Connections

```python
import subprocess
import re

def parse_netstat_n() -> list:
    """
    Parse 'netstat -n -p tcp' for active TCP connections.
    Output format:
      TCP    192.168.1.5:54321    162.159.130.234:443    ESTABLISHED

    Returns list of dicts.
    """
    result = subprocess.run(
        ["netstat", "-n", "-p", "tcp"],
        capture_output=True, text=True, encoding="cp866"
    )
    connections = []

    for line in result.stdout.split("\n"):
        line = line.strip()
        # Match TCP lines with state
        match = re.match(
            r"TCP\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+(\S+)",
            line
        )
        if match:
            local_ip, local_port, remote_ip, remote_port, state = match.groups()
            connections.append({
                "local_addr": f"{local_ip}:{local_port}",
                "remote_addr": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": int(remote_port),
                "state": state,
                "pid": None,  # netstat -n doesn't include PID
            })

    return connections


def find_syn_sent_connections() -> list:
    """Find all connections stuck in SYN_SENT."""
    conns = parse_netstat_n()
    return [c for c in conns if c["state"] == "SYN_SENT"]
```

**Add PID with `netstat -bno`:**
```python
def parse_netstat_bno() -> list:
    """
    Parse 'netstat -bno' for connections with PID and executable name.
    Requires administrator privileges.

    Output format:
      TCP    192.168.1.5:54321    162.159.130.234:443    ESTABLISHED    1234
      [Discord.exe]
    """
    result = subprocess.run(
        ["netstat", "-bno", "-p", "tcp"],
        capture_output=True, text=True, encoding="cp866",
    )
    # Parsing is complex due to multi-line format (exe name on separate line)
    # Prefer GetExtendedTcpTable via ctypes instead
```

**Pros:**
- Simple, works everywhere
- `-bno` includes PID and process name

**Cons:**
- `-bno` requires administrator privileges
- Complex multi-line parsing for `-bno`
- Slower than ctypes API
- Locale-dependent column headers

**Reliability for DPI detection:** Medium. SYN_SENT detection works well,
but `GetExtendedTcpTable` via ctypes is faster and more reliable.

---

## 4. Connection Failure Detection Without Retransmission Data

### 4a. SYN_SENT State Monitoring

This is the **single best DPI indicator** without packet capture.

```python
import time
from collections import defaultdict

class SynSentMonitor:
    """
    Monitor for connections stuck in SYN_SENT state.

    DPI blocking typically manifests as:
    1. SYN sent, no SYN-ACK received -> connection stays in SYN_SENT
    2. After timeout (~21 seconds on Windows), connection fails
    3. Application retries -> new SYN_SENT entry

    Pattern: repeated SYN_SENT entries to the same remote IP:port
    """

    def __init__(self):
        self.history = []  # Track SYN_SENT connections over time

    def check(self, target_pids: set = None, target_ports: set = None):
        """
        Check for stuck SYN_SENT connections.

        Args:
            target_pids: Only check connections from these PIDs
            target_ports: Only check connections to these ports (e.g., 443)
        """
        from tcp_api import get_tcp_connections  # From section 2b

        conns = get_tcp_connections()

        syn_sent = []
        for c in conns:
            if c["state"] != "SYN_SENT":
                continue
            if target_pids and c["pid"] not in target_pids:
                continue
            if target_ports and c["remote_port"] not in target_ports:
                continue
            syn_sent.append(c)

        # Track in history
        timestamp = time.time()
        self.history.append({
            "timestamp": timestamp,
            "connections": syn_sent,
        })

        # Detect patterns: same destination appearing repeatedly
        return self._detect_pattern(syn_sent)

    def _detect_pattern(self, current_syn_sent: list) -> dict:
        """
        Detect suspicious patterns indicating DPI blocking.

        Returns dict with:
        - is_dpi_suspected: bool
        - evidence: list of descriptions
        - affected_targets: set of remote addresses
        """
        evidence = []
        affected = set()

        if not current_syn_sent:
            return {"is_dpi_suspected": False, "evidence": [], "affected_targets": set()}

        # Pattern 1: Multiple SYN_SENT to same destination
        dest_counts = defaultdict(int)
        for c in current_syn_sent:
            key = f"{c['remote_ip']}:{c['remote_port']}"
            dest_counts[key] += 1

        for dest, count in dest_counts.items():
            if count >= 2:
                evidence.append(
                    f"Multiple SYN_SENT ({count}) to {dest} -- likely DPI blocking"
                )
                affected.add(dest)

        # Pattern 2: SYN_SENT persisting across multiple checks
        if len(self.history) >= 3:
            last_3 = self.history[-3:]
            persistent_dests = set()
            for check in last_3:
                for c in check["connections"]:
                    persistent_dests.add(f"{c['remote_ip']}:{c['remote_port']}")

            # Destinations that appeared in all 3 checks
            dest_in_each = set(dest_counts.keys())
            for check in last_3[:-1]:  # exclude current
                check_dests = {
                    f"{c['remote_ip']}:{c['remote_port']}"
                    for c in check["connections"]
                }
                dest_in_each &= check_dests

            for dest in dest_in_each:
                evidence.append(
                    f"SYN_SENT to {dest} persisting across all checks "
                    f"({len(last_3)} samples) -- strong DPI indicator"
                )
                affected.add(dest)

        # Pattern 3: SYN_SENT to known Discord IP ranges
        discord_ranges = get_discord_ip_ranges()  # See section 5
        for c in current_syn_sent:
            if ip_in_ranges(c["remote_ip"], discord_ranges):
                evidence.append(
                    f"SYN_SENT to Discord IP {c['remote_ip']}:{c['remote_port']} "
                    f"-- almost certainly DPI blocking"
                )
                affected.add(f"{c['remote_ip']}:{c['remote_port']}")

        return {
            "is_dpi_suspected": len(evidence) > 0,
            "evidence": evidence,
            "affected_targets": affected,
        }


# Usage
monitor = SynSentMonitor()
while True:
    result = monitor.check(target_ports={443, 80})
    if result["is_dpi_suspected"]:
        print("DPI BLOCKING DETECTED:")
        for ev in result["evidence"]:
            print(f"  - {ev}")
    time.sleep(5)
```

---

### 4b. Connection State Anomaly Detection

```python
class ConnectionStateAnomalyDetector:
    """
    Detect unusual TCP connection patterns that indicate DPI interference:

    1. High rate of connections transitioning ESTABLISHED -> closed
       without data transfer (RST flood from DPI)
    2. Connections disappearing quickly (DPI injecting RST)
    3. Unusual ratio of TIME_WAIT to ESTABLISHED
    """

    def __init__(self):
        self.previous_connections = {}  # remote_addr -> state
        self.state_transitions = []

    def check(self, target_pids: set = None) -> dict:
        from tcp_api import get_tcp_connections
        conns = get_tcp_connections()

        if target_pids:
            conns = [c for c in conns if c["pid"] in target_pids]

        current = {c["remote_addr"]: c["state"] for c in conns}
        anomalies = []

        # Detect connections that disappeared (were ESTABLISHED, now gone)
        for addr, prev_state in self.previous_connections.items():
            if addr not in current and prev_state == "ESTABLISHED":
                # Connection was ESTABLISHED but now vanished
                # Could be DPI sending RST
                anomalies.append(f"Connection {addr} vanished from ESTABLISHED")

        # Detect abnormal state ratios
        state_counts = defaultdict(int)
        for c in conns:
            state_counts[c["state"]] += 1

        total = sum(state_counts.values())
        if total > 0:
            syn_sent_ratio = state_counts.get("SYN_SENT", 0) / total
            if syn_sent_ratio > 0.1:  # More than 10% in SYN_SENT
                anomalies.append(
                    f"Abnormal SYN_SENT ratio: {syn_sent_ratio:.1%}"
                )

            time_wait_ratio = state_counts.get("TIME_WAIT", 0) / total
            if time_wait_ratio > 0.5:  # More than 50% in TIME_WAIT
                anomalies.append(
                    f"High TIME_WAIT ratio: {time_wait_ratio:.1%}"
                )

        self.previous_connections = current
        return {
            "anomalies": anomalies,
            "state_counts": dict(state_counts),
            "total_connections": total,
        }
```

**Pros:**
- No external dependencies
- Pattern-based detection is more robust than single-metric thresholds
- SYN_SENT monitoring is the most accessible DPI indicator
- Can correlate with known Discord IPs for higher confidence

**Cons:**
- Polling-based -- short-lived SYN_SENT states (< 1 sec) may be missed
- Cannot detect DPI that allows SYN but blocks after handshake
- Needs known Discord IP ranges for best accuracy

**Reliability for DPI detection:** High. SYN_SENT persistence to known
Discord IPs is the strongest non-packet-capture indicator.

---

## 5. Reverse DNS for IP -> Domain Mapping

```python
import socket
import ipaddress

def reverse_dns(ip: str, timeout: float = 3.0) -> str:
    """
    Resolve IP to hostname via reverse DNS.

    WARNING: Many cloud/CDN IPs (including Discord via Cloudflare)
    do not have meaningful PTR records.
    """
    try:
        hostname, _ = socket.getnameinfo(
            (ip, 0),
            socket.NI_NAMEREQD
        )
        return hostname
    except socket.gaierror:
        return None


def reverse_dns_gethostbyaddr(ip: str) -> str:
    """Alternative using gethostbyaddr."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


# Discord IP ranges (incomplete -- Discord uses Cloudflare + own infrastructure)
DISCORD_IP_RANGES = [
    # Discord API / Gateway (via Cloudflare AS13335)
    # These change frequently and are not officially published
    "162.159.128.0/17",   # Cloudflare range used by Discord
    "162.159.130.0/24",   # Discord gateway specific
    "162.159.137.0/24",   # Discord voice

    # Discord voice servers (AS49544 i3D.net)
    "66.22.200.0/22",     # i3D.net range used by Discord
    "66.22.204.0/22",
    "66.22.208.0/22",
    "66.22.212.0/22",
    "66.22.216.0/22",
    "66.22.220.0/22",
    "66.22.224.0/22",
    "66.22.228.0/22",
    "66.22.232.0/22",
    "66.22.236.0/22",
    "66.22.240.0/22",
    "66.22.244.0/22",
    "66.22.248.0/22",
    "66.22.252.0/22",

    # Additional ranges observed
    "104.244.0.0/16",     # Various Discord-related
]


def ip_in_ranges(ip: str, ranges: list) -> bool:
    """Check if IP falls within any of the given CIDR ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in ranges:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def is_discord_ip(ip: str) -> bool:
    """Check if an IP belongs to known Discord infrastructure."""
    return ip_in_ranges(ip, DISCORD_IP_RANGES)


def check_ip_identity(ip: str) -> dict:
    """
    Check the identity of an IP address.
    Returns dict with reverse DNS, range match, and confidence.
    """
    hostname = reverse_dns(ip)
    is_discord = is_discord_ip(ip)

    confidence = "unknown"
    if is_discord:
        confidence = "high"
    elif hostname and ("discord" in hostname.lower()):
        confidence = "medium"
        is_discord = True
    elif hostname and ("cloudflare" in hostname.lower()):
        confidence = "low"  # Could be Discord via Cloudflare

    return {
        "ip": ip,
        "hostname": hostname,
        "is_discord_range": is_discord,
        "confidence": confidence,
    }
```

**Pros:**
- Can identify Discord connections without knowing PIDs
- IP range matching is fast and reliable for known ranges

**Cons:**
- **Discord IP ranges are not officially published** and change frequently
- Cloudflare IPs are shared with millions of other services
- Reverse DNS often returns generic Cloudflare hostnames, not "discord"
- New Discord voice servers may use unlisted IP ranges

**Reliability for DPI detection:** Medium. IP range matching works as a
*heuristic* but should not be the sole detection method.

---

## 6. DNS Query Monitoring

### 6a. Reading Windows DNS Client Cache

```python
import subprocess
import re

def get_dns_cache() -> list:
    """
    Read Windows DNS client cache via ipconfig /displaydns.
    Returns list of (name, resolved_ip, ttl) tuples.
    """
    result = subprocess.run(
        ["ipconfig", "/displaydns"],
        capture_output=True, text=True, encoding="cp866"
    )

    entries = []
    current_name = None

    for line in result.stdout.split("\n"):
        line = line.strip()

        # Record name line
        name_match = re.match(r"^(.+?)\s+\.{0,1}\s*$", line)
        if name_match and not line.startswith("Record"):
            current_name = name_match.group(1).strip()
            continue

        # IP address
        ip_match = re.search(r"Address:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            entries.append({
                "name": current_name,
                "ip": ip_match.group(1),
            })

    return entries


def find_discord_dns_entries() -> list:
    """Find DNS cache entries for Discord domains."""
    cache = get_dns_cache()
    discord_domains = [
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "discord.gg",
        "discord.media",
        "discordcdn.com",
        "gateway.discord.gg",
    ]
    return [
        entry for entry in cache
        if entry["name"] and any(
            d in entry["name"].lower() for d in discord_domains
        )
    ]
```

### 6b. DNS Query Monitoring with dnspython

```python
import dns.resolver
import time
from collections import defaultdict

class DNSQueryMonitor:
    """
    Monitor DNS queries to detect Discord domain resolution.
    This can help map IP addresses back to domain names.
    """

    DISCORD_DOMAINS = [
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "gateway.discord.gg",
        "cdn.discordapp.com",
        "media.discordapp.net",
        "voice.discord.gg",
    ]

    def __init__(self):
        self.resolved = {}  # domain -> list of IPs

    def resolve_discord(self) -> dict:
        """Resolve all Discord domains and record IPs."""
        results = {}
        for domain in self.DISCORD_DOMAINS:
            try:
                answers = dns.resolver.resolve(domain, "A")
                ips = [str(rdata) for rdata in answers]
                results[domain] = ips
                self.resolved[domain] = ips
            except dns.resolver.NXDOMAIN:
                results[domain] = []
            except dns.resolver.NoAnswer:
                results[domain] = []
            except dns.exception.DNSException as e:
                results[domain] = [f"error: {e}"]
        return results

    def get_current_discord_ips(self) -> set:
        """Get all current Discord IP addresses."""
        results = self.resolve_discord()
        all_ips = set()
        for ips in results.values():
            for ip in ips:
                if not ip.startswith("error:"):
                    all_ips.add(ip)
        return all_ips

    def ip_to_domain(self, ip: str) -> str:
        """Map IP back to domain via cached resolution."""
        for domain, ips in self.resolved.items():
            if ip in ips:
                return domain
        return None
```

### 6c. Alternative: Monitor DNS queries via ETW (Event Tracing for Windows)

```python
# This requires the etw package: pip install etw
# Microsoft-Windows-DNS-Client provider GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}

def setup_dns_etw_monitor():
    """
    Monitor DNS queries via ETW (Event Tracing for Windows).

    This is the most comprehensive approach but requires:
    - Administrator privileges
    - Third-party package (etw) or complex ctypes code

    Events captured:
    - Every DNS query made by any process
    - Resolution results (IP addresses)
    - Process ID that made the query
    """
    try:
        import etw
    except ImportError:
        print("Install etw package: pip install etw")
        return

    dns_provider_guid = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
    # Event ID 3006 = DNS query completed
    # Event ID 3008 = DNS query start

    # This is complex to implement correctly.
    # See: https://github.com/fireeye/etw
    pass
```

**Pros:**
- DNS cache reading requires no special privileges
- Can build IP -> domain mapping proactively
- ETW-based monitoring is comprehensive (with admin rights)

**Cons:**
- `ipconfig /displaydns` output format is fragile and locale-dependent
- DNS cache doesn't show *which process* made the query
- ETW monitoring requires admin privileges and third-party library
- DNS resolution changes over time (CDN, anycast, load balancing)

**Reliability for DPI detection:** Medium-High as a supporting signal.
DNS monitoring alone cannot detect blocking, but combined with SYN_SENT
detection it provides strong evidence.

---

## Summary: Recommended Detection Strategy

For detecting DPI blocking of Discord connections, the optimal approach
combines multiple signals:

```
┌──────────────────────────────────────────────────────────────────┐
│                    DPI Detection Strategy                        │
├─────────────────────────┬────────────────────────────────────────┤
│ Layer 1 (Primary)       │ SYN_SENT monitoring via                │
│                         │ GetExtendedTcpTable (ctypes)           │
│                         │ → Most reliable, no dependencies       │
├─────────────────────────┼────────────────────────────────────────┤
│ Layer 2 (Confirmation)  │ Global retransmission/failure rate     │
│                         │ via GetTcpStatistics2 (ctypes)         │
│                         │ → Confirms network-wide issues         │
├─────────────────────────┼────────────────────────────────────────┤
│ Layer 3 (Attribution)   │ Discord IP range matching +            │
│                         │ DNS cache for IP->domain mapping       │
│                         │ → Confirms target is Discord           │
├─────────────────────────┼────────────────────────────────────────┤
│ Layer 4 (Optional)      │ Per-connection EStats via              │
│                         │ GetPerTcpConnectionEStats (admin only)  │
│                         │ → Per-connection retransmission counts │
└─────────────────────────┴────────────────────────────────────────┘
```

### Detection Algorithm

```python
def detect_dpi_blocking(check_interval: float = 3.0):
    """
    Main DPI blocking detection loop.

    Returns dict with detection results when DPI blocking is suspected.
    """
    tcp_monitor = TCPCounterMonitor()  # Section 1
    syn_monitor = SynSentMonitor()     # Section 4a
    dns_monitor = DNSQueryMonitor()    # Section 6b

    # Baseline
    baseline_retrans = get_tcp_stats_ipv4()["retrans_segs"]
    baseline_fails = get_tcp_stats_ipv4()["attempt_fails"]

    while True:
        results = {
            "timestamp": time.time(),
            "detections": [],
        }

        # 1. Check for SYN_SENT connections to Discord
        discord_pids = find_discord_process_pids()
        syn_result = syn_monitor.check(target_pids=discord_pids)

        if syn_result["is_dpi_suspected"]:
            results["detections"].append({
                "type": "syn_sent",
                "severity": "high",
                "evidence": syn_result["evidence"],
            })

        # 2. Check global retransmission rate spike
        current = get_tcp_stats_ipv4()
        delta_retrans = current["retrans_segs"] - baseline_retrans
        delta_fails = current["attempt_fails"] - baseline_fails

        if delta_fails > 5:  # More than 5 new failures
            results["detections"].append({
                "type": "connection_failures",
                "severity": "medium",
                "delta_failures": delta_fails,
            })

        # 3. Update baseline
        baseline_retrans = current["retrans_segs"]
        baseline_fails = current["attempt_fails"]

        # 4. Report
        if results["detections"]:
            yield results

        time.sleep(check_interval)
```

### Key Files and APIs Referenced

| Approach | API/Command | Privileges | Dependencies | Reliability |
|---|---|---|---|---|
| PDH counters | `win32pdh` | None | `pywin32` | Medium |
| GetTcpStatistics2 | `iphlpapi.GetTcpStatistics2` | None | stdlib ctypes | Medium-High |
| GetExtendedTcpTable | `iphlpapi.GetExtendedTcpTable` | None | stdlib ctypes | High |
| GetPerTcpConnectionEStats | `iphlpapi.GetPerTcpConnectionEStats` | **Admin** | stdlib ctypes | Very High |
| netstat -s | `netstat -s -p tcp` | None | subprocess (stdlib) | Medium |
| netstat -bno | `netstat -bno -p tcp` | **Admin** | subprocess (stdlib) | Medium |
| psutil net_connections | `psutil.net_connections()` | None | `psutil` | High |
| DNS cache | `ipconfig /displaydns` | None | subprocess (stdlib) | Medium |
| DNS resolution | `dns.resolver` | None | `dnspython` | Medium |
| Reverse DNS | `socket.getnameinfo()` | None | stdlib | Low-Medium |
| ETW DNS monitoring | `etw` package | **Admin** | `etw` | High |
