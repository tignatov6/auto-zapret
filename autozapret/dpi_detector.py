"""
DPI Detector - модуль обнаружения DPI блокировок

Интеграция с blockcheck.sh из Zapret
"""

import asyncio
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .utils.profiler import get_profiler
profiler = get_profiler("dpi_detector")

logger = logging.getLogger(__name__)


class DPIStatus(Enum):
    """Статус обнаружения DPI"""
    NOT_CHECKED = "not_checked"
    NO_DPI = "no_dpi"  # DPI не обнаружен
    DPI_DETECTED = "dpi_detected"  # DPI обнаружен
    IP_BLOCKED = "ip_blocked"  # Блокировка по IP
    DNS_BLOCKED = "dns_blocked"  # DNS блокировка
    ERROR = "error"  # Ошибка проверки
    UNKNOWN = "unknown"  # Неизвестный статус


@dataclass
class DPICheckResult:
    """Результат проверки на DPI"""
    domain: str
    status: DPIStatus
    method: str = ""  # Метод обнаружения (TCP 16-20, SNI, etc.)
    zapret_params: str = ""  # Рекомендуемые параметры zapret
    raw_output: str = ""  # Сырой вывод blockcheck
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())
    error: str = ""
    returncode: int = 0  # Код возврата blockcheck

    @profiler
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status.value,
            "method": self.method,
            "zapret_params": self.zapret_params,
            "checked_at": self.checked_at,
            "error": self.error,
            "returncode": self.returncode
        }


class DPIDetector:
    """
    Детектор DPI блокировок
    
    Использует blockcheck.sh из Zapret для обнаружения блокировок
    и подбора рабочих параметров обхода.
    """
    
    # Пути к blockcheck.sh (ищем в нескольких местах)
    BLOCKCHECK_PATHS = [
        "./zapret-src/zapret-v72.12/blockcheck.sh",
        "./zapret-src/blockcheck.sh",
        "../zapret-src/zapret-v72.12/blockcheck.sh",
        "/opt/zapret/blockcheck.sh",
        "/usr/local/bin/blockcheck.sh",
    ]
    
    # Паттерны для парсинга вывода blockcheck.sh
    PATTERNS = {
        # Успешные методы обхода
        "success": re.compile(
            r'(?:SUCCESS|WORKS|OK|passed)\s*[:\-]?\s*(.+)',
            re.IGNORECASE
        ),
        # Параметры zapret
        "zapret_params": re.compile(
            r'--dpi-desync[=\s][^\s]+(?:\s+--dpi-desync[^\s]+)*',
            re.IGNORECASE
        ),
        # DPI обнаружен
        "dpi_detected": re.compile(
            r'(?:DPI|blocking|blocked|reset|injection)',
            re.IGNORECASE
        ),
        # IP блокировка
        "ip_blocked": re.compile(
            r'(?:IP block|IP blocked|no route|unreachable)',
            re.IGNORECASE
        ),
        # DNS блокировка
        "dns_blocked": re.compile(
            r'(?:DNS|NXDOMAIN|SERVFAIL|refused)',
            re.IGNORECASE
        ),
        # TCP 16-20 test
        "tcp_16_20": re.compile(
            r'(?:TCP.*16|16.*20|hyperion)',
            re.IGNORECASE
        ),
        # SNI test
        "sni_test": re.compile(
            r'(?:SNI|TLS|ClientHello|ServerHello)',
            re.IGNORECASE
        ),
        # RST injection
        "rst_injection": re.compile(
            r'(?:RST|reset|injection|fake)',
            re.IGNORECASE
        ),
    }
    
    @profiler
    def __init__(self, zapret_src_dir: Optional[str] = None,
                 blockcheck_path: Optional[str] = None,
                 use_sudo: bool = False):
        """
        Инициализация детектора

        Args:
            zapret_src_dir: Путь к исходникам Zapret (где лежит blockcheck.sh)
            blockcheck_path: Прямой путь к blockcheck.sh (имеет приоритет)
            use_sudo: Использовать sudo для запуска blockcheck.sh
        """
        self.zapret_src_dir = zapret_src_dir
        self.explicit_blockcheck_path = blockcheck_path
        self.use_sudo = use_sudo
        self.blockcheck_path = self._find_blockcheck()
        
    @profiler
    def _find_blockcheck(self) -> Optional[Path]:
        """Поиск blockcheck.sh"""
        # Сначала проверяем явный путь (из конфига)
        if self.explicit_blockcheck_path:
            path = Path(self.explicit_blockcheck_path)
            if path.exists():
                logger.info(f"Using explicit blockcheck.sh at {path}")
                return path
        
        # Проверяем заданный путь к исходникам
        if self.zapret_src_dir:
            path = Path(self.zapret_src_dir) / "blockcheck.sh"
            if path.exists():
                logger.info(f"Found blockcheck.sh at {path}")
                return path

        # Ищем в стандартных местах
        for path_str in self.BLOCKCHECK_PATHS:
            path = Path(path_str)
            if path.exists():
                logger.info(f"Found blockcheck.sh at {path}")
                return path

        logger.warning("blockcheck.sh not found")
        return None
    
    @profiler
    async def check_domain(self, domain: str, timeout: int = 60) -> DPICheckResult:
        """
        Проверка домена на DPI блокировку

        Args:
            domain: Домен для проверки
            timeout: Таймаут проверки в секундах

        Returns:
            Результат проверки
        """
        logger.info(f"[dpi_detector] Starting DPI check for {domain}")

        # Проверяем наличие blockcheck.sh и что мы не на Windows
        if self.blockcheck_path and os.name != 'nt':
            logger.debug(f"[dpi_detector] Using blockcheck.sh at {self.blockcheck_path}")
            try:
                # Запускаем blockcheck.sh
                logger.info(f"[dpi_detector] Running blockcheck.sh for {domain}...")
                output, returncode = await self._run_blockcheck(domain, timeout)

                # Парсим вывод
                logger.debug(f"[dpi_detector] Parsing blockcheck output (returncode={returncode})...")
                return self._parse_blockcheck_output(domain, output, returncode)

            except asyncio.TimeoutError:
                logger.warning(f"[dpi_detector] blockcheck.sh timeout for {domain}")
                return DPICheckResult(
                    domain=domain,
                    status=DPIStatus.ERROR,
                    error="blockcheck.sh timeout",
                    returncode=-1
                )
            except Exception as e:
                logger.warning(f"[dpi_detector] blockcheck.sh failed for {domain}: {e}, using fallback")

        # Fallback: используем встроенний детектор
        logger.warning("[dpi_detector] blockcheck.sh not available, using fallback detector")
        return await self._fallback_check(domain)
    
    @profiler
    async def _run_blockcheck(self, domain: str, timeout: int) -> Tuple[str, int]:
        """
        Запуск blockcheck.sh

        Returns:
            (вывод, код возврата)
        """
        cmd = []
        if self.use_sudo:
            cmd.append("sudo")
        cmd.extend([
            str(self.blockcheck_path),
            domain,
            "--timeout", str(timeout),
        ])

        logger.debug(f"Running: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 10  # Добавляем 10 сек на запуск
            )

            output = stdout.decode('utf-8', errors='ignore')
            if stderr:
                output += "\n" + stderr.decode('utf-8', errors='ignore')

            return output, process.returncode

        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
    
    @profiler
    def _parse_blockcheck_output(self, domain: str, output: str, returncode: int = 0) -> DPICheckResult:
        """Парсинг вывода blockcheck.sh"""
        logger.debug(f"Parsing blockcheck output for {domain}, returncode={returncode}")

        # Учитываем код возврата
        if returncode == 127:
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.ERROR,
                error="blockcheck.sh not found or not executable",
                returncode=returncode,
                raw_output=output[:10000]
            )
        elif returncode == 126:
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.ERROR,
                error="blockcheck.sh not executable",
                returncode=returncode,
                raw_output=output[:10000]
            )
        elif returncode == 2:
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.ERROR,
                error="blockcheck.sh usage error",
                returncode=returncode,
                raw_output=output[:10000]
            )
        elif returncode is not None and returncode > 10:
            # Сигналы и другие ошибки
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.ERROR,
                error=f"blockcheck.sh crashed with code {returncode}",
                returncode=returncode,
                raw_output=output[:10000]
            )

        # Ищем успешные методы обхода
        success_match = self.PATTERNS["success"].search(output)
        zapret_params_match = self.PATTERNS["zapret_params"].search(output)

        # Определяем статус
        status = DPIStatus.UNKNOWN
        method = ""

        # Проверяем на IP блокировку
        if self.PATTERNS["ip_blocked"].search(output):
            status = DPIStatus.IP_BLOCKED
            method = "IP block detected"
        # Проверяем на DNS блокировку
        elif self.PATTERNS["dns_blocked"].search(output):
            status = DPIStatus.DNS_BLOCKED
            method = "DNS block detected"
        # Есть успешные параметры
        elif success_match and zapret_params_match:
            status = DPIStatus.DPI_DETECTED
            method = success_match.group(1).strip()
        # DPI обнаружен по другим признакам
        elif self.PATTERNS["dpi_detected"].search(output):
            # Проверяем есть ли признаки что DPI нет
            if "no blocking" in output.lower() or "works without parameters" in output.lower():
                status = DPIStatus.NO_DPI
                method = "No blocking detected"
            else:
                status = DPIStatus.DPI_DETECTED
                method = "DPI signatures detected"
        # Нет явных признаков - анализируем дальше
        else:
            # Если есть SUCCESS или WORKS - значит DPI нет
            if "SUCCESS" in output.upper() or "WORKS" in output.upper():
                status = DPIStatus.NO_DPI
                method = "No blocking detected"
            elif "no dpi" in output.lower():
                status = DPIStatus.NO_DPI
                method = "No DPI detected"
            elif returncode == 0:
                # Успешный запуск но без явных результатов
                status = DPIStatus.UNKNOWN
                method = "Inconclusive result"
            else:
                # Ошибка или неизвестная проблема
                status = DPIStatus.ERROR
                method = "Unknown error during check"

        # Извлекаем параметры zapret
        zapret_params = ""
        if zapret_params_match:
            zapret_params = zapret_params_match.group(0)

        return DPICheckResult(
            domain=domain,
            status=status,
            method=method,
            zapret_params=zapret_params,
            raw_output=output[:10000],
            returncode=returncode
        )
    
    @profiler
    async def _fallback_check(self, domain: str) -> DPICheckResult:
        """
        Резервный детектор (если blockcheck.sh не найден)

        Использует простые TCP/TLS тесты
        """
        logger.info(f"[dpi_detector] Running fallback check for {domain}...")
        
        try:
            # Пробуем разрешить домен
            logger.debug(f"[dpi_detector] Testing DNS resolution for {domain}...")
            dns_result = await self._dns_resolve_test(domain)

            # Временные DNS ошибки - считаем ошибкой а не блокировкой
            if dns_result.get("error_type") == "temporary":
                logger.debug(f"[dpi_detector] Temporary DNS error for {domain}")
                return DPICheckResult(
                    domain=domain,
                    status=DPIStatus.ERROR,
                    method="Temporary DNS error",
                    error=dns_result.get("error", "")
                )

            # Постоянные DNS ошибки - считаем блокировкой
            if dns_result.get("blocked"):
                logger.info(f"[dpi_detector] DNS blocked for {domain}")
                return DPICheckResult(
                    domain=domain,
                    status=DPIStatus.DNS_BLOCKED,
                    method="DNS resolution failed (permanent)",
                    error=dns_result.get("error", "")
                )

            # Пробуем TCP соединение
            logger.debug(f"[dpi_detector] Testing TCP connection for {domain}...")
            tcp_result = await self._tcp_connect_test(domain)

            if tcp_result["blocked"]:
                error = tcp_result.get("error", "")
                logger.info(f"[dpi_detector] TCP blocked for {domain}: {error[:50]}...")
                # Различаем типы ошибок
                if "refused" in error.lower():
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.ERROR,
                        method="Connection refused (server down)",
                        error=error
                    )
                elif "no route" in error.lower() or "unreachable" in error.lower():
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.IP_BLOCKED,
                        method="IP unreachable",
                        error=error
                    )
                else:
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.DPI_DETECTED,
                        method="TCP connection blocked",
                        zapret_params="--dpi-desync=fake --dpi-desync-fooling=md5sig",
                        error=error
                    )

            # Пробуем TLS handshake
            logger.debug(f"[dpi_detector] Testing TLS handshake for {domain}...")
            tls_result = await self._tls_handshake_test(domain)

            if tls_result["blocked"]:
                error = tls_result.get("error", "")
                # Различаем TLS ошибки
                if "certificate" in error.lower() or "cert" in error.lower():
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.ERROR,
                        method="TLS certificate error",
                        error=error
                    )
                elif "reset" in error.lower() or "rst" in error.lower():
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.DPI_DETECTED,
                        method="TLS handshake reset (DPI)",
                        zapret_params="--dpi-desync=split --dpi-desync-split-pos=1,midsld"
                    )
                elif "handshake" in error.lower():
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.DPI_DETECTED,
                        method="TLS handshake failed (DPI)",
                        zapret_params="--dpi-desync=split --dpi-desync-split-pos=1,midsld",
                        error=error
                    )
                else:
                    # Другие TLS ошибки - считаем ошибкой
                    return DPICheckResult(
                        domain=domain,
                        status=DPIStatus.ERROR,
                        method="TLS error",
                        error=error
                    )

            # Блокировка не обнаружена
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.NO_DPI,
                method="No blocking detected"
            )

        except Exception as e:
            return DPICheckResult(
                domain=domain,
                status=DPIStatus.ERROR,
                error=str(e)
            )
    
    @profiler
    async def _dns_resolve_test(self, domain: str) -> Dict[str, Any]:
        """
        DNS resolution test

        Returns:
            {"blocked": bool, "error": str, "ips": list, "error_type": str}
            error_type: "permanent" (EAI_NONAME/NODATA) или "temporary" (временная ошибка)
        """
        import socket

        loop = asyncio.get_event_loop()

        @profiler
        def resolve() -> Tuple[bool, str, List[str], str]:
            try:
                # Получаем все адреса для домена
                addr_info = socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if not addr_info:
                    return True, "No addresses found", [], "permanent"

                ips = list(set([ai[4][0] for ai in addr_info]))
                return False, "", ips, ""  # Не заблокировано
            except socket.gaierror as e:
                # Различаем типы DNS ошибок
                if e.errno in (socket.EAI_NONAME, socket.EAI_NODATA):
                    # Домен действительно не существует или намеренно заблокирован
                    return True, f"DNS resolution failed: {e}", [], "permanent"
                elif e.errno == socket.EAI_AGAIN:
                    # Временная ошибка DNS - не считаем блокировкой
                    return False, f"Temporary DNS error: {e}", [], "temporary"
                else:
                    # Другие ошибки DNS - считаем ошибкой а не блокировкой
                    return False, f"DNS error: {e}", [], "temporary"
            except Exception as e:
                # Общие ошибки - считаем временными
                return False, f"DNS error: {e}", [], "temporary"

        blocked, error, ips, error_type = await loop.run_in_executor(None, resolve)

        return {
            "blocked": blocked,
            "error": error,
            "ips": ips,
            "error_type": error_type
        }

    @profiler
    async def _tcp_connect_test(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        TCP connection test с поддержкой IPv6

        Returns:
            {"blocked": bool, "error": str, "time": float}
        """
        import socket
        import time

        loop = asyncio.get_event_loop()

        @profiler
        def connect() -> Tuple[bool, str]:
            # Получаем информацию об адресах
            try:
                addr_info = socket.getaddrinfo(domain, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except socket.gaierror as e:
                return True, f"DNS resolution failed: {e}"

            # Пробуем все адреса
            for family, socktype, proto, canonname, sockaddr in addr_info:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(10)
                try:
                    sock.connect(sockaddr)
                    sock.close()
                    return False, ""  # Не заблокировано
                except socket.timeout:
                    sock.close()
                    continue  # Пробуем следующий адрес
                except socket.error as e:
                    sock.close()
                    # Запоминаем ошибку но пробуем другие адреса
                    last_error = str(e)
            else:
                # Все адреса не сработали
                return True, last_error if 'last_error' in locals() else "All addresses failed"

            return True, "No reachable addresses"

        start_time = time.time()
        blocked, error = await loop.run_in_executor(None, connect)
        elapsed = time.time() - start_time

        return {
            "blocked": blocked,
            "error": error,
            "time": elapsed
        }
    
    @profiler
    async def _tls_handshake_test(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        TLS handshake test с поддержкой IPv6

        Returns:
            {"blocked": bool, "error": str, "time": float, "errors_by_address": dict}
        """
        import socket
        import ssl
        import time

        loop = asyncio.get_event_loop()

        @profiler
        def handshake() -> Tuple[bool, str, Dict[str, str]]:
            # Получаем информацию об адресах
            try:
                addr_info = socket.getaddrinfo(domain, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except socket.gaierror as e:
                return True, f"DNS resolution failed: {e}", {}

            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            errors_by_address = {}
            last_error = None

            # Пробуем все адреса по очереди
            for family, socktype, proto, canonname, sockaddr in addr_info:
                sock = None
                wrapped = None
                addr_str = f"{sockaddr[0]}:{sockaddr[1]}" if len(sockaddr) >= 2 else str(sockaddr)
                
                try:
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(10)
                    wrapped = context.wrap_socket(sock, server_hostname=domain)
                    wrapped.connect(sockaddr)
                    # Успех - хотя бы один адрес сработал
                    return False, "", errors_by_address
                except ssl.SSLCertVerificationError as e:
                    # Ошибка сертификата - не DPI, но и не успех
                    errors_by_address[addr_str] = f"SSL certificate error: {e}"
                    last_error = errors_by_address[addr_str]
                    # Не пробуем другие адреса - ошибка сертификата одинакова для всех
                    break
                except ssl.SSLError as e:
                    # Различаем типы SSL ошибок - некоторые не фатальны
                    error_str = str(e)
                    if "reset" in error_str.lower() or "connection reset" in error_str.lower():
                        # RST - вероятный DPI, пробуем другие адреса
                        errors_by_address[addr_str] = f"TLS connection reset (possible DPI): {e}"
                        last_error = errors_by_address[addr_str]
                    elif "handshake" in error_str.lower():
                        # Ошибка handshake - пробуем другие адреса
                        errors_by_address[addr_str] = f"TLS handshake failed: {e}"
                        last_error = errors_by_address[addr_str]
                    elif "timeout" in error_str.lower() or "timed out" in error_str.lower():
                        # Таймаут - пробуем другие адреса
                        errors_by_address[addr_str] = f"TLS timeout: {e}"
                        last_error = errors_by_address[addr_str]
                    else:
                        # Другие SSL ошибки - запоминаем и пробуем дальше
                        errors_by_address[addr_str] = f"SSL error: {e}"
                        last_error = errors_by_address[addr_str]
                except socket.timeout:
                    errors_by_address[addr_str] = "Socket timeout"
                    last_error = errors_by_address[addr_str]
                    continue
                except socket.error as e:
                    errors_by_address[addr_str] = f"Socket error: {e}"
                    last_error = errors_by_address[addr_str]
                    continue
                except Exception as e:
                    errors_by_address[addr_str] = f"Unexpected error: {e}"
                    last_error = errors_by_address[addr_str]
                finally:
                    # Закрываем в обратном порядке
                    if wrapped is not None:
                        try:
                            wrapped.close()
                        except:
                            pass
                    elif sock is not None:
                        try:
                            sock.close()
                        except:
                            pass

            # Все адреса не сработали
            if not last_error:
                last_error = "No reachable addresses"
            
            # Определяем тип блокировки по ошибкам
            # Если все ошибки "reset" или "handshake" - вероятно DPI
            all_errors = " ".join(errors_by_address.values())
            is_dpi = "reset" in all_errors.lower() or "handshake" in all_errors.lower()
            
            return True, last_error, errors_by_address

        start_time = time.time()
        blocked, error, errors_by_address = await loop.run_in_executor(None, handshake)
        elapsed = time.time() - start_time

        return {
            "blocked": blocked,
            "error": error,
            "time": elapsed,
            "errors_by_address": errors_by_address
        }
    
    @profiler
    async def quick_check(self, domain: str) -> bool:
        """
        Быстрая проверка на DPI (без подбора параметров)
        
        Returns:
            True если DPI обнаружен
        """
        result = await self.check_domain(domain, timeout=30)
        return result.status in [DPIStatus.DPI_DETECTED, DPIStatus.IP_BLOCKED]


# Глобальный экземпляр детектора
_detector: Optional[DPIDetector] = None
_detector_params: Dict[str, Any] = {}  # Запоминаем параметры для детектора


@profiler
def get_detector(zapret_src_dir: Optional[str] = None,
                 blockcheck_path: Optional[str] = None,
                 use_sudo: bool = False) -> DPIDetector:
    """Получить глобальный экземпляр детектора"""
    global _detector, _detector_params
    
    # Текущие параметры
    current_params = {
        'zapret_src_dir': zapret_src_dir,
        'blockcheck_path': blockcheck_path,
        'use_sudo': use_sudo
    }
    
    # Если параметры изменились или детектор ещё не создан - пересоздаём
    if _detector is None or _detector_params != current_params:
        _detector = DPIDetector(zapret_src_dir, blockcheck_path, use_sudo)
        _detector_params = current_params
    
    return _detector
