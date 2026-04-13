"""
Общие утилиты для Auto-Zapret
"""

import ipaddress
import re
from typing import Union

from .utils.profiler import get_profiler

profiler = get_profiler("utils")

# Паттерн для проверки IPv4
_IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


@profiler
def is_ip_address(host: str) -> bool:
    """
    Проверка является ли строка IP адресом (IPv4 или IPv6)
    
    Args:
        host: Строка для проверки
        
    Returns:
        True если это IP адрес
    """
    host = host.strip()
    
    # Проверяем IPv4
    if _IPV4_PATTERN.match(host):
        try:
            ipaddress.IPv4Address(host)
            return True
        except ipaddress.AddressValueError:
            return False
    
    # Проверяем IPv6
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    
    try:
        ipaddress.IPv6Address(host)
        return True
    except ipaddress.AddressValueError:
        return False


@profiler
def normalize_domain(domain: str) -> str:
    """
    Нормализация домена: lower-case, убирание точки в конце, trim пробелов

    Args:
        domain: Домен для нормализации

    Returns:
        Нормализованный домен (или IP без изменений)
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
