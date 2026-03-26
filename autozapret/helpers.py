"""
Общие утилиты для Auto-Zapret
"""

from .utils.profiler import get_profiler

profiler = get_profiler("utils")


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
