# Файл: profiler.py

import time
import threading
import collections
from contextlib import ContextDecorator
from typing import Dict, List, Callable, Any, Union

_LOCK = threading.Lock()
# { module_name: { section_name: [total_time, calls] } }
_STATS: Dict[str, Dict[str, List[Union[float, int]]]] = collections.defaultdict(
    lambda: collections.defaultdict(lambda: [0.0, 0])
)

_IS_ENABLED = True # Глобальный флаг для включения/отключения профилирования

def enable_profiling(enable: bool = True):
    """Включает или отключает сбор статистики профайлером."""
    global _IS_ENABLED
    _IS_ENABLED = enable

def is_profiling_enabled() -> bool:
    """Проверяет, включено ли профилирование."""
    return _IS_ENABLED

class _Section(ContextDecorator):
    def __init__(self, module_name: str, section_name: str,
                 stats_dict: Dict[str, Dict[str, List[Union[float, int]]]] = _STATS,
                 lock: threading.Lock = _LOCK):
        self.module_name = module_name
        self.section_name = section_name
        self.t0: float = 0.0
        self.stats_dict = stats_dict # Куда записывать статистику
        self.lock = lock             # Какой лок использовать

    def __enter__(self) -> '_Section':
        if is_profiling_enabled():
            self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if is_profiling_enabled():
            dt = time.perf_counter() - self.t0
            with self.lock:
                entry = self.stats_dict[self.module_name][self.section_name]
                entry[0] += dt
                entry[1] += 1

    async def __aenter__(self) -> '_Section':
        if is_profiling_enabled():
            self.t0 = time.perf_counter()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if is_profiling_enabled():
            dt = time.perf_counter() - self.t0
            with self.lock:
                entry = self.stats_dict[self.module_name][self.section_name]
                entry[0] += dt
                entry[1] += 1

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Декорирование функций (синхронных и асинхронных)"""
        if not is_profiling_enabled():
            return func
        
        import asyncio
        import functools
        
        if asyncio.iscoroutinefunction(func):
            # Асинхронная функция
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                async with self:
                    return await func(*args, **kwargs)
            return async_wrapper
        else:
            # Синхронная функция - используем стандартный механизм ContextDecorator
            return super().__call__(func)

class _Profiler:
    def __init__(self, module_name: str,
                 target_stats_dict: Dict[str, Dict[str, List[Union[float, int]]]] = _STATS,
                 target_lock: threading.Lock = _LOCK):
        self.module_name = module_name
        self.target_stats_dict = target_stats_dict # По умолчанию глобальный _STATS
        self.target_lock = target_lock             # По умолчанию глобальный _LOCK

    def __call__(self, arg: Union[str, Callable[..., Any]]):
        if not is_profiling_enabled(): # Если профилирование отключено
            if callable(arg) and not isinstance(arg, str): # Используется как декоратор @profiler
                return arg # Возвращаем оригинальную функцию, без обертки
            elif isinstance(arg, str): # Используется как менеджер контекста: with profiler("name")
                # Возвращаем "пустой" объект _Section.
                # Его методы __enter__/__exit__ ничего не сделают, т.к. is_profiling_enabled() == False.
                # Передаем "пустые" словари/блокировки, так как они не будут использоваться.
                return _Section(self.module_name, arg, stats_dict={}, lock=threading.Lock())
            else:
                # Обработка других непредвиденных типов arg, если профилирование отключено.
                # Возврат "пустого" _Section является безопасным вариантом для предотвращения TypeError.
                return _Section(self.module_name, "unexpected_profiler_arg_when_disabled", stats_dict={}, lock=threading.Lock())

        # Если профилирование ВКЛЮЧЕНО:
        if callable(arg) and not isinstance(arg, str):
            func_to_profile: Callable[..., Any] = arg
            section_name: str = func_to_profile.__name__
            # Создаем _Section с указанием, куда сохранять статистику
            return _Section(self.module_name, section_name, self.target_stats_dict, self.target_lock)(func_to_profile)
        elif isinstance(arg, str):
            section_name_str: str = arg
            return _Section(self.module_name, section_name_str, self.target_stats_dict, self.target_lock)
        else:
            raise TypeError(
                "Profiler argument must be a section name (str) or a callable."
            )

    def __getattr__(self, section_name: str) -> _Section:
        if not is_profiling_enabled(): # Если профилирование отключено
             # Возвращаем "пустышку" _Section, которая ничего не делает
            return _Section(self.module_name, section_name, {}, threading.Lock())


        if section_name.startswith("__"):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{section_name}'")
        return _Section(self.module_name, section_name, self.target_stats_dict, self.target_lock)


def get_profiler(module_name: str) -> _Profiler:
    """
    Возвращает профайлер, «привязанный» к module_name.
    Статистика по умолчанию пишется в глобальный _STATS.
    """
    return _Profiler(module_name)

def get_local_profiler(module_name: str,
                        local_stats_dict: Dict[str, Dict[str, List[Union[float, int]]]],
                        local_lock: threading.Lock) -> _Profiler:
    """
    Возвращает профайлер, который будет писать статистику в предоставленный
    local_stats_dict, используя local_lock.
    Полезно для сбора статистики в воркерах.
    """
    return _Profiler(module_name, target_stats_dict=local_stats_dict, target_lock=local_lock)


def merge_stats(source_stats: Dict[str, Dict[str, List[Union[float, int]]]],
                target_stats: Dict[str, Dict[str, List[Union[float, int]]]] = _STATS,
                lock: threading.Lock = _LOCK) -> None:
    """
    Объединяет статистику из source_stats в target_stats (по умолчанию в глобальный _STATS).
    Ожидается, что структура source_stats такая же, как у _STATS.
    """
    if not is_profiling_enabled() or not source_stats:
        return

    with lock:
        for mod_name, sections in source_stats.items():
            if not isinstance(sections, collections.defaultdict) and not isinstance(sections, dict):
                # print(f"Profiler: Skipping merge for module '{mod_name}': sections is not a dict.")
                continue
            target_mod_sections = target_stats[mod_name] # Это defaultdict
            for sect_name, (time_val, calls_val) in sections.items():
                if not isinstance(time_val, (int, float)) or not isinstance(calls_val, int):
                    # print(f"Profiler: Skipping merge for section '{mod_name}.{sect_name}': invalid data types.")
                    continue

                target_entry = target_mod_sections[sect_name]
                target_entry[0] += time_val
                target_entry[1] += calls_val

def clear_stats() -> None:
    """Очищает всю собранную статистику."""
    with _LOCK:
        _STATS.clear()

def report(sort_by: str = "time", target_stats: Dict[str, Dict[str, List[Union[float, int]]]] = _STATS, logger_obj=None) -> None:
    """
    Выводит сводку из target_stats (по умолчанию из глобального _STATS).
    sort_by = 'time' | 'calls'
    logger_obj = logger для вывода (если None, использует print)
    """
    def log(msg):
        if logger_obj:
            logger_obj.info(msg)
        else:
            print(msg)
    
    if not is_profiling_enabled():
        log("\n─── MiniProfiler report (profiling disabled) ───")
        log("─────────────────────────────\n")
        return

    with _LOCK:
        log("\n─── MiniProfiler report ───")
        if not target_stats:
            log("  No profiling data collected.")
            log("─────────────────────────────\n")
            return

        sorted_modules = sorted(target_stats.items(), key=lambda item: item[0])

        for mod, sects in sorted_modules:
            if not isinstance(sects, collections.defaultdict) and not isinstance(sects, dict):
                log(f"  Module '{mod}' has invalid section data type: {type(sects)}")
                continue

            total_mod_time: float = sum(s[0] for s in sects.values() if isinstance(s, list) and len(s) > 0 and isinstance(s[0], (float,int)))

            log(f"\n[{mod}]  total {total_mod_time:.3f} s")

            if sort_by == "time":
                key_func = lambda kv_pair: kv_pair[1][0] if isinstance(kv_pair[1], list) and len(kv_pair[1]) > 0 else 0
            elif sort_by == "calls":
                key_func = lambda kv_pair: kv_pair[1][1] if isinstance(kv_pair[1], list) and len(kv_pair[1]) > 1 else 0
            else:
                key_func = lambda kv_pair: kv_pair[1][0] if isinstance(kv_pair[1], list) and len(kv_pair[1]) > 0 else 0

            try:
                valid_sects = {k: v for k, v in sects.items() if isinstance(v, list) and len(v) == 2 and isinstance(v[0], (float, int)) and isinstance(v[1], int)}
                rows = sorted(valid_sects.items(), key=key_func, reverse=True)
            except Exception as e:
                log(f"  Error sorting sections for module {mod}: {e}")
                continue

            total_for_perc = sum(r[1][0] for r in rows)
            if abs(total_for_perc) < 1e-9:
                total_for_perc = 1e-9

            for name, (tt, n) in rows:
                perc: float = (tt / total_for_perc) * 100 if total_for_perc != 0 else 0
                log(f"  {name:30s}: {tt:7.3f}s  | {perc:5.1f}% | {n:7d}×")
        log("─────────────────────────────\n")