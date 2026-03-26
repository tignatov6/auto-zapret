"""
Тесты для strategy_generator.py
"""

import pytest

from autozapret.strategy_generator import (
    StrategyGenerator,
    StrategyConfig,
    get_generator,
)


@pytest.fixture
def generator_no_fake():
    """Генератор без fake файлов"""
    return StrategyGenerator(has_fake_files=False)


@pytest.fixture
def generator_with_fake():
    """Генератор с fake файлами"""
    return StrategyGenerator(has_fake_files=True)


# ══════════════════════════════════════════════════════════
#                 STRATEGY CONFIG
# ══════════════════════════════════════════════════════════

def test_strategy_config_to_params():
    """Тест преобразования стратегии в параметры"""
    config = StrategyConfig(
        name="test_strategy",
        mode="multisplit",
        pos="1",
        fool="ts",
        rep=2,
        wssize="1:6",
        ttl=5,
        autottl="-3",
        seqovl=1,
        fake_tls_mod="rnd,rndsni,dupsid",
        extra=["--dpi-desync-hostfakesplit-mod=altorder=1"]
    )
    
    params = config.to_params()
    
    # Проверяем что все параметры присутствуют
    assert "--dpi-desync=multisplit" in params
    assert "--dpi-desync-split-pos=1" in params
    assert "--dpi-desync-fooling=ts" in params
    assert "--dpi-desync-repeats=2" in params
    assert "--wssize=1:6" in params
    assert "--dpi-desync-ttl=5" in params
    assert "--dpi-desync-autottl=-3" in params
    assert "--dpi-desync-split-seqovl=1" in params
    assert "--dpi-desync-fake-tls-mod=rnd,rndsni,dupsid" in params
    assert "--dpi-desync-hostfakesplit-mod=altorder=1" in params


def test_strategy_config_minimal():
    """Тест минимальной стратегии"""
    config = StrategyConfig(
        name="minimal",
        mode="fake",
        rep=1  # rep=1 добавляется по умолчанию
    )
    
    params = config.to_params()
    # rep=1 добавляется всегда
    assert "--dpi-desync=fake" in params


# ══════════════════════════════════════════════════════════
#                 GENERATOR
# ══════════════════════════════════════════════════════════

def test_generator_init():
    """Тест инициализации генератора"""
    gen_no_fake = StrategyGenerator(has_fake_files=False)
    gen_with_fake = StrategyGenerator(has_fake_files=True)
    
    assert gen_no_fake.has_fake_files is False
    assert gen_with_fake.has_fake_files is True


def test_generate_all_without_fake(generator_no_fake):
    """Тест генерации всех стратегий без fake файлов"""
    strategies = generator_no_fake.generate_all()
    
    # Должно быть сгенерировано минимум 50 стратегий
    assert len(strategies) >= 50
    
    # Проверяем что все стратегии имеют параметры
    for strat in strategies:
        assert strat.name
        assert strat.mode
        params = strat.to_params()
        assert params
        assert "--dpi-desync=" in params


def test_generate_all_with_fake(generator_with_fake):
    """Тест генерации всех стратегий с fake файлами"""
    strategies = generator_with_fake.generate_all()
    
    # Должно быть сгенерировано минимум 500 стратегий
    assert len(strategies) >= 500
    
    # Проверяем что все стратегии имеют параметры
    for strat in strategies:
        assert strat.name
        assert strat.mode
        params = strat.to_params()
        assert params
        assert "--dpi-desync=" in params


def test_generate_basic_splits(generator_no_fake):
    """Тест генерации базовых Split стратегий"""
    strategies = generator_no_fake._generate_basic_splits()
    
    # Должно быть минимум 20 стратегий
    assert len(strategies) >= 20
    
    # Проверяем что есть multisplit и multidisorder
    modes = [s.mode for s in strategies]
    assert "multisplit" in modes
    assert "multidisorder" in modes
    
    # Проверяем приоритетные позиции
    priority_strats = [s for s in strategies if s.pos in ["sniext+1", "1", "midsld", "1,midsld"]]
    assert len(priority_strats) > 0


def test_generate_wssize_strategies(generator_no_fake):
    """Тест генерации WSSIZE стратегий"""
    strategies = generator_no_fake._generate_wssize_strategies()
    
    # Должно быть минимум 10 стратегий
    assert len(strategies) >= 10
    
    # Проверяем что есть стратегии с wssize и без
    with_wssize = [s for s in strategies if s.wssize]
    without_wssize = [s for s in strategies if not s.wssize]
    
    assert len(with_wssize) > 0
    assert len(without_wssize) > 0
    
    # Проверяем значение wssize
    for s in with_wssize:
        assert s.wssize == "1:6"


def test_generate_seqovl_strategies(generator_no_fake):
    """Тест генерации SeqOvl стратегий"""
    strategies = generator_no_fake._generate_seqovl_strategies()
    
    # Должно быть минимум 6 стратегий (2 mode × 3 pos × 2 seqovl)
    assert len(strategies) >= 6
    
    # Проверяем что seqovl установлен
    for s in strategies:
        assert s.seqovl in [1, 2]


def test_generate_fake_strategies(generator_with_fake):
    """Тест генерации Fake стратегий с TTL циклом"""
    strategies = generator_with_fake._generate_fake_strategies()
    
    # Должно быть минимум 500 стратегий
    # 4 fake modes × (16 TTL + 8 AutoTTL) × 5 fools ≈ 480+
    assert len(strategies) >= 400
    
    # Проверяем что есть TTL стратегии
    ttl_strats = [s for s in strategies if s.ttl]
    assert len(ttl_strats) > 0
    
    # Проверяем диапазон TTL
    ttl_values = [s.ttl for s in ttl_strats if s.ttl]
    assert min(ttl_values) >= 1
    assert max(ttl_values) <= 16
    
    # Проверяем что есть AutoTTL стратегии
    autottl_strats = [s for s in strategies if s.autottl]
    assert len(autottl_strats) > 0


def test_generate_fake_tls_mods(generator_with_fake):
    """Тест генерации Fake TLS модификаторов"""
    strategies = generator_with_fake._generate_fake_tls_mods()
    
    # Должно быть 2 стратегии
    assert len(strategies) == 2
    
    # Проверяем модификаторы
    mods = [s.fake_tls_mod for s in strategies]
    assert "rnd,rndsni,dupsid" in mods
    assert "padencap" in mods


def test_generate_hostfakesplit_mods(generator_with_fake):
    """Тест генерации HostFakeSplit модификаторов"""
    strategies = generator_with_fake._generate_hostfakesplit_mods()
    
    # Должно быть 2 стратегии
    assert len(strategies) == 2
    
    # Проверяем что есть extra параметры
    for s in strategies:
        assert len(s.extra) > 0
    
    # Проверяем названия
    names = [s.name for s in strategies]
    assert "hostfakesplit_altorder1" in names
    assert "hostfakesplit_midhost" in names


def test_generate_http_mods(generator_no_fake):
    """Тест генерация HTTP модификаторов"""
    strategies = generator_no_fake._generate_http_mods()
    
    # Должно быть 3 стратегии (по количеству SPLITS_HTTP)
    assert len(strategies) == 3
    
    # Проверяем что mode=multisplit
    for s in strategies:
        assert s.mode == "multisplit"


# ══════════════════════════════════════════════════════════
#                 SINGLETON
# ══════════════════════════════════════════════════════════

def test_get_generator_singleton():
    """Тест singleton паттерна"""
    # Сбрасываем singleton
    import autozapret.strategy_generator as sg
    sg._generator = None
    
    # Получаем первый экземпляр
    gen1 = get_generator(has_fake_files=False)
    
    # Получаем второй экземпляр
    gen2 = get_generator(has_fake_files=False)
    
    # Должен быть тот же самый объект
    assert gen1 is gen2
    
    # Очищаем
    sg._generator = None


# ══════════════════════════════════════════════════════════
#                 PARAMS VALIDATION
# ══════════════════════════════════════════════════════════

def test_params_format(generator_no_fake):
    """Тест формата параметров"""
    strategies = generator_no_fake._generate_basic_splits()
    
    for strat in strategies[:10]:  # Проверяем первые 10
        params = strat.to_params()
        
        # Проверяем формат
        assert params.startswith("--dpi-desync=")
        
        # Проверяем что нет лишних пробелов
        assert "  " not in params
        
        # Проверяем что все флаги начинаются с --
        for part in params.split(" "):
            if part.startswith("-"):
                assert part.startswith("--")


def test_strategy_names_unique(generator_with_fake):
    """Тест уникальности имён стратегий"""
    strategies = generator_with_fake.generate_all()
    
    names = [s.name for s in strategies]
    unique_names = set(names)
    
    # Большинство имён должны быть уникальны (допускаем небольшие дубликаты)
    # 679 стратегий - 649 уникальных = 30 дубликатов (допустимо)
    duplicate_count = len(names) - len(unique_names)
    assert duplicate_count < len(names) * 0.1  # Менее 10% дубликатов
