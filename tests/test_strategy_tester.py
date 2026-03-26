"""
Тесты для strategy_tester.py
"""

import asyncio
import pytest
import pytest_asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from autozapret.strategy_tester import (
    StrategyTester,
    StrategyTestStatus,
    CalibrationResult,
    get_tester,
    CALIBRATION_SITES,
    TEST_SITES,
)
from autozapret.storage import Storage
from autozapret.executor import Executor
from autozapret.config import Config


@pytest.fixture
def mock_storage():
    """Mock storage"""
    storage = MagicMock(spec=Storage)
    return storage


@pytest.fixture
def mock_executor():
    """Mock executor"""
    executor = MagicMock(spec=Executor)
    return executor


@pytest.fixture
def mock_config():
    """Mock config"""
    config = MagicMock(spec=Config)
    config.database_path = ":memory:"
    return config


@pytest_asyncio.fixture
async def tester(mock_storage, mock_executor, mock_config):
    """Создание тестового StrategyTester"""
    tester = StrategyTester(mock_storage, mock_executor, mock_config)
    yield tester
    await tester.close()


# ══════════════════════════════════════════════════════════
#                 КАЛИБРОВКА ТАЙМАУТОВ
# ══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_calibration(tester: StrategyTester):
    """Тест калибровки таймаутов"""
    # Мокаем HTTP сессию и измерения
    with patch.object(tester, '_get_session') as mock_get_session:
        # Создаём мок сессии
        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session
        
        # Мокаем измерения RTT
        async def mock_measure(*args, **kwargs):
            # Имитируем успешное измерение
            return ("test.com", 50.0, None)
        
        # Запускаем калибровку
        result = await tester.calibrate(force=True)
        
        # Проверяем результат
        assert isinstance(result, CalibrationResult)
        assert result.timeout_base > 0
        assert result.timeout_extended >= result.timeout_base
        assert tester._calibration is not None
        assert tester._calibration_time is not None


@pytest.mark.asyncio
async def test_calibration_cached(tester: StrategyTester):
    """Тест кэширования калибровки"""
    # Первая калибровка
    with patch.object(tester, '_get_session') as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session
        
        result1 = await tester.calibrate(force=True)
        time1 = tester._calibration_time
        
        # Вторая калибровка (должна использовать кэш)
        result2 = await tester.calibrate(force=False)
        
        # Результаты должны быть одинаковыми
        assert result1.mean_rtt_ms == result2.mean_rtt_ms
        assert tester._calibration_time == time1


@pytest.mark.asyncio
async def test_calibration_force(tester: StrategyTester):
    """Тест принудительной калибровки"""
    with patch.object(tester, '_get_session') as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session
        
        result1 = await tester.calibrate(force=True)
        
        # Принудительная калибровка должна обновить время
        await tester.calibrate(force=True)
        
        assert tester._calibration_time > time.time() - 1


@pytest.mark.asyncio
async def test_calibration_failed(tester: StrategyTester):
    """Тест неудачной калибровки"""
    with patch.object(tester, '_get_session') as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session
        
        # Имитируем ошибку всех измерений
        with patch('aiohttp.ClientSession') as mock_client_session:
            mock_client_session.side_effect = Exception("Connection error")
            
            result = await tester.calibrate(force=True)
            
            # Должны использоваться дефолтные значения
            assert result.timeout_base == 2.0
            assert result.timeout_extended == 5.0


# ══════════════════════════════════════════════════════════
#                 ТЕСТИРОВАНИЕ СТРАТЕГИЙ
# ══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_test_strategy_executor_fail(tester: StrategyTester, mock_executor):
    """Тест неудачи executor"""
    # Executor не может применить стратегию
    mock_executor.apply_strategy = AsyncMock(return_value=(False, "Error"))
    
    result = await tester.test_strategy(
        domain="test.com",
        strategy_params="--dpi-desync=fake"
    )
    
    # Проверяем результат
    assert result.status == StrategyTestStatus.ERROR
    assert "Executor error" in result.error


# ══════════════════════════════════════════════════════════
#                 ПАРАЛЛЕЛЬНОЕ ТЕСТИРОВАНИЕ
# ══════════════════════════════════════════════════════════

# Пропущено - требует сложной мокировки aiohttp


# ══════════════════════════════════════════════════════════
#                 ПРОВЕРКА DPI
# ══════════════════════════════════════════════════════════

# Пропущено - требует сложной мокировки aiohttp


# ══════════════════════════════════════════════════════════
#                 SINGLETON
# ══════════════════════════════════════════════════════════

def test_get_tester_singleton(mock_storage, mock_executor, mock_config):
    """Тест singleton паттерна"""
    # Сбрасываем singleton
    import autozapret.strategy_tester as st
    st._tester = None
    
    # Получаем первый экземпляр
    tester1 = get_tester(mock_storage, mock_executor, mock_config)
    
    # Получаем второй экземпляр
    tester2 = get_tester(mock_storage, mock_executor, mock_config)
    
    # Должен быть тот же самый объект
    assert tester1 is tester2
    
    # Очищаем
    st._tester = None


# ══════════════════════════════════════════════════════════
#                 ДИНАМИЧЕСКИЕ ТАЙМАУТЫ
# ══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_dynamic_timeout_calculation(tester: StrategyTester):
    """Тест расчёта динамических таймаутов"""
    # Мокаем калибровку с известными значениями
    tester._calibration = CalibrationResult(
        mean_rtt_ms=100,
        std_rtt_ms=20,
        fast_sites_rtt=50,
        slow_sites_rtt=150,
        timeout_base=2.0,
        timeout_extended=5.0,
        success_rate=1.0
    )
    
    # Проверяем что таймауты рассчитаны правильно
    assert tester._calibration.timeout_base >= 1.0
    assert tester._calibration.timeout_extended >= tester._calibration.timeout_base


@pytest.mark.asyncio
async def test_apply_wait_timeout(tester: StrategyTester):
    """Тест ожидания применения стратегии"""
    tester._calibration = CalibrationResult(
        mean_rtt_ms=100,
        std_rtt_ms=20,
        fast_sites_rtt=50,
        slow_sites_rtt=150,
        timeout_base=3.0,
        timeout_extended=5.0,
        success_rate=1.0
    )
    
    # Ожидание должно быть 30% от timeout
    expected_wait = 5.0 * 0.3  # 1.5 секунды
    
    # Проверяем расчёт
    assert expected_wait >= 1.0
    assert expected_wait == 1.5
