"""
Тесты для DPI Detector
"""

import pytest
import pytest_asyncio

from autozapret.dpi_detector import (
    DPIDetector, DPIStatus, DPICheckResult, get_detector
)


class TestDPIDetector:
    """Тесты DPI detector"""
    
    def test_detector_init(self):
        """Тест инициализации детектора"""
        detector = DPIDetector()
        
        # Проверяем что пути ищутся
        assert detector.BLOCKCHECK_PATHS is not None
        assert len(detector.BLOCKCHECK_PATHS) > 0
    
    def test_detector_find_blockcheck(self):
        """Тест поиска blockcheck.sh"""
        detector = DPIDetector(zapret_src_dir="./zapret-src")
        
        # blockcheck.sh должен быть найден в zapret-src
        assert detector.blockcheck_path is not None
        assert "blockcheck.sh" in str(detector.blockcheck_path)
    
    def test_detector_fallback_paths(self):
        """Тест fallback путей"""
        # Создаём детектор с несуществующим путём
        detector = DPIDetector(zapret_src_dir="/nonexistent/path/xyz123")
        
        # blockcheck.sh может быть найден через fallback пути
        # Поэтому проверяем что detector всё равно работает
        assert detector is not None
        # Если путь не найден, blockcheck_path будет None или искать в fallback
    
    @pytest.mark.asyncio
    async def test_fallback_check(self):
        """Тест fallback проверки (без blockcheck.sh)"""
        detector = DPIDetector(zapret_src_dir="/nonexistent/path")
        
        # Fallback должен вернуть какой-то результат
        result = await detector._fallback_check("example.com")
        
        assert isinstance(result, DPICheckResult)
        assert result.domain == "example.com"
        assert result.status in [
            DPIStatus.NO_DPI,
            DPIStatus.DPI_DETECTED,
            DPIStatus.ERROR
        ]
    
    @pytest.mark.asyncio
    async def test_tcp_connect_test(self):
        """Тест TCP connection test"""
        detector = DPIDetector()
        
        # Тестируем на известном домене
        result = await detector._tcp_connect_test("example.com", port=80)
        
        assert isinstance(result, dict)
        assert "blocked" in result
        assert "error" in result
        assert "time" in result
        assert isinstance(result["time"], float)
    
    @pytest.mark.asyncio
    async def test_tls_handshake_test(self):
        """Тест TLS handshake test"""
        detector = DPIDetector()
        
        # Тестируем на известном домене
        result = await detector._tls_handshake_test("example.com", port=443)
        
        assert isinstance(result, dict)
        assert "blocked" in result
        assert "error" in result
        assert "time" in result
    
    @pytest.mark.asyncio
    async def test_quick_check(self):
        """Тест быстрой проверки"""
        detector = DPIDetector(zapret_src_dir="/nonexistent/path")
        
        # Quick check должен вернуть bool
        result = await detector.quick_check("example.com")
        
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_check_domain_fallback(self):
        """Тест проверки домена (fallback)"""
        detector = DPIDetector(zapret_src_dir="/nonexistent/path")
        
        result = await detector.check_domain("example.com", timeout=10)
        
        assert isinstance(result, DPICheckResult)
        assert result.domain == "example.com"
        assert result.status != DPIStatus.NOT_CHECKED
    
    def test_dpi_check_result_to_dict(self):
        """Тест конвертации результата в dict"""
        result = DPICheckResult(
            domain="test.com",
            status=DPIStatus.DPI_DETECTED,
            method="TCP 16-20",
            zapret_params="--dpi-desync=fake"
        )
        
        d = result.to_dict()
        
        assert d["domain"] == "test.com"
        assert d["status"] == "dpi_detected"
        assert d["method"] == "TCP 16-20"
        assert d["zapret_params"] == "--dpi-desync=fake"
        assert "checked_at" in d
    
    def test_dpi_status_enum(self):
        """Тест enum статусов"""
        assert DPIStatus.NOT_CHECKED.value == "not_checked"
        assert DPIStatus.NO_DPI.value == "no_dpi"
        assert DPIStatus.DPI_DETECTED.value == "dpi_detected"
        assert DPIStatus.IP_BLOCKED.value == "ip_blocked"
        assert DPIStatus.DNS_BLOCKED.value == "dns_blocked"
        assert DPIStatus.ERROR.value == "error"
    
    def test_get_detector_singleton(self):
        """Тест глобального детектора"""
        detector1 = get_detector()
        detector2 = get_detector()
        
        # Должен возвращать один экземпляр
        assert detector1 is detector2
    
    @pytest.mark.asyncio
    async def test_check_blocked_domain(self):
        """Тест проверки заблокированного домена (симуляция)"""
        detector = DPIDetector(zapret_src_dir="/nonexistent/path")
        
        # Т.к. blockcheck.sh не найден, используется fallback
        # который делает реальное TCP соединение
        result = await detector.check_domain("example.com", timeout=10)
        
        # example.com не должен быть заблокирован
        assert result.status in [DPIStatus.NO_DPI, DPIStatus.ERROR]


class TestDPIDetectorPatterns:
    """Тесты паттернов парсинга"""
    
    def test_patterns_exist(self):
        """Тест существования паттернов"""
        detector = DPIDetector()
        
        assert "success" in detector.PATTERNS
        assert "zapret_params" in detector.PATTERNS
        assert "dpi_detected" in detector.PATTERNS
        assert "ip_blocked" in detector.PATTERNS
        assert "dns_blocked" in detector.PATTERNS
    
    def test_patterns_compile(self):
        """Тест компиляции regex паттернов"""
        detector = DPIDetector()
        
        for name, pattern in detector.PATTERNS.items():
            # Паттерн должен быть скомпилированным regex
            assert hasattr(pattern, "search")
            assert hasattr(pattern, "match")


@pytest.mark.asyncio
async def test_detector_timeout():
    """Тест таймаута проверки"""
    detector = DPIDetector(zapret_src_dir="/nonexistent/path")
    
    # Короткий таймаут
    result = await detector.check_domain("10.255.255.1", timeout=2)
    
    # Должен вернуть ошибку или результат
    assert isinstance(result, DPICheckResult)


@pytest.mark.asyncio
async def test_detector_multiple_domains():
    """Тест проверки нескольких доменов"""
    detector = DPIDetector(zapret_src_dir="/nonexistent/path")
    
    domains = ["example.com", "google.com", "cloudflare.com"]
    results = []
    
    for domain in domains:
        result = await detector.check_domain(domain, timeout=10)
        results.append(result)
    
    # Все результаты должны быть валидными
    for result in results:
        assert isinstance(result, DPICheckResult)
        assert result.domain in domains
