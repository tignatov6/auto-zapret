"""
Тесты для улучшенной обработки DNS/TLS ошибок в dpi_detector.py
"""

import pytest
import socket
from unittest.mock import patch, MagicMock

from autozapret.dpi_detector import DPIDetector, DPIStatus


class TestDNSErrorHandling:
    """Тесты обработки DNS ошибок"""

    @pytest.mark.asyncio
    async def test_dns_noname_blocked(self):
        """Тест: EAI_NONAME считается блокировкой"""
        detector = DPIDetector()
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # gaierror принимает позиционные аргументы
            mock_getaddrinfo.side_effect = socket.gaierror(
                socket.EAI_NONAME, "Name or service not known"
            )
            
            result = await detector._dns_resolve_test("nonexistent.domain.invalid")
            
            assert result["blocked"] is True
            assert result["error_type"] == "permanent"
            assert "DNS resolution failed" in result["error"]

    @pytest.mark.asyncio
    async def test_dns_nodata_blocked(self):
        """Тест: EAI_NODATA считается блокировкой"""
        detector = DPIDetector()
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.gaierror(
                socket.EAI_NODATA, "No address associated with hostname"
            )
            
            result = await detector._dns_resolve_test("empty.domain.invalid")
            
            assert result["blocked"] is True
            assert result["error_type"] == "permanent"

    @pytest.mark.asyncio
    async def test_dns_again_temporary(self):
        """Тест: EAI_AGAIN считается временной ошибкой"""
        detector = DPIDetector()
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.gaierror(
                socket.EAI_AGAIN, "Temporary failure in name resolution"
            )
            
            result = await detector._dns_resolve_test("flaky.domain.invalid")
            
            assert result["blocked"] is False
            assert result["error_type"] == "temporary"
            assert "Temporary DNS error" in result["error"]

    @pytest.mark.asyncio
    async def test_dns_other_error_temporary(self):
        """Тест: Другие DNS ошибки считаются временными"""
        detector = DPIDetector()
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.gaierror(
                socket.EAI_FAIL, "Non-recoverable failure"
            )
            
            result = await detector._dns_resolve_test("broken.domain.invalid")
            
            assert result["blocked"] is False
            assert result["error_type"] == "temporary"

    @pytest.mark.asyncio
    async def test_dns_success(self):
        """Тест: Успешное разрешение домена"""
        detector = DPIDetector()
        
        mock_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:2800:220:1:248:1893:25c8:1946', 443, 0, 0)),
        ]
        
        with patch('socket.getaddrinfo', return_value=mock_result):
            result = await detector._dns_resolve_test("example.com")
            
            assert result["blocked"] is False
            assert result["error_type"] == ""
            assert len(result["ips"]) == 2
            assert "93.184.216.34" in result["ips"]


class TestTLSErrorHandling:
    """Тесты обработки TLS ошибок"""

    @pytest.mark.asyncio
    async def test_tls_cert_error_not_dpi(self):
        """Тест: Ошибка сертификата не считается DPI"""
        detector = DPIDetector()
        
        import ssl
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo, \
             patch('ssl.create_default_context') as mock_context:
            
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))
            ]
            
            mock_ssl_socket = MagicMock()
            mock_ssl_socket.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "certificate verify failed"
            )
            
            mock_context.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "certificate verify failed"
            )
            
            result = await detector._tls_handshake_test("example.com")
            
            assert result["blocked"] is True
            assert "SSL certificate error" in result["error"]

    @pytest.mark.asyncio
    async def test_tls_reset_is_dpi(self):
        """Тест: RST во время TLS считается DPI"""
        detector = DPIDetector()
        
        import ssl
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo, \
             patch('ssl.create_default_context') as mock_context:
            
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))
            ]
            
            mock_context.return_value.wrap_socket.side_effect = ssl.SSLError(
                "[SSL: KRB5_S_TKT_NYV] unexpected eof while reading (_ssl.c:2500)"
            )
            
            # Симулируем ошибку "connection reset"
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = ssl.SSLError("connection reset by peer")
            mock_context.return_value.wrap_socket.return_value = mock_socket
            
            result = await detector._tls_handshake_test("example.com")
            
            assert result["blocked"] is True
            assert "errors_by_address" in result

    @pytest.mark.asyncio
    async def test_tls_handshake_failure_dpi(self):
        """Тест: Ошибка handshake считается DPI"""
        detector = DPIDetector()
        
        import ssl
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo, \
             patch('ssl.create_default_context') as mock_context:
            
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))
            ]
            
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = ssl.SSLError("ssl handshake failure")
            mock_context.return_value.wrap_socket.return_value = mock_socket
            
            result = await detector._tls_handshake_test("example.com")
            
            assert result["blocked"] is True
            assert "TLS handshake failed" in result["error"]

    @pytest.mark.asyncio
    async def test_tls_timeout_continue(self):
        """Тест: Таймаут TLS позволяет попробовать другие адреса"""
        detector = DPIDetector()
        
        import ssl
        import socket
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo, \
             patch('ssl.create_default_context') as mock_context:
            
            # Два адреса
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
            ]
            
            # Первый адрес таймаут, второй успех
            call_count = [0]
            
            def connect_side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise socket.timeout("timed out")
                return None  # Второй вызов успешен
            
            mock_socket_instance = MagicMock()
            mock_socket_instance.connect.side_effect = connect_side_effect
            
            mock_context.return_value.wrap_socket.return_value = mock_socket_instance
            
            result = await detector._tls_handshake_test("example.com")
            
            # Должен попробовать оба адреса
            assert mock_socket_instance.connect.call_count == 2
            # Второй адрес сработал
            assert result["blocked"] is False

    @pytest.mark.asyncio
    async def test_tls_all_addresses_failed(self):
        """Тест: Все адреса не сработали"""
        detector = DPIDetector()
        
        import ssl
        import socket
        
        with patch('socket.getaddrinfo') as mock_getaddrinfo, \
             patch('ssl.create_default_context') as mock_context:
            
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
            ]
            
            mock_socket_instance = MagicMock()
            mock_socket_instance.connect.side_effect = socket.error("Connection refused")
            
            mock_context.return_value.wrap_socket.return_value = mock_socket_instance
            
            result = await detector._tls_handshake_test("example.com")
            
            assert result["blocked"] is True
            assert "errors_by_address" in result
            # Должны быть ошибки для обоих адресов
            assert len(result["errors_by_address"]) == 2


class TestFallbackCheckErrorTypes:
    """Тесты классификации ошибок в fallback check"""

    @pytest.mark.asyncio
    async def test_fallback_temporary_dns_error(self):
        """Тест: Временная DNS ошибка возвращает ERROR а не DNS_BLOCKED"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp:
            
            mock_dns.return_value = {
                "blocked": False,
                "error": "Temporary DNS error",
                "error_type": "temporary"
            }
            
            result = await detector._fallback_check("example.com")
            
            assert result.status == DPIStatus.ERROR
            assert "Temporary DNS error" in result.method

    @pytest.mark.asyncio
    async def test_fallback_permanent_dns_blocked(self):
        """Тест: Постоянная DNS ошибка возвращает DNS_BLOCKED"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns:
            
            mock_dns.return_value = {
                "blocked": True,
                "error": "DNS resolution failed",
                "error_type": "permanent"
            }
            
            result = await detector._fallback_check("blocked.domain")
            
            assert result.status == DPIStatus.DNS_BLOCKED
            assert "DNS resolution failed" in result.method

    @pytest.mark.asyncio
    async def test_fallback_connection_refused(self):
        """Тест: Connection refused возвращает ERROR (сервер недоступен)"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp:
            
            mock_dns.return_value = {"blocked": False, "error": "", "error_type": ""}
            mock_tcp.return_value = {"blocked": True, "error": "Connection refused"}
            
            result = await detector._fallback_check("down.server.com")
            
            assert result.status == DPIStatus.ERROR
            assert "Connection refused" in result.method

    @pytest.mark.asyncio
    async def test_fallback_ip_unreachable(self):
        """Тест: IP unreachable возвращает IP_BLOCKED"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp:
            
            mock_dns.return_value = {"blocked": False, "error": "", "error_type": ""}
            mock_tcp.return_value = {"blocked": True, "error": "No route to host"}
            
            result = await detector._fallback_check("blocked.ip.com")
            
            assert result.status == DPIStatus.IP_BLOCKED

    @pytest.mark.asyncio
    async def test_fallback_tls_cert_error(self):
        """Тест: TLS certificate error возвращает ERROR"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp, \
             patch.object(detector, '_tls_handshake_test') as mock_tls:
            
            mock_dns.return_value = {"blocked": False, "error": "", "error_type": ""}
            mock_tcp.return_value = {"blocked": False, "error": "", "time": 0.1}
            mock_tls.return_value = {"blocked": True, "error": "SSL certificate error"}
            
            result = await detector._fallback_check("bad-cert.com")
            
            assert result.status == DPIStatus.ERROR
            assert "TLS certificate error" in result.method

    @pytest.mark.asyncio
    async def test_fallback_tls_reset_dpi(self):
        """Тест: TLS reset возвращает DPI_DETECTED"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp, \
             patch.object(detector, '_tls_handshake_test') as mock_tls:
            
            mock_dns.return_value = {"blocked": False, "error": "", "error_type": ""}
            mock_tcp.return_value = {"blocked": False, "error": "", "time": 0.1}
            mock_tls.return_value = {"blocked": True, "error": "connection reset by peer"}
            
            result = await detector._fallback_check("dpi-blocked.com")
            
            assert result.status == DPIStatus.DPI_DETECTED
            assert "reset" in result.method.lower()

    @pytest.mark.asyncio
    async def test_fallback_tls_other_error(self):
        """Тест: Другие TLS ошибки возвращают ERROR"""
        detector = DPIDetector()
        
        with patch.object(detector, '_dns_resolve_test') as mock_dns, \
             patch.object(detector, '_tcp_connect_test') as mock_tcp, \
             patch.object(detector, '_tls_handshake_test') as mock_tls:
            
            mock_dns.return_value = {"blocked": False, "error": "", "error_type": ""}
            mock_tcp.return_value = {"blocked": False, "error": "", "time": 0.1}
            mock_tls.return_value = {"blocked": True, "error": "Some unknown SSL error"}
            
            result = await detector._fallback_check("unknown-error.com")
            
            assert result.status == DPIStatus.ERROR
            assert "TLS error" in result.method


class TestDPICheckResultToDict:
    """Тесты конвертации результата в dict"""

    def test_result_to_dict(self):
        """Тест: Конвертация результата в словарь"""
        from autozapret.dpi_detector import DPICheckResult
        
        result = DPICheckResult(
            domain="test.com",
            status=DPIStatus.DPI_DETECTED,
            method="Test method",
            zapret_params="--dpi-desync=fake",
            error=""
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["domain"] == "test.com"
        assert result_dict["status"] == "dpi_detected"
        assert result_dict["method"] == "Test method"
        assert result_dict["zapret_params"] == "--dpi-desync=fake"
        assert "checked_at" in result_dict
