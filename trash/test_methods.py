"""
Тест: Проверка работы через PowerShell vs curl
"""

import asyncio
import subprocess
import time

TEST_DOMAIN = "www.youtube.com"

async def test_curl():
    """Тест curl"""
    try:
        start = time.time()
        process = await asyncio.create_subprocess_exec(
            'curl', '-s', '-o', 'nul', '-w', '%{http_code}|%{time_total}',
            '--max-time', '5', '--connect-timeout', '5', '-4',
            f'https://{TEST_DOMAIN}/',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode().strip()
            parts = output.split('|')
            if len(parts) == 2:
                http_code = int(parts[0])
                return True, f"HTTP {http_code}, {rtt:.0f}ms"
        return False, f"curl code={process.returncode}, {rtt:.0f}ms"
    except Exception as e:
        return False, f"curl error: {e}"

async def test_powershell():
    """Тест PowerShell Invoke-WebRequest"""
    try:
        start = time.time()
        
        # PowerShell скрипт
        ps_script = f'''
$ErrorActionPreference = "Stop"
try {{
    $response = Invoke-WebRequest -Uri "https://{TEST_DOMAIN}/" -TimeoutSec 5 -UseBasicParsing
    $ms = {int(start * 1000)}
    echo "OK|200|$ms"
}} catch {{
    $ms = {int(start * 1000)}
    echo "FAIL|0|$ms"
}}
'''
        
        process = await asyncio.create_subprocess_exec(
            'powershell', '-Command', ps_script,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        output = stdout.decode().strip()
        parts = output.split('|')
        if len(parts) >= 3:
            status = parts[0]
            http_code = parts[1]
            if status == "OK":
                return True, f"PowerShell HTTP {http_code}, {rtt:.0f}ms"
        
        return False, f"PowerShell failed: {output[:100]}"
        
    except asyncio.TimeoutError:
        return False, "PowerShell timeout"
    except Exception as e:
        return False, f"PowerShell error: {e}"

async def test_socket():
    """Прямой TCP тест через socket"""
    import socket
    import ssl
    
    try:
        start = time.time()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Подключение
        sock.connect((TEST_DOMAIN, 443))
        
        # TLS handshake
        ctx = ssl.create_default_context()
        ssock = ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN)
        
        # HTTP запрос
        ssock.send(f"HEAD / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: close\r\n\r\n".encode())
        data = ssock.recv(256)
        
        rtt = (time.time() - start) * 1000
        ssock.close()
        
        if data:
            return True, f"Socket OK, {rtt:.0f}ms"
        return False, f"Socket empty response, {rtt:.0f}ms"
        
    except Exception as e:
        return False, f"Socket error: {e}"

async def main():
    print("\n🔍 СРАВНЕНИЕ МЕТОДОВ ТЕСТА")
    print("="*60)
    
    print(f"\nТест: {TEST_DOMAIN}")
    print("="*60)
    
    # curl
    print("\n1. curl:")
    ok, msg = await test_curl()
    print(f"   {'✅' if ok else '❌'} {msg}")
    curl_ok = ok
    
    await asyncio.sleep(2)
    
    # PowerShell
    print("\n2. PowerShell:")
    ok, msg = await test_powershell()
    print(f"   {'✅' if ok else '❌'} {msg}")
    ps_ok = ok
    
    await asyncio.sleep(2)
    
    # Socket
    print("\n3. Socket (прямой TCP):")
    ok, msg = await test_socket()
    print(f"   {'✅' if ok else '❌'} {msg}")
    socket_ok = ok
    
    # Итоги
    print("\n" + "="*60)
    print("ИТОГИ")
    print("="*60)
    print(f"curl:       {'✅ РАБОТАЕТ' if curl_ok else '❌ НЕ РАБОТАЕТ'}")
    print(f"PowerShell: {'✅ РАБОТАЕТ' if ps_ok else '❌ НЕ РАБОТАЕТ'}")
    print(f"Socket:     {'✅ РАБОТАЕТ' if socket_ok else '❌ НЕ РАБОТАЕТ'}")
    
    if not curl_ok and (ps_ok or socket_ok):
        print("\n⚠️ ВЫВОД: curl НЕ РАБОТАЕТ, нужно использовать PowerShell/Socket!")

if __name__ == '__main__':
    asyncio.run(main())
