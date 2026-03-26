"""
Тест: Проверка работы winws через PowerShell
"""

import asyncio
import subprocess
import time

TEST_DOMAIN = "www.youtube.com"

async def test_powershell():
    """Тест через PowerShell Invoke-WebRequest"""
    print("\n" + "="*60)
    print("ТЕСТ: PowerShell Invoke-WebRequest")
    print("="*60)
    
    try:
        start = time.time()
        
        # Используем PowerShell для тестирования
        process = await asyncio.create_subprocess_exec(
            'powershell',
            '-Command',
            f'$ErrorActionPreference="Stop"; $r=Invoke-WebRequest -Uri "https://{TEST_DOMAIN}/" -TimeoutSec 5 -UseBasicParsing; echo "$($r.StatusCode)|$($r.ResponseTime)"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore').strip()
            print(f"✅ PowerShell УСПЕХ: {output}")
            return True
        else:
            stderr_text = stderr.decode('utf-8', errors='ignore')[:200]
            print(f"❌ PowerShell FAILED: code={process.returncode}, {rtt:.0f}ms")
            print(f"   stderr: {stderr_text}")
            return False
            
    except asyncio.TimeoutError:
        print(f"❌ PowerShell TIMEOUT: 5 сек")
        return False
    except Exception as e:
        print(f"❌ PowerShell ERROR: {e}")
        return False

async def test_curl():
    """Тест через curl"""
    print("\n" + "="*60)
    print("ТЕСТ: curl")
    print("="*60)
    
    try:
        start = time.time()
        
        process = await asyncio.create_subprocess_exec(
            'curl',
            '-s', '-o', 'nul', '-w', '%{http_code}|%{time_total}',
            '--max-time', '5',
            '--connect-timeout', '5',
            f'https://{TEST_DOMAIN}/',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=7)
        rtt = (time.time() - start) * 1000
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore').strip()
            parts = output.split('|')
            if len(parts) == 2:
                http_code = int(parts[0])
                time_total = float(parts[1])
                print(f"✅ curl УСПЕХ: HTTP {http_code}, {time_total*1000:.0f}ms")
                return True
            else:
                print(f"❌ curl parse error: {output}")
                return False
        else:
            print(f"❌ curl FAILED: code={process.returncode}, {rtt:.0f}ms")
            return False
            
    except asyncio.TimeoutError:
        print(f"❌ curl TIMEOUT: 5 сек")
        return False
    except FileNotFoundError:
        print(f"❌ curl НЕ НАЙДЕН")
        return False
    except Exception as e:
        print(f"❌ curl ERROR: {e}")
        return False

async def main():
    print("\n🔍 ПРОВЕРКА СЕТЕВОГО СТЕКА")
    print("="*60)
    
    # PowerShell тест
    ps_result = await test_powershell()
    await asyncio.sleep(2)
    
    # curl тест
    curl_result = await test_curl()
    
    print("\n" + "="*60)
    print("ИТОГИ")
    print("="*60)
    print(f"PowerShell: {'✅ PASS' if ps_result else '❌ FAIL'}")
    print(f"curl: {'✅ PASS' if curl_result else '❌ FAIL'}")

if __name__ == '__main__':
    asyncio.run(main())
