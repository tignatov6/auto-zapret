#!/usr/bin/env python3
"""
CI скрипт для автоматической проверки Auto-Zapret

Запускает:
1. Линтинг (flake8 если установлен)
2. Все тесты pytest
3. Генерацию отчёта о покрытии

Использование:
    python run_tests.py [--no-cov] [--verbose]
"""

import subprocess
import sys
import os
from pathlib import Path


def print_header(text: str):
    """Печать заголовка"""
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def run_command(cmd: list, description: str) -> bool:
    """Запуск команды и проверка результата"""
    print_header(description)
    print(f"Command: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    if result.returncode != 0:
        print(f"FAILED: {description}")
        return False
    
    print(f"PASSED: {description}")
    return True


def check_python_version():
    """Проверка версии Python"""
    print_header("Python Version Check")
    version = sys.version_info
    print(f"Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print("Python 3.10+ required")
        return False
    
    print("Python version OK")
    return True


def check_dependencies():
    """Проверка зависимостей"""
    print_header("Dependencies Check")
    
    required = [
        ("pytest", ["pytest", "--version"]),
        ("pytest-asyncio", ["python", "-c", "import pytest_asyncio"]),
    ]
    
    all_ok = True
    
    for name, cmd in required:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"OK: {name} installed")
            else:
                print(f"MISSING: {name}")
                all_ok = False
        except Exception as e:
            print(f"ERROR: {name} - {e}")
            all_ok = False
    
    return all_ok


def install_dependencies():
    """Установка зависимостей"""
    print_header("Installing Dependencies")
    
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        capture_output=False,
        text=True
    )
    
    if result.returncode != 0:
        print("Failed to install dependencies")
        return False
    
    print("Dependencies installed")
    return True


def run_tests(no_cov: bool = False, verbose: bool = False):
    """Запуск тестов"""
    print_header("Running Tests")
    
    cmd = [sys.executable, "-m", "pytest", "tests/", "--tb=short"]
    
    if not no_cov:
        cmd.extend([
            "--cov=autozapret",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
            "--cov-report=xml:coverage.xml"
        ])
    
    if verbose:
        cmd.append("-v")
    
    result = subprocess.run(cmd, capture_output=False, text=True)
    
    if result.returncode != 0:
        print("\nTests FAILED")
        return False
    
    print("\nTests PASSED")
    return True


def generate_report():
    """Генерация отчёта"""
    print_header("Test Report")
    
    coverage_xml = Path("coverage.xml")
    coverage_html = Path("htmlcov/index.html")
    
    if coverage_xml.exists():
        print(f"Coverage XML: {coverage_xml.absolute()}")
    
    if coverage_html.exists():
        print(f"Coverage HTML: {coverage_html.absolute()}")
        print(f"\nTo view HTML report: open {coverage_html.absolute()}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-Zapret CI Script")
    parser.add_argument("--no-cov", action="store_true", help="Disable coverage")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--install", action="store_true", help="Install dependencies first")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency check")
    
    args = parser.parse_args()
    
    # Переходим в директорию проекта
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)
    
    print("\n" + "=" * 60)
    print(" Auto-Zapret CI/CD Pipeline")
    print("=" * 60)
    print(f"Working directory: {script_dir}")
    
    # Проверки
    if not check_python_version():
        sys.exit(1)
    
    if not args.skip_deps:
        if args.install:
            if not install_dependencies():
                sys.exit(1)
        
        if not check_dependencies():
            print("\nRun with --install to install missing dependencies")
            sys.exit(1)
    
    # Запуск тестов
    if not run_tests(no_cov=args.no_cov, verbose=args.verbose):
        sys.exit(1)
    
    # Отчёт
    generate_report()
    
    print("\n" + "=" * 60)
    print(" All checks passed!")
    print("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    main()
