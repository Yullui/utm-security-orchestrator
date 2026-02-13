@echo off
REM UTM PC Test Runner (Windows Batch)
REM Run this to test UTM on your Windows 11 system

setlocal enabledelayedexpansion

echo.
echo ========================================================================
echo  UTM SECURITY ORCHESTRATOR - PC TEST SUITE
echo ========================================================================
echo.

REM Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found. Install from https://python.org
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
echo [PASS] Python %PYTHON_VER% found

REM Check dependencies
echo.
echo [INFO] Checking dependencies...
python -c "import yaml" >nul 2>&1 || echo [WARN] yaml not installed - run: pip install -r requirements.txt
python -c "import requests" >nul 2>&1 || echo [WARN] requests not installed - run: pip install -r requirements.txt
python -c "import pytest" >nul 2>&1 || echo [WARN] pytest not installed - run: pip install -r requirements.txt

REM Run comprehensive tests
echo.
echo ========================================================================
echo  RUNNING COMPREHENSIVE PC TESTS
echo ========================================================================
python test_pc.py
set TEST_RESULT=%errorlevel%

if %TEST_RESULT% equ 0 (
    echo.
    echo ========================================================================
    echo  SUCCESS - All tests passed!
    echo ========================================================================
    echo.
    echo Next steps:
    echo   1. Review help desk playbooks: playbooks/helpdesk_playbook.md
    echo   2. Generate SBOM: python generate_sbom.py
    echo   3. Run orchestrator: python utm.py
    echo   4. Check logs: type utm.log
    echo.
) else (
    echo.
    echo ========================================================================
    echo  FAILURE - Some tests failed (see above)
    echo ========================================================================
    echo.
)

exit /b %TEST_RESULT%
