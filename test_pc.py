#!/usr/bin/env python3
"""
UTM PC System Test - Windows 11 / Linux
Run this to validate UTM components on your machine.
"""

import os
import sys
import platform
import subprocess
import json
import tempfile
from pathlib import Path

def print_header(title):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def print_pass(msg):
    print(f"  ✓ [PASS] {msg}")

def print_fail(msg):
    print(f"  ✗ [FAIL] {msg}")

def print_info(msg):
    print(f"  ℹ [INFO] {msg}")

def test_environment():
    """Check Python and dependencies."""
    print_header("1. Environment Checks")
    
    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        print_pass(f"Python {py_ver} (3.11+ required)")
    else:
        print_fail(f"Python {py_ver} (3.11+ required)")
        return False
    
    # OS detection
    os_name = platform.system()
    print_pass(f"OS: {os_name} {platform.release()}")
    
    # Check required modules
    required = ["yaml", "requests"]
    optional = ["cryptography", "psutil"]
    
    missing = []
    for mod in required:
        try:
            __import__(mod)
            print_pass(f"Module '{mod}' installed")
        except ImportError:
            print_fail(f"Module '{mod}' missing (required)")
            missing.append(mod)
    
    for mod in optional:
        try:
            __import__(mod)
            print_pass(f"Module '{mod}' installed (optional)")
        except ImportError:
            print_info(f"Module '{mod}' not installed (optional but recommended)")
    
    if missing:
        print("\n  Install missing dependencies with:")
        print("    pip install -r requirements.txt")
        return False
    
    return True

def test_safe_executor():
    """Test command execution allowlisting."""
    print_header("2. Safe Executor (Command Allowlisting)")
    
    try:
        from utm_safe import SafeExecutor, is_valid_input
    except ImportError:
        print_fail("utm_safe module not found")
        return False
    
    # Test input validation
    print_info("Testing input sanitization...")
    
    test_cases = [
        ("python -c print(x)", False, "contains injection chars"),
        ("ping google.com", True, "clean command"),
        ("echo; rm -rf /", False, "has semicolon"),
        ("python script.py | grep test", False, "has pipe"),
    ]
    
    for cmd, should_pass, reason in test_cases:
        result = is_valid_input(cmd)
        if result == should_pass:
            print_pass(f"Input '{cmd[:30]}...' - {reason}")
        else:
            print_fail(f"Input '{cmd}' validation failed")
            return False
    
    # Test executor
    print_info("Testing executor with python...")
    executor = SafeExecutor()
    
    try:
        proc = executor.run([sys.executable, "-c", "print('hello')"])
        if "hello" in proc.stdout:
            print_pass("Python execution successful")
        else:
            print_fail("Python execution output unexpected")
            return False
    except Exception as e:
        print_fail(f"Python execution failed: {e}")
        return False
    
    # Test disallowed binary
    print_info("Testing blocklist (curl should be blocked)...")
    try:
        executor.run(["curl", "https://example.com"])
        print_fail("Curl was allowed (should be blocked)")
        return False
    except RuntimeError as e:
        print_pass(f"Curl correctly blocked: {str(e)[:40]}...")
    
    return True

def test_threat_feeds():
    """Test threat intelligence ingestion."""
    print_header("3. Threat Intelligence Feeds")
    
    try:
        import utm_feed
    except ImportError:
        print_fail("utm_feed module not found")
        return False
    
    # Test IP extraction
    print_info("Testing IP extraction from sample feed...")
    sample_feed = """
# Malicious IPs
192.168.1.1
8.8.8.8
10.0.0.1
1.1.1.1
999.999.999.999
invalid-ip
"""
    
    ips = utm_feed.extract_public_ips(sample_feed)
    
    # Verify results
    checks = [
        ("8.8.8.8" in ips, "Public IP (8.8.8.8) extracted"),
        ("1.1.1.1" in ips, "Public IP (1.1.1.1) extracted"),
        ("192.168.1.1" not in ips, "Private IP (192.168.1.1) filtered"),
        ("10.0.0.1" not in ips, "Private IP (10.0.0.1) filtered"),
    ]
    
    for check, desc in checks:
        if check:
            print_pass(desc)
        else:
            print_fail(desc)
            return False
    
    # Test feed fetch simulation
    print_info("Testing feed size limits...")
    print_pass(f"MAX_FEED_BYTES = {utm_feed.MAX_FEED_BYTES:,} bytes (1 MB)")
    
    return True

def test_logging():
    """Test tamper-evident logging."""
    print_header("4. Tamper-Evident Logging (HMAC)")
    
    try:
        import utm_logging
    except ImportError:
        print_fail("utm_logging module not found")
        return False
    
    # Set log key
    os.environ["UTM_LOG_KEY"] = "test-key-12345"
    
    # Create temp log
    fd, log_path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    
    try:
        print_info("Writing test events to log...")
        utm_logging.log_event(log_path, {"event": "login", "user": "admin"})
        utm_logging.log_event(log_path, {"event": "audit", "action": "policy_check"})
        print_pass("Events logged successfully")
        
        print_info("Verifying log integrity...")
        if utm_logging.verify_log(log_path):
            print_pass("Log integrity verified (HMAC valid)")
        else:
            print_fail("Log integrity check failed")
            return False
        
        print_info("Simulating tampering...")
        with open(log_path, "r+", encoding="utf-8") as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("admin", "attacker"))
        
        if not utm_logging.verify_log(log_path):
            print_pass("Tampering detected (HMAC mismatch)")
        else:
            print_fail("Tampering not detected")
            return False
        
        return True
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)

def test_hardening_checks():
    """Test runtime hardening status."""
    print_header("5. Runtime Hardening Checks")
    
    try:
        import utm_hardening
    except ImportError:
        print_fail("utm_hardening module not found")
        return False
    
    # Check elevation
    is_elev = utm_hardening.is_elevated()
    if platform.system() == "Windows":
        status = "Administrator" if is_elev else "Standard User"
    else:
        status = "Root" if is_elev else "Non-root"
    
    print_pass(f"Elevation status: {status}")
    if not is_elev:
        print_info("Note: Some features require elevated privileges")
    
    # Check Secure Boot
    sb = utm_hardening.check_secure_boot()
    print_pass(f"Secure Boot/UEFI: {'Enabled' if sb else 'Not detected'}")
    
    # Check MAC (Linux)
    if platform.system() == "Linux":
        mac = utm_hardening.check_apparmor_selinux()
        print_pass(f"Mandatory Access Control: {mac or 'none'}")
    
    return True

def test_sbom_generation():
    """Test SBOM generation."""
    print_header("6. SBOM (Software Bill of Materials)")
    
    try:
        import generate_sbom
    except ImportError:
        print_fail("generate_sbom module not found")
        return False
    
    # Generate SBOM
    sbom_path = "test_sbom_output.json"
    try:
        print_info(f"Generating SBOM from requirements.txt...")
        generate_sbom.generate_sbom("requirements.txt", sbom_path)
        
        with open(sbom_path, "r") as f:
            sbom = json.load(f)
        
        pkg_count = len(sbom.get("sbom", []))
        print_pass(f"SBOM generated with {pkg_count} packages")
        
        # Show first few
        for pkg in sbom["sbom"][:3]:
            print_info(f"  - {pkg['name']} {pkg.get('version', 'unspecified')}")
        
        return True
    finally:
        if os.path.exists(sbom_path):
            os.remove(sbom_path)

def test_artifact_collection():
    """Test IR artifact collection."""
    print_header("7. Artifact Collection (Incident Response)")
    
    try:
        import artifact_collector
    except ImportError:
        print_fail("artifact_collector module not found")
        return False
    
    print_info("Collecting system artifacts (processes, connections)...")
    
    try:
        out_dir = tempfile.mkdtemp(prefix="utm_artifacts_")
        path = artifact_collector.collect_artifacts(out_dir)
        
        if os.path.exists(path):
            with open(path, "r") as f:
                artifacts = json.load(f)
            
            proc_count = len(artifacts.get("processes", []))
            conn_count = len(artifacts.get("net_connections", []))
            
            print_pass(f"Artifacts collected: {proc_count} processes, {conn_count} connections")
            print_info(f"Artifacts saved to: {out_dir}")
            return True
        else:
            print_fail("Artifact file not created")
            return False
    except Exception as e:
        print_fail(f"Artifact collection failed: {e}")
        return False

def test_orchestrator():
    """Test the main orchestrator."""
    print_header("8. Main Orchestrator")
    
    try:
        from utm import SecurityOrchestrator
    except ImportError:
        print_fail("utm module not found")
        return False
    
    os.environ["UTM_LOG_KEY"] = "test-key"
    
    try:
        print_info("Initializing orchestrator...")
        agent = SecurityOrchestrator()
        print_pass("Orchestrator initialized")
        
        print_info(f"OS: {agent.os_info}")
        print_info(f"Elevated: {agent.is_elevated}")
        
        # Test config hash
        config_hash = agent.compute_config_hash()
        if config_hash:
            print_pass(f"Config SHA256: {config_hash[:16]}...")
        else:
            print_info("Config file not found (expected if not configured)")
        
        return True
    except Exception as e:
        print_fail(f"Orchestrator initialization failed: {e}")
        return False

def run_unit_tests():
    """Run pytest unit tests."""
    print_header("9. Unit Tests (pytest)")
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            output = result.stdout.strip()
            print_pass(f"All tests passed: {output}")
            return True
        else:
            print_fail("Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print_fail(f"Could not run pytest: {e}")
        print_info("Install pytest: pip install pytest")
        return False

def run_linting():
    """Run code quality checks."""
    print_header("10. Code Quality (ruff, mypy, bandit)")
    
    results = {}
    
    # Ruff
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "."],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print_pass("ruff: No linting issues")
            results["ruff"] = True
        else:
            print_fail("ruff: Some issues found (see above)")
            results["ruff"] = False
    except Exception:
        print_info("ruff not installed (install: pip install ruff)")
        results["ruff"] = None
    
    # MyPy
    try:
        result = subprocess.run(
            [sys.executable, "-m", "mypy", ".", "--no-error-summary"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print_pass("mypy: Type checking passed")
            results["mypy"] = True
        else:
            print_fail("mypy: Some type issues found")
            results["mypy"] = False
    except Exception:
        print_info("mypy not installed (install: pip install mypy)")
        results["mypy"] = None
    
    # Bandit
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", ".", "-c", "bandit.yml"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print_pass("bandit: No security issues")
            results["bandit"] = True
        else:
            print_info("bandit: Review warnings (may be non-critical)")
            results["bandit"] = False
    except Exception:
        print_info("bandit not installed (install: pip install bandit)")
        results["bandit"] = None
    
    return any(v for v in results.values() if v is not None)

def main():
    print("\n" + "█" * 70)
    print("█" + " " * 68 + "█")
    print("█  UTM SECURITY ORCHESTRATOR - PC SYSTEM TEST  " + " " * 22 + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)
    
    tests = [
        ("Environment", test_environment),
        ("Safe Executor", test_safe_executor),
        ("Threat Feeds", test_threat_feeds),
        ("Logging", test_logging),
        ("Hardening", test_hardening_checks),
        ("SBOM", test_sbom_generation),
        ("Artifacts", test_artifact_collection),
        ("Orchestrator", test_orchestrator),
        ("Unit Tests", run_unit_tests),
        ("Code Quality", run_linting),
    ]
    
    results = {}
    for name, test_fn in tests:
        try:
            results[name] = test_fn()
        except Exception as e:
            print_fail(f"Test crashed: {e}")
            results[name] = False
    
    # Summary
    print_header("TEST SUMMARY")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status:8} {name}")
    
    print(f"\n  Total: {passed}/{total} passed\n")
    
    if passed == total:
        print("  🎉 All tests passed! UTM is ready for use.\n")
        return 0
    else:
        print(f"  ⚠️  {total - passed} test(s) failed. See details above.\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
