# UTM PC Testing — Quick Start Guide

This guide walks you through testing the UTM Security Orchestrator on your Windows 11 or Linux system.

## Prerequisites

- **Python 3.11+**: Download from https://python.org
- **pip**: Usually comes with Python
- **Dependencies**: Run `pip install -r requirements.txt` first

## Quick Test (2 minutes)

### Windows PowerShell

```powershell
# Set execution policy (if prompted)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Run tests
python test_pc.py
```

### Windows Command Prompt

```cmd
python test_pc.py
```

### Linux / macOS

```bash
python3 test_pc.py
```

## What Gets Tested

| # | Test | What it checks |
|---|------|----------------|
| 1 | Environment | Python 3.11+, required modules installed |
| 2 | Safe Executor | Command allowlisting, injection blocking (CWE-78) |
| 3 | Threat Feeds | IP extraction, feed validation, public vs private IP filtering |
| 4 | Logging | HMAC-protected event logs, tampering detection |
| 5 | Hardening | Elevation status, Secure Boot, AppArmor/SELinux |
| 6 | SBOM | Software bill of materials generation from requirements.txt |
| 7 | Artifacts | Incident response artifact collection (processes, connections) |
| 8 | Orchestrator | Main UTM controller initialization and config hashing |
| 9 | Unit Tests | Full pytest suite (9 tests) |
| 10 | Linters | Code quality (ruff, mypy, bandit) |

## Expected Output

### Successful Run
```
======================================================================
  UTM SECURITY ORCHESTRATOR - PC SYSTEM TEST
======================================================================

=== 1. Environment Checks ===
  ✓ [PASS] Python 3.11.5 (3.11+ required)
  ✓ [PASS] OS: Windows 10.0.22631
  ✓ [PASS] Module 'yaml' installed
  ✓ [PASS] Module 'requests' installed

=== 2. Safe Executor (Command Allowlisting) ===
  ℹ [INFO] Testing input sanitization...
  ✓ [PASS] Input 'python -c print(x)'... - contains injection chars
  ...
  ✓ [PASS] Curl correctly blocked: Binary 'curl' not allowed by policy

=== 3. Threat Intelligence Feeds ===
  ℹ [INFO] Testing IP extraction from sample feed...
  ✓ [PASS] Public IP (8.8.8.8) extracted
  ...

=== TEST SUMMARY ===
  ✓ PASS   Environment
  ✓ PASS   Safe Executor
  ...
  Total: 10/10 passed

  🎉 All tests passed! UTM is ready for use.
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'yaml'"

**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### "Python 3.11+ required"

**Solution**: Update Python
- Download from https://python.org/downloads
- Or use `conda`: `conda install python=3.11`

### "Permission denied" (Linux/macOS)

**Solution**: Run with `sudo` or adjust script permissions
```bash
chmod +x test_pc.py
sudo python test_pc.py
```

### Tests pass but some marked "FAIL"

Check the specific failure message above. Common issues:
- Missing optional module (cryptography, psutil) — install with `pip install cryptography psutil`
- File permissions — run as Administrator/root for full tests
- No threat feed connectivity — offline mode is OK for this test

### "Artifact collection failed: permission denied"

This is normal on Windows 10 without admin. Run as Administrator:
```powershell
# PowerShell - run as admin
Start-Process powershell -ArgumentList "python test_pc.py" -Verb RunAs
```

## Manual Feature Tests

### Test 1: Safe Executor (Injection Prevention)

```python
from utm_safe import SafeExecutor

se = SafeExecutor()

# This works (python is allowlisted)
result = se.run(['python', '-c', "print('ok')"])
print(result.stdout)

# This fails (curl is blocked)
try:
    se.run(['curl', 'https://example.com'])
except RuntimeError as e:
    print(f"Blocked: {e}")

# This fails (injection attempt detected)
try:
    se.run("python -c print(x); rm -rf /")
except ValueError as e:
    print(f"Blocked: {e}")
```

### Test 2: Threat Intelligence

```python
import utm_feed

# Sample malicious feed
sample = "8.8.8.8\n10.0.0.1\n192.168.1.1\n1.1.1.1"

# Extract only public IPs
public_ips = utm_feed.extract_public_ips(sample)
print(f"Public IPs: {public_ips}")  # Should be {8.8.8.8, 1.1.1.1}
```

### Test 3: Tamper-Evident Logging

```python
import os
from utm_logging import log_event, verify_log
import tempfile

# Set log key
os.environ['UTM_LOG_KEY'] = 'my-secret-key'

# Create log
fd, log_path = tempfile.mkstemp()
os.close(fd)

# Write events
log_event(log_path, {'user': 'admin', 'action': 'login'})

# Verify integrity (should pass)
if verify_log(log_path):
    print("Log integrity: OK")

# Simulate tampering
with open(log_path, 'r+') as f:
    f.write(f.read().replace('admin', 'attacker'))

# Verify again (should fail)
if not verify_log(log_path):
    print("Tampering detected: ✓")

os.remove(log_path)
```

### Test 4: SBOM Generation

```python
import json
from generate_sbom import generate_sbom

# Generate SBOM
generate_sbom('requirements.txt', 'my_sbom.json')

# View it
with open('my_sbom.json') as f:
    sbom = json.load(f)
    print(f"{len(sbom['sbom'])} packages in SBOM")
```

### Test 5: Artifact Collection (IR)

```python
import json
from artifact_collector import collect_artifacts

# Collect system artifacts
path = collect_artifacts('artifacts')

# View results
with open(path) as f:
    data = json.load(f)
    print(f"{len(data['processes'])} processes")
    print(f"{len(data['net_connections'])} network connections")
```

### Test 6: Full Orchestrator

```bash
# Set log key
export UTM_LOG_KEY="test-key"

# Run orchestrator (will load config, fetch threat intel, audit compliance)
python utm.py

# Check logs
type utm.log  # Windows
# or
cat utm.log   # Linux
```

## Running Tests on Schedule

### Windows Task Scheduler

```powershell
# Create a scheduled task to run tests daily
$action = New-ScheduledTaskAction -Execute 'python' -Argument 'test_pc.py'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'UTM-Daily-Check' -Action $action -Trigger $trigger
```

### Linux Cron

```bash
# Run tests daily at 2 AM
0 2 * * * cd /path/to/utm && python test_pc.py >> /var/log/utm-test.log 2>&1
```

## Next Steps

After tests pass:

1. **Review Playbooks**: Read [`playbooks/helpdesk_playbook.md`](playbooks/helpdesk_playbook.md) for incident response procedures
2. **Generate SBOM**: Run `python generate_sbom.py` to document dependencies
3. **Run Orchestrator**: Execute `python utm.py` to start monitoring
4. **Check Logs**: View `utm.log` to see events and audit trail
5. **Configure Policy**: Customize `registry.yaml` for your system
6. **Sign Policy** (optional): Use Ed25519 keys to sign your policy file for integrity

## Support

- **Test Details**: See [`TESTING.md`](TESTING.md) for comprehensive testing guide
- **Architecture**: See [`README.md`](README.md) for system design and features

---

**Last Updated**: February 12, 2026
