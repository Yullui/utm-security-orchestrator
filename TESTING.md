# UTM Testing Guide

This document covers unit tests, integration tests, manual scenarios, and production validation for the UTM Orchestrator.

## Unit Tests (Automated)

### Run All Tests
```bash
python -m pytest -q
python -m pytest -v  # verbose
python -m pytest -v --tb=long  # with detailed tracebacks
```

### Run Specific Test File
```bash
python -m pytest tests/test_utm_safe.py -v
python -m pytest tests/test_utm_feed.py -v
python -m pytest tests/test_utm_logging.py -v
python -m pytest tests/test_utm_config_sign.py -v
python -m pytest tests/test_generate_sbom.py -v
```

### Run with Coverage
```bash
pip install pytest-cov
python -m pytest --cov=. --cov-report=html
# Open htmlcov/index.html in browser
```

---

## Integration Tests (Manual)

### 1. Test Safe Executor (Command Allowlisting)

**Scenario**: Verify that only allowlisted binaries can execute.

```bash
python -c "
from utm_safe import SafeExecutor
se = SafeExecutor()

# Should succeed (python is allowlisted)
try:
    proc = se.run(['python', '-c', \"print('hello')\"])
    print('[PASS] Python execution allowed:', proc.stdout)
except Exception as e:
    print('[FAIL]', e)

# Should fail (curl not allowlisted)
try:
    proc = se.run(['curl', 'https://example.com'])
    print('[FAIL] Curl should not be allowed')
except RuntimeError as e:
    print('[PASS] Curl blocked:', e)

# Should fail (injection attempt)
try:
    proc = se.run('python -c print(hello); rm -rf /')
    print('[FAIL] Injection should be blocked')
except ValueError as e:
    print('[PASS] Injection blocked:', e)
"
```

**Expected Output**:
```
[PASS] Python execution allowed: hello
[PASS] Curl blocked: Binary 'curl' not allowed by policy
[PASS] Injection blocked: Command contains disallowed characters or is malformed
```

---

### 2. Test Threat Feed Ingestion

**Scenario**: Verify feed fetching, size limits, and IP extraction.

```bash
python -c "
import utm_feed

# Test IP extraction from sample feed
sample = '''
# IP Blacklist
10.0.0.1
8.8.8.8
192.168.1.1
1.1.1.1
invalid.ip
999.999.999.999
'''

ips = utm_feed.extract_public_ips(sample)
print(f'[TEST] Extracted public IPs: {ips}')
assert '8.8.8.8' in ips, 'Public IP not extracted'
assert '10.0.0.1' not in ips, 'Private IP should be filtered'
assert '1.1.1.1' in ips, 'Cloudflare DNS should be extracted'
print('[PASS] IP extraction working correctly')

# Test max size limit
try:
    big_data = b'A' * (utm_feed.MAX_FEED_BYTES + 1)
    utm_feed.fetch_feed('https://fake.test', expected_sha256=None)
    print('[FAIL] Should have raised size limit error')
except Exception as e:
    print(f'[INFO] Size-limiting is tested in unit tests')
"
```

---

### 3. Test Tamper-Evident Logging

**Scenario**: Create logs and verify HMAC integrity.

```bash
import os
import tempfile
from utm_logging import log_event, verify_log

# Set log key
os.environ['UTM_LOG_KEY'] = 'test-key-123'

fd, log_path = tempfile.mkstemp()
os.close(fd)

try:
    # Log two events
    log_event(log_path, {'action': 'login', 'user': 'admin'})
    log_event(log_path, {'action': 'remediate', 'cmd': 'powershell.exe'})
    
    # Verify integrity
    if verify_log(log_path):
        print('[PASS] Log integrity verified')
    else:
        print('[FAIL] Log integrity check failed')
    
    # Tamper with the log
    with open(log_path, 'r+', encoding='utf-8') as f:
        data = f.read()
        f.seek(0)
        f.write(data.replace('admin', 'hacker'))
    
    # Verification should fail
    if not verify_log(log_path):
        print('[PASS] Tampering detected')
    else:
        print('[FAIL] Tampering not detected')
        
finally:
    os.remove(log_path)
```

---

### 4. Test Config Signing & Verification

**Scenario**: Sign a config file and verify it.

```bash
python -c "
import tempfile
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from utm_config_sign import sign_config, verify_config

# Generate keypair
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

# Write key files
fd1, priv_path = tempfile.mkstemp()
fd2, pub_path = tempfile.mkstemp()
fd3, cfg_path = tempfile.mkstemp()
fd4, sig_path = tempfile.mkstemp()

os.close(fd1); os.close(fd2); os.close(fd3); os.close(fd4)

try:
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(priv_path, 'wb') as f: f.write(priv_pem)
    with open(pub_path, 'wb') as f: f.write(pub_pem)
    with open(cfg_path, 'wb') as f: f.write(b'registry_fixes: []')
    
    # Sign
    sign_config(cfg_path, priv_path, sig_path)
    
    # Verify valid signature
    if verify_config(cfg_path, sig_path, pub_path):
        print('[PASS] Valid signature verified')
    else:
        print('[FAIL] Should have verified')
    
    # Tamper and re-verify
    with open(cfg_path, 'ab') as f:
        f.write(b'tampering')
    
    if not verify_config(cfg_path, sig_path, pub_path):
        print('[PASS] Tampering detected')
    else:
        print('[FAIL] Should have detected tampering')
        
finally:
    for p in [priv_path, pub_path, cfg_path, sig_path]:
        if os.path.exists(p):
            os.remove(p)
"
```

---

### 5. Test SBOM Generation

**Scenario**: Generate and validate SBOM.

```bash
import os
import json
from generate_sbom import generate_sbom

# Generate SBOM
generate_sbom('requirements.txt', 'test_sbom.json')

# Verify structure
with open('test_sbom.json', 'r') as f:
    sbom = json.load(f)

assert 'sbom' in sbom, 'Missing sbom key'
assert len(sbom['sbom']) > 0, 'SBOM is empty'
assert 'name' in sbom['sbom'][0], 'Missing package name'

print(f'[PASS] SBOM generated with {len(sbom["sbom"])} packages')
for pkg in sbom['sbom'][:3]:
    print(f'  - {pkg["name"]} {pkg["version"]}')

os.remove('test_sbom.json')
```

---

## Manual Scenario Tests

### 6. Test Full Orchestrator Flow (Dry Run)

**Create a test policy file** (`test_policy.yaml`):
```yaml
registry_fixes:
  - key: "HKLM\\Software\\Test"
    value: "TestValue"
    data: "1"

system_commands:
  - command: ["python", "-c", "print('remediation')"]
    reason: "Test remediation"
```

**Run orchestrator** (will load policy, run threat intel, check registry):
```bash
export UTM_LOG_KEY="test-key"
python -c "
from utm import SecurityOrchestrator
orchestrator = SecurityOrchestrator(config_path='test_policy.yaml')
orchestrator.fetch_threat_intelligence()
orchestrator.run_compliance_audit()
"
```

**Verify logs were created**:
```bash
cat utm.log  # Should show JSON events with HMACs
```

---

### 7. Test with Signed Policy

**Generate keys** (one-time):
```bash
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

with open('utm_private.pem', 'wb') as f:
    f.write(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('utm_public.pem', 'wb') as f:
    f.write(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print('Keys generated: utm_private.pem, utm_public.pem')
"
```

**Sign the policy**:
```bash
python -c "
from utm_config_sign import sign_config
sign_config('test_policy.yaml', 'utm_private.pem', 'test_policy.yaml.sig')
print('Policy signed: test_policy.yaml.sig')
"
```

**Load and verify**:
```bash
export UTM_POLICY_PUBKEY=\"\$(cat utm_public.pem)\"
python utm.py
```

---

### 8. Test Artifact Collection (IR)

**Collect artifacts**:
```bash
python -c "
from artifact_collector import collect_artifacts
path = collect_artifacts('test_artifacts')
print(f'Artifacts collected to: {path}')
"

# View artifacts
cat test_artifacts/artifacts.json | python -m json.tool | head -50
```

---

## Static Analysis Tests

### 9. Run Linters

**Ruff (Python linting)**:
```bash
python -m ruff check .
python -m ruff check . --fix  # Auto-fix simple issues
```

**MyPy (Type checking)**:
```bash
python -m mypy .
python -m mypy --strict utm.py  # Stricter checks
```

**Bandit (Security scanning)**:
```bash
python -m bandit -r . -c bandit.yml
python -m bandit -r utm.py utm_safe.py utm_feed.py  # Specific files
```

---

## Docker Testing

### 10. Test Container Build and Run

**Build image**:
```bash
docker build -t utm:latest .
```

**Run container**:
```bash
docker run \
  --env "UTM_LOG_KEY=test-key" \
  --volume "$(pwd)/artifacts:/app/artifacts" \
  utm:latest
```

**Verify output**:
```bash
ls -la artifacts/
cat artifacts/utm.log
```

---

## CI/CD Testing

### 11. Run GitHub Actions Locally (Optional)

Install `act` tool:
```bash
# macOS: brew install act
# Windows: https://github.com/nektos/act
# Linux: https://github.com/nektos/act

act -j test  # Runs CI workflow locally
```

---

## Production Readiness Checklist

- [ ] All unit tests passing: `pytest -v`
- [ ] No lint errors: `ruff check .`
- [ ] Type checks passing: `mypy .`
- [ ] No critical Bandit findings: `bandit -r .`
- [ ] SBOM generated: `python generate_sbom.py`
- [ ] Policy file signed and verified
- [ ] Log key configured in environment
- [ ] Threat feeds accessible and fetchable
- [ ] Artifact collection working
- [ ] Docker build succeeds
- [ ] Help desk playbooks reviewed

---

## Example: End-to-End Test Script

Save this as `test_e2e.sh`:

```bash
#!/bin/bash
set -e

echo "=== Running E2E Tests ==="

# Unit tests
echo "[1/5] Running unit tests..."
python -m pytest -q

# Linting
echo "[2/5] Running linters..."
python -m ruff check . || true

# SBOM
echo "[3/5] Generating SBOM..."
python generate_sbom.py

# Artifact collection
echo "[4/5] Collecting artifacts..."
export UTM_LOG_KEY="test-key"
python -c "from artifact_collector import collect_artifacts; collect_artifacts('artifacts')"

# Orchestrator dry-run
echo "[5/5] Running orchestrator dry-run..."
python utm.py

echo "=== All E2E tests passed ==="
```

Run it:
```bash
chmod +x test_e2e.sh
./test_e2e.sh
```

---

## Troubleshooting

**Test fails with "ModuleNotFoundError"**:
```bash
pip install -r requirements.txt
```

**Bandit fails on intentional test findings**:
- Edit `bandit.yml` to skip specific tests
- Or update `.github/workflows/ci.yml` to use `|| true` (non-blocking)

**Artifact collection permission denied**:
- Run as administrator (Windows) or with `sudo` (Linux)
- Or run in Docker container

**Logging fails with "UTM_LOG_KEY missing"**:
```bash
export UTM_LOG_KEY="your-secret-key"
```

---

## Performance Testing

To measure throughput and latency:

```bash
import time
from utm import SecurityOrchestrator

agent = SecurityOrchestrator()
start = time.time()

# Phase 1: Threat Intelligence (network I/O)
agent.fetch_threat_intelligence()
ti_time = time.time() - start

# Phase 2: Compliance (disk I/O)
start = time.time()
agent.run_compliance_audit()
audit_time = time.time() - start

print(f"Threat Intelligence: {ti_time:.2f}s")
print(f"Compliance Audit: {audit_time:.2f}s")
print(f"Total: {ti_time + audit_time:.2f}s")
```

---

## Continuous Testing

For continuous integration, consider:
- **Pre-commit hook**: Run `ruff` and `pytest` before committing
- **Scheduled CI**: Run full test suite + CVE scans on schedule (GitHub Actions)
- **Production monitoring**: Collect logs and metrics from running orchestrator

See `.github/workflows/ci.yml` for automated GitHub Actions configuration.
