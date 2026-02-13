# UTM Security Orchestrator

> Enterprise-grade Unified Threat Management platform for Windows 11/Linux hardening, compliance automation, and incident response.

![Tests](https://img.shields.io/badge/tests-10%2F10%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Compliance](https://img.shields.io/badge/compliance-NIST%20%7C%20PCI%20%7C%20CIS-yellow)

## 🎯 Overview

A production-ready security platform that combines:
- **Endpoint Hardening**: STIG/NIST/PCI compliance automation
- **Threat Detection**: IP-based threat intelligence & activity monitoring
- **Incident Response**: Automated artifacts collection & forensics
- **Policy Enforcement**: Cryptographically signed configuration management
- **Audit Logging**: Tamper-evident HMAC-protected event trails

## ⚡ Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment (required for audit logging)
export UTM_LOG_KEY="$(openssl rand -hex 32)"

# Run full scan (threat intel + compliance + monitoring)
python utm.py

# Or specific modes
python utm.py --audit              # Compliance check only
python utm.py --ti                 # Threat intelligence only
python utm.py --info               # System hardening status
python utm.py --json               # Machine-readable output (SIEM)
```

## 📦 What's Included

| Component | Purpose | Tests |
|-----------|---------|-------|
| **utm.py** | Main orchestrator with CLI interface | ✅ |
| **utm_safe.py** | Safe command execution (prevents injection) | ✅ |
| **utm_feed.py** | Threat intelligence ingestion | ✅ |
| **utm_logging.py** | Tamper-evident audit logging | ✅ |
| **utm_config_sign.py** | Ed25519 policy verification | ✅ |
| **utm_hardening.py** | Runtime hardening checks | ✅ |
| **artifact_collector.py** | IR artifact collection | ✅ |
| **generate_sbom.py** | Software Bill of Materials | ✅ |

**Test Coverage**: 10/10 passing (100% module coverage)

## 🔐 Security Hardening

### CWE Mitigations
- **CWE-78**: OS Command Injection → SafeExecutor allowlist
- **CWE-345**: Policy Integrity → Ed25519 signatures
- **CWE-434**: Log Tampering → Per-event HMAC-SHA256
- **CWE-703**: Silent Failures → Proper exception logging

### Static Analysis
```bash
python -m bandit -r .              # Security scanning
python -m ruff check .             # Linting
python -m mypy . --ignore-missing  # Type checking
python -m pytest -q tests/         # Unit tests (10 passing)
```

## 📋 Compliance

| Standard | Coverage |
|----------|----------|
| **NIST 800-53** | AU-2, AU-12, SI-4, AC-3, SI-5, CM-5 |
| **PCI-DSS** | 1.1, 6.2, 10.1, 10.2 |
| **CIS Controls** | v8.1, v8.5, v9.1, v16.1 |
| **Windows STIG** | 16 controls automated (V-253337 → V-268317) |

## 📖 Documentation

- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Enterprise installation & configuration
- **[OPERATIONAL_GUIDE.md](OPERATIONAL_GUIDE.md)** - Daily operations & help desk procedures
- **[SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md)** - Incident response & threat procedures
- **[QUALITY_ASSURANCE.md](QUALITY_ASSURANCE.md)** - Full QA validation & metrics
- **[playbooks/helpdesk_playbook.md](playbooks/helpdesk_playbook.md)** - Help desk runbooks
- **[TESTING.md](TESTING.md)** - Testing procedures & validation

## 🚀 Features

### Threat Intelligence
- Ingests IPs from 3 public feeds (EmergingThreats, TorExitNodes, AbuseCH)
- Deduplicates & validates threat data
- Real-time connection monitoring against blacklist

### Compliance Automation
- Windows Registry auditing (STIG controls)
- Automatic remediation via allowlisted commands
- Audit logging of all changes (HMAC-protected)

### Incident Response
- Automatic artifact collection (processes, connections)
- Forensics-ready JSON export
- Quick containment procedures (documented)

### Policy Management
- YAML-based configuration files
- Ed25519 signature verification before load
- Prevents tampering via cryptographic proof

## 📊 Example Output

```
================================================================================
  UTM SECURITY ORCHESTRATOR v3.0 | Windows 11
  Started: 2026-02-13 10:42:15
================================================================================
  [OK] SBOM generated: sbom.json

[PHASE 1: THREAT INTELLIGENCE]
  [*] Starting threat intelligence ingest...
  [+] EmergingThreats: 443 IPs loaded
  [+] TorExitNodes: 1335 IPs loaded
  [+] AbuseCH: 3 IPs loaded
  [OK] Threat intelligence complete: 1781 unique IPs
  PHASE 1 PASSED [33%] in 2.59s

[PHASE 2: COMPLIANCE AUDIT & REMEDIATION]
  [OK] Registry audit: 16 passed, 0 failed
  [*] Remediation skipped: insufficient_privileges
  PHASE 2 PASSED [67%] in 0.01s

[PHASE 3: ACTIVITY MONITORING]
  [OK] No suspicious active connections
  PHASE 3 PASSED [100%] in 0.00s

================================================================================
  SCAN COMPLETED [100%] in 2.59s
  Phases: PHASE 1 2.59s + PHASE 2 0.01s + PHASE 3 0.00s
  Log file: utm.log
================================================================================
```

## 🛠️ Development

### Environment Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Running Tests
```bash
python -m pytest tests/ -q              # Quick unit tests
python test_pc.py                       # Comprehensive integration tests
```

### CI/CD
GitHub Actions workflow automatically runs:
- Ruff (linting)
- MyPy (type checking)
- Bandit (security scanning)
- PyTest (unit tests)

## 📦 Dependencies

All dependencies pinned to specific versions (see `requirements.txt`):

- `requests` - HTTPS threat feed fetching
- `PyYAML` - Policy parsing
- `cryptography` - Ed25519 policy signing
- `psutil` - Process/connection monitoring
- `pytest` - Unit testing
- `ruff`, `mypy`, `bandit` - Code quality tools

## 🔑 Configuration

### Environment Variables

```bash
# REQUIRED - HMAC key for audit logging (generate with: openssl rand -hex 32)
export UTM_LOG_KEY="your-secret-key-here"

# OPTIONAL - Ed25519 public key for policy verification
export UTM_POLICY_PUBKEY="-----BEGIN PUBLIC KEY-----\n..."

# OPTIONAL - Custom policy file location
export UTM_POLICY="registry.yaml"
```

### Policy File (registry.yaml)

```yaml
registry_fixes:
  - id: 'V-253337'
    description: 'Application event log size must be 32768 KB or greater'
    key: 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    value: 'MaxSize'
    type: 'REG_DWORD'
    data: 32768

system_commands:
  - id: 'V-253285'
    description: 'Verify PowerShell 2.0 is Disabled'
    command: 'powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
```

## 📞 Support

For issues, questions, or feature requests:
1. Review relevant documentation files
2. Check existing GitHub issues
3. Review incident response playbooks for troubleshooting

## ✅ Production Readiness

- [x] 10/10 unit tests passing
- [x] Zero Bandit HIGH/MEDIUM issues
- [x] 100% type hints (MyPy passing)
- [x] STIG controls: 16/16 implemented
- [x] SBOM tracking enabled
- [x] Audit logging: tamper-evident
- [x] Professional documentation complete
- [x] Help desk playbooks included
- [x] CI/CD pipeline enabled

## 📜 License

Proprietary - Internal use only

---

**Version**: 3.0  
**Last Updated**: February 13, 2026  
**Status**: Production Ready ✅
