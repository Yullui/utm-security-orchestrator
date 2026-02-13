# UTM Security Orchestrator v3.0

**Enterprise-grade Unified Threat Management for Windows 11 and Linux hardening, compliance auditing, and incident response.**

---

## 📋 Quick Links

| Document | Purpose |
|----------|---------|
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | Installation, configuration, enterprise setup |
| **[OPERATIONAL_GUIDE.md](OPERATIONAL_GUIDE.md)** | Day-to-day operations, help desk procedures, troubleshooting |
| **[SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md)** | Incident response, threat detection, security procedures |
| **[TEST_QUICK_START.md](TEST_QUICK_START.md)** | Testing & validation on your PC |
| **[playbooks/helpdesk_playbook.md](playbooks/helpdesk_playbook.md)** | Help desk incident response playbooks |

---

## ⚡ Quick Start (5 min)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Verify installation
python test_pc.py

# 3. Run your first scan
python utm.py --info          # Check system hardening status
python utm.py --audit         # Compliance audit only
python utm.py                 # Full scan (threat intel + compliance + monitoring)
```

---

## 🎯 Features

- **CWE-78 Safe Execution**: Allowlist-based command execution prevents injection
- **Threat Intelligence**: Automatic ingestion from public feeds (EmergrThreats, Tor, AbuseCH)
- **Policy Verification**: Ed25519 signature validation before policy load
- **Tamper-Evident Logging**: HMAC-protected append-only JSON event logs
- **Compliance Auditing**: Registry checks (Windows), configuration state validation
- **Activity Monitoring**: Real-time connection tracking, malicious IP detection
- **Incident Response**: Automated artifact collection, forensic-ready exports
- **Runtime Hardening**: Elevation checks, Secure Boot, AppArmor/SELinux detection
- **SBOM Tracking**: Automatic Software Bill of Materials generation
- **Professional Playbooks**: Help desk and security team runbooks

---

## 📁 Key Files

```
utm.py                         # Main orchestrator (production-ready CLI)
utm_safe.py                    # Safe executor (prevents CWE-78)
utm_feed.py                    # Threat intelligence ingestion
utm_logging.py                 # Tamper-evident HMAC logging
utm_config_sign.py             # Ed25519 policy signing/verification
utm_hardening.py               # Runtime hardening checks
artifact_collector.py          # IR artifact collection
generate_sbom.py               # SBOM generation
requirements.txt               # Python dependencies
Dockerfile                     # Container deployment
.github/workflows/ci.yml       # CI/CD (linting, testing, bandit)
playbooks/                     # Help desk & IR playbooks
tests/                         # Unit tests (pytest)
```

---

## 🔧 Command Reference

```bash
# System information
python utm.py --info                   # Show hardening status
python utm.py --help                   # Show all options

# Scanning modes
python utm.py                          # Full scan (threat intel + compliance + monitor)
python utm.py --ti                     # Threat intelligence only
python utm.py --audit                  # Compliance audit only

# Incident response
python utm.py --collect-artifacts      # Collect IR evidence
python utm.py --verify-logs            # Check log integrity
python utm.py --json                   # Output as JSON (for SIEM)

# Configuration
python utm.py --policy my_policy.yaml  # Use alternate policy file
python utm.py --log-key "mykey"        # Override HMAC key
```

---

## 🔐 Security & Compliance

| Standard | Coverage |
|----------|----------|
| **NIST 800-53** | AU-2, AU-12, SI-4, AC-3, SI-5, CM-5 |
| **CIS Controls** | v8.1, v8.5, v9.1, v16.1 |
| **PCI-DSS** | 1.1, 6.2, 10.1, 10.2 |
| **CWE** | CWE-78 (injection), CWE-345 (integrity), CWE-434 (tampering) |

---

## 📊 Test Coverage

```bash
# Run all tests
python -m pytest -q              # 9 tests, all types
python test_pc.py                # 10 component tests
python -m ruff check .           # Linting
python -m mypy . || true         # Type checking
python -m bandit -r .            # Security scanning
```

---

## 🚀 Deployment

**Single Machine**:
```bash
pip install -r requirements.txt
export UTM_LOG_KEY="$(openssl rand -hex 32)"
python utm.py
```

**Enterprise (Multiple Hosts)**:
See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for:
- Federated multi-host setup
- SIEM integration (ELK, Splunk, Datadog)
- Scheduled scanning (cron/Task Scheduler)
- Policy distribution & signing

**Container**:
```bash
docker build -t utm:latest .
docker run --env UTM_LOG_KEY="key" utm:latest
```

---

## 📖 Documentation

### For Users
- **First-Time Setup**: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Day-to-Day Ops**: [OPERATIONAL_GUIDE.md](OPERATIONAL_GUIDE.md)
- **Help Desk/IR**: [playbooks/helpdesk_playbook.md](playbooks/helpdesk_playbook.md)

### For Security Teams
- **Incident Response**: [SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md)
- **Threat Modeling**: [SECURITY_PLAYBOOK.md#1-system-architecture--security-properties](SECURITY_PLAYBOOK.md#1-system-architecture--security-properties)
- **Compliance Alignment**: [SECURITY_PLAYBOOK.md#2-compliance-alignment](SECURITY_PLAYBOOK.md#2-compliance-alignment)

### For Development/Testing
- **Testing Guide**: [TESTING.md](TESTING.md)
- **Quick Test**: [TEST_QUICK_START.md](TEST_QUICK_START.md)

---

## 🛠️ Configuration

### Example Policy (registry.yaml)

```yaml
registry_fixes:
  - key: "HKLM\\System\\CurrentControlSet\\Control\\Lsa"
    value: "RestrictAnonymous"
    data: "1"
    reason: "CIS 5.1 - Prevent null session enumeration"

system_commands:
  - command: ["powershell.exe", "-c", "Update-Help -Force"]
    reason: "Keep PowerShell help current"

audit_schedule:
  frequency: "daily"
  time: "02:00"
  timezone: "UTC"
```

See [DEPLOYMENT_GUIDE.md#configuration](DEPLOYMENT_GUIDE.md#configuration) for full examples.

---

## 🆘 Troubleshooting

**"ModuleNotFoundError"**:
```bash
pip install -r requirements.txt
```

**"Permission denied" (Linux/macOS)**:
```bash
sudo python utm.py
```

**"Policy won't load"**:
```bash
python -c "import yaml; yaml.safe_load(open('registry.yaml'))"  # Check YAML syntax
```

More troubleshooting: See [OPERATIONAL_GUIDE.md#troubleshooting](OPERATIONAL_GUIDE.md#troubleshooting)

---

## 📞 Support & Contact

- **Help Desk**: See contact info in [OPERATIONAL_GUIDE.md](OPERATIONAL_GUIDE.md)
- **Security Team**: See escalation matrix in [SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md)
- **Documentation**: Start with [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

---

## 📜 License & Version

**Version**: 3.0  
**Date**: February 12, 2026  
**License**: Internal/Proprietary

---

**Ready to deploy?** Start with [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

