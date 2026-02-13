# UTM Security Orchestrator — Security Playbook v3.0

**For**: Security Operations Center (SOC), Security Architects, Compliance Officers  
**Version**: 3.0  
**Date**: February 2026  
**Audience**: Enterprise security teams, incident responders, auditors

---

## 1. System Architecture & Security Properties

### Threat Model

The UTM Orchestrator protects against:
- **CWE-78 (OS Command Injection)**: Safe executor blocks injection via allowlisting
- **Unsigned/Tampered Policies**: Ed25519 signature verification before loading
- **Log Tampering**: HMAC-based integrity verification per event
- **Malicious Network Activity**: Threat feed ingestion + connection monitoring
- **Privilege Escalation**: Least-privilege enforcement, elevation gating
- **Supply Chain Attacks**: SBOM tracking + dependency pinning

### Security Boundaries

| Boundary | Protection |
|----------|-----------|
| **Command Execution** | Allowlist-based (CWE-78, B602) |
| **Policy Files** | Ed25519 signature verification (CWE-345) |
| **Audit Logs** | HMAC per-event + append-only (CWE-434) |
| **External Feeds** | Size limits, HTTPS, checksum validation |
| **Process Spawning** | No `shell=True`, subprocess.run only (B602) |
| **Secrets** | Environment-backed (placeholder for Vault) |

---

## 2. Compliance Alignment

### NIST 800-53 Controls

| Control | UTM Feature | Implementation |
|---------|-------------|-----------------|
| **AU-2** (Audit Events) | Tamper-evident logging | HMAC-protected JSON logs |
| **AU-12** (Generate Logs) | Event logging | All operations recorded |
| **SI-4** (System Monitoring) | Activity monitoring | Connection tracking, IP blocklist |
| **AC-3** (Access Control) | Allowlist enforcement | Binary/command allowlist |
| **SI-5** (Security Alerts) | Threat intelligence | Feed ingestion + alert generation |
| **CM-5** (Access Policy Enforcement) | Policy verification | Signature checking before load |

### PCI-DSS Compliance

- **Requirement 1.1**: Firewall rules (Windows Firewall / iptables integration ready)
- **Requirement 6.2**: Security patches (policy-driven remediation)
- **Requirement 10.1**: Audit logging (with HMAC integrity)
- **Requirement 10.2**: User activity tracking (process monitoring)

### CIS Controls

- **v8.1**: Inventory & Control of Hardware
- **v8.5**: Access Restrictions  
- **v9.1**: Network Segmentation
- **v16.1**: Monitoring & Alerting

---

## 3. Detection & Response Scenarios

### Scenario A: Suspicious Outbound Connection Detected

**Trigger**: Connection to blacklisted IP detected by `monitor_activities()`

```yaml
Alert Type: MALICIOUS_IP_CONNECTION
Severity: HIGH
Details:
  timestamp: 2026-02-12T14:23:15Z
  malicious_ip: 203.0.113.45
  pid: 2840
  process_name: svchost.exe
  local_addr: 192.168.1.100:54321
```

**Immediate Actions**:
1. Isolate process: terminate with `SafeExecutor` (if approved)
2. Collect artifacts: `python utm.py --collect-artifacts`
3. Create log entry: automatically via `utm_logging`
4. Alert SOC via SIEM: forward `utm.log` to ELK/Splunk

**Investigation**:
```bash
# Check process relationships
tasklist /v | grep 2840

# Review network history  
netstat -ano | grep ESTABLISHED

# Check file hash
certUtil -hashfile C:\Path\To\svchost.exe SHA256

# Compare against threat intel
curl https://virustotal.com/api/v3/files/<hash>
```

**Escalation**:
- If process is system-critical → pause remediation, escalate to IR team
- If process is user-mode → quarantine and notify user
- If multiple IPs → check for lateral movement

---

### Scenario B: Policy Tampering Detected

**Trigger**: Policy signature verification fails OR HMAC check fails on logs

```yaml
Alert Type: POLICY_INTEGRITY_VIOLATION
Severity: CRITICAL
Details:
  event: policy_sig_invalid
  path: registry.yaml
  expected_sig: <pub-key-verified>
  actual_sig: INVALID
```

**Immediate Actions**:
1. STOP all remediation immediately
2. Revert to last-known-good signed policy
3. Generate forensic snapshot
4. Lock policy file: read-only, immutable flag
5. Alert SOC + CISO + Audit

**Investigation**:
```bash
# Check who modified the file
wmic logicaldisk get name | xargs -I {} ls -la "{}:\registry.yaml*"

# Compare with backup
diff registry.yaml registry.yaml.backup

# Check event logs for modifications
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663}

# Verify signature database
ls -la /opt/utm/keys/
```

**Remediation**:
1. Restore from signed backup
2. Audit key access logs
3. Rotate all signing keys
4. Run full re-compliance check
5. Document incident in audit log

---

### Scenario C: Unauthorized Administrator Login

**Trigger**: Local admin account creation or privilege escalation attempt

**Actions**:
```bash
# List all admin accounts
net localgroup Administrators

# Check recent logins
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 0}

# Force password change
net user <username> /logonpasswordchg:yes
```

**Response**:
1. Verify administrator identity (call them)
2. If unauthorized: disable account, audit logins
3. Force MFA/password reset
4. Review what the account accessed
5. Log in security operations center

---

## 4. Incident Response Procedures

### Phase 1: Detection & Alerting (0–5 min)

```
┌─────────────────────────────────────────┐
│ UTM detects suspicious activity         │
│   • Malicious IP connection            │
│   • Policy tampering                    │
│   • Privilege escalation                │
│   • Anomalous process spawn             │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ Automated logging & alerting            │
│   • HMAC-signed event logged            │
│   • Alert sent to SIEM (ELK/Splunk)    │
│   • Automated snapshot saved            │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ SOC notified via alert (PagerDuty/etc) │
│   • P1: Policy tampering               │
│   • P2: Malicious connection           │
│   • P3: Elevated privilege use         │
└─────────────────────────────────────────┘
```

### Phase 2: Triage (5–15 min)

**Help Desk SOC Checklist**:
- [ ] Confirm alert is real (no false positives)
- [ ] Identify affected system/user
- [ ] Classify severity (P1/P2/P3)
- [ ] Notify user & their manager
- [ ] Collect artifacts: `python utm.py --collect-artifacts`
- [ ] Capture screenshots & process memory

**Escalation Decision**:
- **P1 (Critical)**: Immediate IR team engagement, consider isolation
- **P2 (High)**: Investigate within 1 hour, prepare containment
- **P3 (Medium)**: Routine investigation, monitor for patterns

### Phase 3: Containment (15–60 min)

**Short-term**:
1. Isolate network: disconnect from LAN/Wi-Fi
2. Kill malicious process: use `SafeExecutor` with approval
3. Block IP at host firewall
4. Take forensic copy of drive (if possible)

**Medium-term**:
1. Reset compromised credentials
2. Scan for lateral movement
3. Patch vulnerable software
4. Review access logs (past 7 days)

### Phase 4: Eradication (1–24 hours)

1. Remove malware/backdoors
2. Reset OS to known-good state (image)
3. Validate policy files are signed
4. Restore from clean backup
5. Run full compliance audit: `python utm.py --audit`

### Phase 5: Recovery (24–72 hours)

1. Reintroduce system to network under monitoring
2. Run threat intelligence update
3. Monitor for re-infection (watch logs)
4. Notify user system is clean

### Phase 6: Post-Incident Review (72 hours +)

1. Root cause analysis: how did this happen?
2. Lessons learned: what can we improve?
3. Update defenses: tighten policies, add rules
4. Share findings with security team
5. Update playbooks if needed

---

## 5. Threat Intelligence Management

### Feed Integration

Currently configured feeds:
- **EmergingThreats**: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`
- **Tor Exit Nodes**: `https://check.torproject.org/exit-addresses`
- **AbuseCH**: `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`

**Add Custom Feed**:
```python
# Edit utm.py, add to INTEL_FEEDS:
INTEL_FEEDS['MyFeed'] = 'https://your-org.com/threat-intel/feed.txt'
```

### Feed Validation

Each feed is validated for:
- **Size**: Capped at 1 MB (configurable)
- **Format**: IP parsing with JUNK rejection
- **Privacy**: Private IP ranges filtered out (10.x, 192.168.x, 172.16-31.x)
- **Checksum**: Optional SHA256 verification (if configured)

### Feed Freshness

Recommended:
- **High-confidence feeds** (EmergingThreats): Update every 6 hours
- **Medium-confidence feeds** (Tor): Update daily
- **Custom feeds**: Update per SLA

**Schedule updates** (Windows Task Scheduler):
```powershell
$action = New-ScheduledTaskAction -Execute 'python' -Argument 'utm.py --ti'
$trigger = New-ScheduledTaskTrigger -Daily -At 1am
Register-ScheduledTask -TaskName 'UTM-TI-Update' -Action $action -Trigger $trigger
```

---

## 6. Policy Management & Governance

### Policy Structure

`registry.yaml` example:
```yaml
registry_fixes:
  - key: "HKLM\\System\\CurrentControlSet\\Control\\Lsa"
    value: "RestrictAnonymous"
    data: "1"
    reason: "CIS Control 5.3 - Minimize anonymous access"

system_commands:
  - command: ["powershell.exe", "-c", "Update-Help -Force"]
    reason: "Keep PowerShell help up-to-date"
    
audit_schedule:
  frequency: "daily"
  time: "02:00"
```

### Signing & Verification

**Generate signing key** (one-time, secure location):
```bash
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
print(pem.decode())
" > /secure/utm_private.pem

# Keep PUBLIC key in repository
python -c "
from cryptography.hazmat.primitives import serialization
from utm_config_sign import load_private_key

priv = load_private_key('/secure/utm_private.pem')
pub = priv.public_key()
pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
" > utm_public.pem
```

**Sign policy**:
```bash
python -c "
from utm_config_sign import sign_config
sign_config('registry.yaml', '/secure/utm_private.pem', 'registry.yaml.sig')
"
```

**Verify policy** (automatic on startup):
```bash
export UTM_POLICY_PUBKEY=\$(cat utm_public.pem)
python utm.py  # Will verify registry.yaml.sig
```

---

## 7. Audit & Logging

### Log Format

Each event is line-delimited JSON with HMAC:
```json
{"event": {"action": "remediation_executed", "cmd": "powershell.exe", "status": "ok"}, "hmac": "a1b2c3..."}
{"event": {"action": "ti_ingest", "provider": "EmergingThreats", "count": 1250}, "hmac": "d4e5f6..."}
```

### Log Access & Analysis

**View audit trail** (with HMAC verification):
```bash
python -c "
from utm_logging import verify_log
import json

if verify_log('utm.log'):
    print('[✓] Log integrity verified')
    with open('utm.log') as f:
        for line in f:
            record = json.loads(line)
            print(record['event'])
else:
    print('[✗] Log tampering detected!')
"
```

**Export to SIEM**:
```bash
# Send logs to Elasticsearch
cat utm.log | logstash -f logstash.conf

# Or parse and forward to Splunk
splunk add oneshot utm.log -sourcetype json
```

### Log Retention

- **Online logs**: 90 days (rotation via cron/Task Scheduler)
- **Archive logs**: 7 years (encrypted, immutable)
- **Compliance audits**: Per regulatory requirement (SOC 2, ISO 27001, etc.)

---

## 8. Vulnerability & Patch Management

### Known Limitations

- **No zero-day protection**: Relies on threat intelligence feeds
- **Process monitoring** requires psutil (may have OS-specific limitations)
- **Remediation** requires elevation (user consent needed on some systems)
- **Policy signing** depends on secure key storage

### Security Updates

Monitor for:
- Python security advisories: https://python.org/dev/peps/pep-0619/
- Dependency CVEs: Use `safety check` or Snyk in CI

**Update process**:
```bash
# Check for dependency vulnerabilities
pip install safety
safety check --file requirements.txt

# Update dependencies
pip install -U -r requirements.txt

# Re-run tests
python -m pytest -q

# Rebuild SBOM
python generate_sbom.py
```

---

## 9. Metrics & KPIs

### Security Metrics to Track

| Metric | Calculation | Target |
|--------|-----------|---------|
| **MTTR** (Mean Time To Respond) | Alert → Investigation start | < 5 min |
| **MTTD** (Mean Time To Detect) | Incident → Alert | < 1 min |
| **Log Integrity** | Valid HMACs / Total events | 100% |
| **Policy Compliance** | Passing checks / Total checks | > 95% |
| **Threat Feed Freshness** | Time since last update | < 24 hours |
| **Incident Closure Rate** | Closed incidents / Total | > 90% / week |

---

## 10. Contact & Escalation

### Escalation Matrix

| Condition | Owner | Action |
|-----------|-------|--------|
| **P1: Policy Tampering** | CISO | Immediate lockdown, forensics |
| **P1: Privilege Escalation** | IR Lead | Isolation, credential reset |
| **P2: Malicious IP** | SOC Lead | Investigation, containment |
| **P2: Suspicious Process** | Help Desk | Triage, collect artifacts |
| **P3: Alerts** | Help Desk | Monitor, routine investigation |

### Contact Information

- **SOC**: `soc@company.com` | PagerDuty: `##soc-utm`
- **IR Team**: `ir-team@company.com` | Slack: `#incident-response`
- **Security Architecture**: `security-arch@company.com`
- **Compliance**: `compliance@company.com`

---

## Appendix: Quick Reference

```bash
# Check system status
python utm.py --info

# Run threat intelligence only
python utm.py --ti

# Compliance audit (no remediation)
python utm.py --audit

# Collect incident response artifacts
python utm.py --collect-artifacts

# Verify log integrity
python utm.py --verify-logs

# Output as JSON (for SIEM ingestion)
python utm.py --json
```

---

**Last Updated**: February 12, 2026  
**Next Review**: Q2 2026
