# UTM Operational Guide v3.0

**For**: Help Desk, System Administrators, Security Operations  
**Version**: 3.0  
**Date**: February 2026  

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Daily Operations](#daily-operations)
3. [Help Desk Procedures](#help-desk-procedures)
4. [Troubleshooting](#troubleshooting)
5. [Maintenance & Updates](#maintenance--updates)
6. [Common Issues & Solutions](#common-issues--solutions)

---

## Getting Started

### 1. Installation

**Prerequisite**: Python 3.11+
```bash
cd /path/to/utm
pip install -r requirements.txt
```

**Verify Installation**:
```bash
python test_pc.py
```
Should show: `✓ PASS` on all 10 tests.

### 2. First-Time Setup

**Step 1: Generate SBOM** (track all dependencies)
```bash
python generate_sbom.py
```
Creates `sbom.json` with all software packages.

**Step 2: Configure Log Key** (for audit trail integrity)
```powershell
# Windows PowerShell
[System.Environment]::SetEnvironmentVariable("UTM_LOG_KEY", "your-secret-key", "User")

# Linux
export UTM_LOG_KEY="your-secret-key"
echo 'export UTM_LOG_KEY="your-secret-key"' >> ~/.bashrc
```

**Step 3: Test Full Scan**
```bash
python utm.py
```
Should complete within 2–5 minutes.

---

## Daily Operations

### Morning Briefing (5 min)

1. **Check overnight alerts**:
   ```bash
   tail -100 utm.log | python -m json.tool
   ```

2. **Count active blacklists**:
   ```bash
   python -c "
   from utm import SecurityOrchestrator
   agent = SecurityOrchestrator()
   agent.fetch_threat_intelligence()
   print(f'Threat feeds: {len(agent.blacklisted_ips):,} IPs')
   "
   ```

3. **Verify log integrity**:
   ```bash
   python utm.py --verify-logs
   ```
   Should show: `Log integrity verified`

### Routine Scan (Daily, ~2:00 AM)

**Windows Task Scheduler**:
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute 'python' `
    -Argument 'c:\path\to\utm.py' `
    -WorkingDirectory 'c:\path\to'

$trigger = New-ScheduledTaskTrigger -Daily -At 2:00am

$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName 'UTM-Daily-Scan' `
    -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

**Linux Cron**:
```bash
0 2 * * * cd /opt/utm && UTM_LOG_KEY="$(cat /etc/utm/.key)" python utm.py >> /var/log/utm.log 2>&1
```

**Verify it ran**:
```bash
# Windows: check Task Scheduler history
Get-ScheduledTaskInfo -TaskName 'UTM-Daily-Scan'

# Linux: check cron execution
grep CRON /var/log/syslog | tail -5
```

### Incident Response (When alert fires)

1. **Get alert details**:
   ```bash
   python utm.py --json | jq '.alerts[]'
   ```

2. **Collect artifacts** (immediately upon alert):
   ```bash
   python utm.py --collect-artifacts
   ls -la artifacts/
   ```

3. **Verify logs weren't tampered with**:
   ```bash
   python utm.py --verify-logs
   ```

4. **Follow incident playbook**:
   See `SECURITY_PLAYBOOK.md` → Incident Response Procedures

---

## Help Desk Procedures

### Tier 1: Initial Triage

**User Reports**: "My computer is acting slow" or "Connection to X blocked"

**Steps**:
1. Ask: "Have you seen any security warnings?" 
2. Check if UTM alert exists:
   ```bash
   grep "suspicious\|alert\|fail" utm.log | tail -20
   ```
3. If yes → follow **Incident Response** (above)
4. If no → escalate to Tier 2

### Tier 2: Investigation

**Suspicious Process**:
```bash
# List processes
tasklist /v

# Get specific process details
wmic process where processid=1234 get CommandLine

# Check file signature
certUtil -hashfile C:\Path\To\File.exe SHA256
```

**Suspicious Connection**:
```bash
# Show all established connections
netstat -ano | findstr ESTABLISHED

# Correlate with threat feeds
python -c "
from utm import SecurityOrchestrator
agent = SecurityOrchestrator()
agent.fetch_threat_intelligence()
print(f'203.0.113.45 is malicious: {\"203.0.113.45\" in agent.blacklisted_ips}')
"
```

**Policy Compliance**:
```bash
# Check current compliance status
python utm.py --audit

# Review policy file
cat registry.yaml | grep -A5 "RestrictAnonymous"
```

### Tier 3: Remediation

**Approved? Then execute**:
```bash
# Run with human approval gates
python utm.py

# Or specific remediation only
python -c "
from utm import SecurityOrchestrator
agent = SecurityOrchestrator()
policy = agent.load_policy()
if policy:
    agent.apply_system_remediation(policy.get('system_commands', []))
"
```

**Before remediation**:
- [ ] User notified & approved
- [ ] Artifacts collected (maybe old data needed)
- [ ] Backup taken
- [ ] Supervisor signed off

---

## Troubleshooting

### Issue 1: "ModuleNotFoundError: No module named 'yaml'"

**Cause**: Missing dependencies  
**Fix**:
```bash
pip install -r requirements.txt
```

### Issue 2: "Permission denied" collecting artifacts

**Cause**: Need elevation  
**Fix — Windows**:
```powershell
Start-Process powershell -ArgumentList "python utm.py --collect-artifacts" -Verb RunAs
```

**Fix — Linux**:
```bash
sudo python utm.py --collect-artifacts
```

### Issue 3: "Log integrity verification failed"

**Cause**: Log file was modified (or key changed)  
**Action**:
1. **STOP** all operations
2. **ALERT** SOC immediately
3. **COLLECT** forensic copy of logs
4. **INVESTIGATE** who modified the file
5. **REVOKE** user access if suspicious

See `SECURITY_PLAYBOOK.md` → Scenario B

### Issue 4: Threat feeds not updating

**Check connectivity**:
```bash
# Test each feed URL
python -c "
import requests
urls = [
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'https://check.torproject.org/exit-addresses',
]
for url in urls:
    try:
        resp = requests.get(url, timeout=10)
        print(f'{url[:50]:50} -> {resp.status_code}')
    except Exception as e:
        print(f'{url[:50]:50} -> ERROR: {e}')
"
```

**If feeds fail**:
- Check internet connectivity: `ping 8.8.8.8`
- Check firewall rules: Allow HTTPS outbound to threat feed domains
- Manual feed update:
  ```bash
  # Download manually to artifacts/
  curl https://rules.emergingthreats.net/blockrules/compromised-ips.txt -o artifacts/feed.txt
  ```

### Issue 5: Policy won't load

**Check policy syntax**:
```bash
python -c "
import yaml
try:
    with open('registry.yaml') as f:
        yaml.safe_load(f)
    print('[✓] Policy YAML is valid')
except yaml.YAMLError as e:
    print(f'[✗] Invalid YAML: {e}')
"
```

**Check signature** (if configured):
```bash
python -c "
from utm_config_sign import verify_config
result = verify_config('registry.yaml', 'registry.yaml.sig', 'utm_public.pem')
print(f'Signature valid: {result}')
"
```

---

## Maintenance & Updates

### Weekly Maintenance

**Every Monday**:
```bash
# 1. Verify all logs are intact
python utm.py --verify-logs

# 2. Check SBOM for dependency updates
pip list --outdated

# 3. Run linters
python -m ruff check .
python -m mypy . --no-error-summary

# 4. Rotate logs (delete > 90 days old)
find . -name "utm.log*" -mtime +90 -delete
```

### Monthly Maintenance

**First week of month**:
```bash
# 1. Full audit of all machines
for host in server1 server2 server3; do
    ssh $host "python utm.py --audit"
done

# 2. Review threat intelligence effectiveness
python -c "
import json
alerts_this_month = 15
true_positives = 12
tpr = true_positives / alerts_this_month
print(f'True positive rate: {tpr*100:.1f}%')
"

# 3. Archive old logs
tar czf utm-logs-$(date +%Y%m).tar.gz utm.log*
aws s3 cp utm-logs-$(date +%Y%m).tar.gz s3://backups/utm/

# 4. Recertify policies
python utm.py --info
```

### Quarterly Updates

**Each quarter**:
```bash
# 1. Update dependencies
pip install -U -r requirements.txt

# 2. Re-run full test suite
python -m pytest -v

# 3. Security scanning
python -m bandit -r . -c bandit.yml

# 4. Update threat feeds (add new sources if available)
# Edit INTEL_FEEDS in utm.py

# 5. Review & approve policy changes
# Edit registry.yaml, sign & test on staging
```

### Annual Audit

**Jan 1 or Q1**:
```bash
# 1. Full system review
python utm.py --info

# 2. Access control audit
getent passwd | grep -v nologin

# 3. Log review (full year)
zcat utm.log.*.gz | wc -l

# 4. Incident retrospective
grep "critical\|alert" utm.log.* | wc -l

# 5. Update documentation
# Ensure README.md, playbooks, and this guide reflect current state

# 6. Certification & sign-off
# Get compliance, security, and ops approval
```

---

## Common Issues & Solutions

### Problem: High false-positive rate in threat feeds

**Symptom**: Too many legitimate IPs being blocked  
**Solution**:
1. **Reduce threat feed sensitivity** (use higher-confidence sources only)
2. **Add whitelist**:
   ```python
   # In utm.py, after feed ingestion
   WHITELIST = {'1.1.1.1', '8.8.8.8'}  # Cloudflare, Google DNS
   agent.blacklisted_ips -= WHITELIST
   ```
3. **Fine-tune IP ranges** per your organization's needs

### Problem: Out-of-date threat intelligence

**Symptom**: Detected IPs are from weeks ago  
**Solution**:
- **Increase update frequency**: From daily → every 6 hours
- **Add real-time feeds**: Consider commercial threat intel APIs
- **Use curated feeds**: Focus on high-confidence sources

### Problem: System slow during scans

**Symptom**: Computer is sluggish when UTM runs  
**Solution**:
1. **Move scan to off-hours**: Change scheduled task to 3:00 AM (less traffic)
2. **Throttle monitoring**: Reduce `psutil` query rate
3. **Exclude network drives**: Only scan local disks

### Problem: Logs filling disk

**Symptom**: `df -h` shows disk 95%+ full  
**Solution**:
```bash
# Compress old logs
gzip utm.log.*

# Archive to cold storage
tar czf utm-logs-old.tar.gz utm.log.*.gz
rm utm.log.*.gz

# Or delete if not needed
rm utm.log.* --before=90-days
```

### Problem: Users complaining about blocked processes

**Symptom**: User: "Why can't I run X anymore?"  
**Solution**:
1. **Understand**: Allowlist is preventing unsafe execution
2. **Approve** (if safe): Add binary to allowlist in `utm_safe.py`
3. **Test**: `python -c "from utm_safe import SafeExecutor; se = SafeExecutor(allowed_binaries={'myapp.exe'}); se.run(['myapp.exe'])"`
4. **Deploy**: Update on all machines

---

## Contacts & Escalation

**Help Desk**: `helpdesk@company.com` or Slack `#help`  
**SOC Team**: `soc@company.com` or PagerDuty `#soc-utm`  
**Security Arch**: `security-arch@company.com` or Slack `#security`  
**On-Call IR**: Page via PagerDuty for P1 incidents

---

## Quick Reference Card

```bash
# Status check
python utm.py --info                    # System info
python utm.py --verify-logs             # Log integrity
python utm.py --audit                   # Compliance only

# Daily operations
python utm.py                            # Full scan (TI + audit + monitor)
python utm.py --ti                       # Threat intel only
python utm.py --collect-artifacts       # Collect IR evidence

# Maintenance
python -m pytest -q                      # Run tests
python -m ruff check .                   # Lint code
python generate_sbom.py                  # Update SBOM

# Viewing logs
tail -50 utm.log                         # Last 50 events
grep malicious utm.log                   # Search for alerts
python -c "import json; [print(json.loads(l)['event']) for l in open('utm.log')]"  # Pretty-print all events
```

---

**Last Updated**: February 12, 2026  
**Next Review**: Q2 2026
