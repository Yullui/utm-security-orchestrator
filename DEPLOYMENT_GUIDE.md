# UTM Deployment & Enterprise Setup Guide

**Version**: 3.0 Production Release  
**Date**: February 2026  
**For**: System Administrators, Security Architects, DevOps Teams

---

## Quick Start (5 minutes)

### 1. Install & Verify

```bash
# Clone/download UTM
cd /opt/utm  # or C:\Program Files\UTM

# Install dependencies
pip install -r requirements.txt

# Verify installation
python test_pc.py
```

Expected output: `Total: 10/10 passed`

### 2. Set Environment Variables

```bash
# Set log integrity key (HMAC for audit trail)
export UTM_LOG_KEY="$(openssl rand -hex 32)"

# Optional: Set policy verification key
export UTM_POLICY_PUBKEY="$(cat utm_public.pem)"
```

### 3. Run First Scan

```bash
# Full scan (threat intel + compliance + monitoring)
python utm.py

# Or check system hardening status
python utm.py --info
```

---

## Production Deployment

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Endpoint (Windows 11 / Linux)                          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ UTM Security Orchestrator                       │   │
│  │  • Threat intel ingestion (public feeds)        │   │
│  │  • Safe command execution (allowlist)           │   │
│  │  • Policy verification (Ed25519)                │   │
│  │  • Tamper-evident logging (HMAC)                │   │
│  │  • Runtime hardening checks                     │   │
│  └──────────────────┬──────────────────────────────┘   │
│                    │                                    │
│        ┌───────────┼───────────┬──────────────┐        │
│        │           │           │              │        │
│        v           v           v              v        │
│  ┌──────────┐  ┌──────────┐ ┌────────┐  ┌──────────┐ │
│  │Register  │  │Firewall  │ │Process │  │ Network  │ │
│  │Audit/    │  │Config    │ │Monitor │  │Artifacts │ │
│  │Policy    │  │(Windows) │ │& Log   │  │Collection│ │
│  └──────────┘  └──────────┘ └────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────┘
        │
        │ Logs (HMAC-protected JSON)
        │
        v
┌─────────────────────────────┐
│ SIEM / Log Aggregation      │
│ (ELK, Splunk, Datadog)      │
└─────────────────────────────┘
        │
        │ Alerts
        │
        v
┌─────────────────────────────┐
│ SOC / Security Dashboard    │
└─────────────────────────────┘
```

### Multi-Host Deployment

**Federated Setup** (for large organizations):

```yaml
# config/utm_central.yaml
central_config:
  log_aggregation: "https://siem.company.com/api/logs"
  policy_server: "https://policy.company.com/api/policy"
  threat_intel_mirror: "https://ti.company.com/feeds"
  
agents:
  - name: "workstations"
    scope: "*.company.com"
    policy: "baseline_hardening.yaml"
    schedule: "0 2 * * *"  # 2:00 AM daily
    
  - name: "servers"
    scope: "prod-*.company.com"
    policy: "server_hardening.yaml"
    schedule: "0 1 * * *"  # 1:00 AM daily (before servers busy)
```

**Deploy to all machines**:
```bash
#!/bin/bash
# deploy.sh

HOSTS="web1 web2 web3 db1 db2 fw1"

for host in $HOSTS; do
    ssh $host "
        cd /opt/utm
        git pull origin main
        pip install -r requirements.txt
        python -m pytest -q && echo '[✓] Tests passed'
        python generate_sbom.py
    "
done

echo "[✓] Deployment complete to all hosts"
```

---

## Configuration

### Example Policy (registry.yaml)

```yaml
---
# Windows Registry hardening policy
registry_fixes:
  # CIS Control 5.1: Restrict Anonymous Access
  - key: "HKLM\\System\\CurrentControlSet\\Control\\Lsa"
    value: "RestrictAnonymous"
    data: "1"
    reason: "CIS 5.1 - Prevent null session enumeration"
    
  # CIS Control 5.2: Restrict Remote SAM Connections
  - key: "HKLM\\System\\CurrentControlSet\\Control\\Lsa"
    value: "RestrictRemoteSAM"
    data: "1"
    reason: "CIS 5.2 - Prevent remote registry access"
    
  # NIST: Disable unnecessary services
  - key: "HKLM\\System\\CurrentControlSet\\Services\\NetBT"
    value: "Start"
    data: "4"
    reason: "Disable NetBIOS (use DNS instead)"

# System commands (remediation)
system_commands:
  - command: ["powershell.exe", "-c", "Update-Help -Force"]
    reason: "Keep PowerShell help up-to-date"
    
  - command: ["powershell.exe", "-c", "Get-WindowsUpdate -Install -MicrosoftUpdate -Confirm:$false"]
    reason: "Install Windows patches (requires elevation)"
    
  - command: ["netsh.exe", "advfirewall", "reset"]
    reason: "Reset Windows Firewall to defaults (if corrupted)"

# Scheduling
audit_schedule:
  frequency: "daily"
  time: "02:00"
  timezone: "UTC"
  
compliance_targets:
  - cis_windows_benchmark: "v1.14"
  - nist_800_53: "AC-3,SI-4,AU-12"
  - pci_dss: "1.1,6.2,10.2"
```

### Configure Threat Feeds

Edit `utm.py`:
```python
INTEL_FEEDS: Dict[str, str] = {
    # Default feeds (high confidence)
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "TorExitNodes": "https://check.torproject.org/exit-addresses",
    "AbuseCH": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    
    # Add your own
    "CompanyInternalTI": "https://ti.company.com/api/malicious-ips",
    "CustomBlocklist": "https://company.com/threat-intel/feed.txt",
}
```

---

## Integration with SIEM

### ELK Stack (Elasticsearch)

```bash
# 1. Install logstash plugin
logstash-plugin install logstash-input-file

# 2. Create logstash config
cat > /etc/logstash/conf.d/utm.conf << 'EOF'
input {
  file {
    path => "/opt/utm/utm.log"
    codec => json
    start_position => "end"
    tags => ["utm", "security"]
  }
}

filter {
  mutate {
    add_field => { "source" => "utm" }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "utm-%{+YYYY.MM.dd}"
  }
}
EOF

# 3. Start logstash
systemctl restart logstash

# 4. View in Kibana
# Kibana > Discover > utm-* index
```

### Splunk

```bash
# 1. Copy UTM logs to Splunk input
cp utm.log /opt/splunkforwarder/etc/apps/utm/logs/

# 2. Add source type
# Splunk Settings > Data Inputs > Files & Directories
# Add /opt/utm/utm.log, source type: json

# 3. Create alerts
# Splunk > Alerts > New Alert
# Search: sourcetype=utm malicious_ip=*
# Action: Send to PagerDuty
```

### Datadog

```python
# Edit utm.py, add at end of main():
import datadog
datadog.initialize(api_key='your-dd-api-key', app_key='your-dd-app-key')

# Send all results to Datadog
from datadog import api
api.Metric.send(
    metric='utm.scan.completed',
    points=1,
    tags=['os:windows', 'version:3.0']
)
```

---

## Hardening Checklist

- [ ] Python 3.11+ installed
- [ ] All dependencies installed: `pip install -r requirements.txt`
- [ ] Environment variables set: `UTM_LOG_KEY`, optionally `UTM_POLICY_PUBKEY`
- [ ] Daily scan scheduled (2:00 AM is recommended)
- [ ] Logs forwarded to SIEM (ELK/Splunk/Datadog)
- [ ] Alerts configured in security dashboard
- [ ] Help desk trained on playbooks (`playbooks/helpdesk_playbook.md`)
- [ ] Security team receives P1 alerts via PagerDuty
- [ ] SBOM generated and tracked: `python generate_sbom.py`
- [ ] Policy file signed (recommended): `python -c "from utm_config_sign import sign_config; sign_config('registry.yaml', 'private.pem', 'registry.yaml.sig')"`
- [ ] Test full incident response once per quarter
- [ ] Annual audit scheduled

---

## Monitoring & Alerting Rules

### Alert Rules (for SIEM)

**P1 (Critical) Alerts**:
```
- Policy tampering: event.type=="policy_sig_invalid" 
- Log tampering: event.type=="log_verification_failed"
- Privilege escalation: event.type=="privilege_elevation_attempt"
- Multiple malicious IPs from same host: COUNT(malicious_ip) > 3 IN 1h
```

**P2 (High) Alerts**:
```
- Malicious IP connection: event.type=="suspicious_connection"
- Failed compliance check: event.type=="compliance_failed"
- Threat feed fetch failure: event.type=="ti_error" COUNT > 3
```

**P3 (Medium) Alerts**:
```
- Remediation required: event.type=="remediation_skipped"
- Artifacts collected: event.type=="artifact_collection"
```

### Dashboard Metrics

Create dashboards in SIEM:
- **Compliance Rate**: `compliance_passed / total_checks * 100`
- **Alert Volume**: `COUNT(malicious_ip) BY host, day`
- **Policy Violations**: `event.type="policy_*" TREND`
- **Log Integrity**: `log_verification_valid / total_events`

---

## Backup & Disaster Recovery

### Backup Strategy

```bash
# Daily backup of critical files (after UTM runs)
tar czf /backup/utm-$(date +%Y%m%d).tar.gz \
    /opt/utm/registry.yaml \
    /opt/utm/registry.yaml.sig \
    /opt/utm/utm.log \
    /opt/utm/utm_public.pem \
    /opt/utm/sbom.json

# Archive to cold storage (AWS S3, Azure, etc.)
aws s3 cp /backup/utm-$(date +%Y%m%d).tar.gz s3://backups/utm/
```

### Disaster Recovery Plan

**If UTM system is compromised**:
1. Isolate the machine from network
2. Restore from last-known-good backup
3. Re-validate all policy files with signatures
4. Re-run compliance audit on entire fleet
5. Investigate root cause

**If main policy is lost**:
```bash
# Restore from Git (if it's version-controlled)
git checkout registry.yaml
python -c "from utm_config_sign import sign_config; sign_config('registry.yaml', 'private.pem', 'registry.yaml.sig')"
```

---

## Performance & Optimization

### Typical Scan Times

| Component | Duration | Notes |
|-----------|----------|-------|
| Threat Intelligence Fetch | 10–30 sec | Depends on network/feed size |
| Registry Audit (Windows) | 5–10 sec | Only runs on Windows |
| Policy Load & Verify | 1–2 sec | Signature verification |
| Activity Monitoring | 5–15 sec | Depends on # connections |
| Logging & Artifacts | 2–5 sec | Only if --collect-artifacts |
| **Total** | **30–90 sec** | **Typical full scan** |

### Tuning

**For slow networks** (high-latency feeds):
```python
# In utm.py, increase timeout:
response = requests.get(url, timeout=30)  # was 10
```

**For high-process-count systems** (servers):
```python
# Skip comprehensive activity monitoring
agent.monitor_activities()  # Runs psutil on all processes
# Use sampling instead (check 10% of processes)
```

**For resource-constrained systems**:
```bash
# Run threat intel only (faster)
python utm.py --ti

# Or audit only (skips feed fetches)
python utm.py --audit
```

---

## Support & Documentation

- **Installation Issues**: See `README.md`
- **Testing & Debugging**: See `TESTING.md`, `TEST_QUICK_START.md`
- **Security Procedures**: See `SECURITY_PLAYBOOK.md`
- **Day-to-Day Operations**: See `OPERATIONAL_GUIDE.md`
- **Help Desk Procedures**: See `playbooks/helpdesk_playbook.md`

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **3.0** | Feb 2026 | CLI args, JSON output, professional playbooks |
| **2.1** | Jan 2026 | Added SBOM, artifact collection, improved logging |
| **2.0** | Dec 2025 | Added config signing, HMAC logging |
| **1.0** | Nov 2025 | Initial release |

---

**For support**: Contact your security team or see contact info in `SECURITY_PLAYBOOK.md`
