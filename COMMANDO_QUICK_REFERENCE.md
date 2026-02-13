# Mandiant Commando Quick Reference Card

## Installation

Already integrated! Run directly:

```bash
python utm.py --commando [MODE]
python utm.py --purple-report
```

## Quick Commands

### 1. Run Detection Tests
```bash
python utm.py --commando detection
```
**Tests**: PowerShell, Registry persistence, Token abuse, C2 beacons, Lateral movement
**Output**: Terminal + `commando_findings.json`

### 2. Export as JSON
```bash
python utm.py --commando detection --json
```
**Use**: Import to Splunk, ELK, Sentinel, or custom SIEM

### 3. Get Recommendations
```bash
python utm.py --purple-report
```
**Output**: 7 security improvements + 5 critical controls

### 4. Full Scan (Default)
```bash
python utm.py
```
Includes: TI + Compliance + Monitoring + Commando

### 5. Custom Mode
```bash
python utm.py --commando simulation   # Offline attack sim
python utm.py --commando validation   # Test defense effectiveness
python utm.py --commando purple_team  # Red vs blue exercise
```

## Output Files

| File | Contents |
|------|----------|
| `commando_tests.log` | Timestamped test execution log |
| `commando_findings.json` | Structured findings for SIEM |
| `utm.log` | Integration log with all phases |

## API Quick Reference

```python
from utm_commando import CommandoSimulator, AttackTechnique, CommandoMode

# Create simulator
sim = CommandoSimulator(mode=CommandoMode.SIMULATION)

# Enable techniques (optional, required for DETECTION mode)
sim.enable_technique(AttackTechnique.EXECUTION)

# Run tests
sim.test_command_execution("powershell.exe")
sim.test_persistence_mechanism("registry_run_key")
sim.test_c2_beacon_detection("dns_tunneling")

# Export findings
sim.export_findings("findings.json")

# Get report
report = sim.generate_report()
print(f"Findings: {report['total_findings']}")
```

## MITRE ATT&CK Mapping Quick Lookup

| Attack | Code | Test Command | Detection |
|--------|------|---------|-----------|
| Command Execution | T1059 | `test_command_execution()` | PowerShell transcripts, Command line audit |
| Persistence | T1547 | `test_persistence_mechanism()` | Registry monitoring, FIM |
| Privilege Escalation | T1134 | `test_privilege_escalation()` | Token events (4672), UAC logs |
| Defense Evasion | T1036 | `test_file_masquerading()` | File signature validation, Hashes |
| Lateral Movement | T1570 | `test_lateral_movement()` | SMB auditing, WMI logs, SSH auth logs |
| C2 Channels | T1071 | `test_c2_beacon_detection()` | DNS filtering, TLS inspection, EDR |

## Common Findings & How to Fix Them

### 🔴 CRITICAL: Token Impersonation (T1134)
**What**: Attacker gained SYSTEM without password  
**Fix**: ASAP - Enable 4672 auditing, update OS, limit privileged processes

### 🟠 HIGH: Registry Persistence (T1547)
**What**: Malware survives reboot via Run keys  
**Fix**: This week - Enable registry monitoring, file integrity monitoring

### 🟠 HIGH: C2 Detected (T1071)
**What**: Malware is communicating with attacker  
**Fix**: Urgent - DNS filtering, firewall block, alert security team

### 🟡 MEDIUM: PowerShell (T1059)
**What**: Attacker running commands via PowerShell  
**Fix**: This month - Enable transcript logging, constrained language mode

## Recommended Monthly Schedule

| Week | Action |
|------|--------|
| 1 | Run `--commando detection` baseline |
| 2 | Review findings, prioritize fixes |
| 3 | Implement top 2-3 recommendations |
| 4 | Run `--purple-report` for progress |

## For SOC Teams

### Alert Rules to Create

```
Alert if:
1. PowerShell executed without transcript
2. Registry Run key modified
3. SeImpersonate privilege used
4. DNS tunneling detected
5. Anomalous outbound connections
```

### Splunk Search

```spl
index=utm source="commando_findings.json" 
| search critical_findings > 0 
| table timestamp, technique, stage
```

### Grafana Dashboard

Import `commando_findings.json` to show:
- Techniques tested over time
- Critical vs high vs medium findings
- Detection rate trending
- Remediation progress

## Testing Your Setup

1. **Verify installation**:
   ```bash
   python -m pytest test_utm_commando.py -v
   ```
   Expected: 18 tests PASSED

2. **Run quick test**:
   ```bash
   python utm.py --commando detection
   ```
   Expected: 5 tests, ~3 findings, < 1 second

3. **Check output**:
   ```bash
   type commando_findings.json
   ```
   Expected: Valid JSON with critical/high findings

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Technique not enabled" | Add `sim.enable_technique(...)` |
| No findings generated | Ensure mode is SIMULATION or PURPLE_TEAM |
| Tests running slowly | Switch to DETECTION mode (offline) |
| JSON not created | Check disk space, file permissions |
| Module import error | Verify `utm_commando.py` in same directory |

## Integration Examples

### Send to Splunk
```bash
python utm.py --commando detection --json | \
  curl -X POST http://splunk:8088/services/collector \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d @-
```

### Send to Elasticsearch
```bash
python utm.py --commando detection --json | \
  curl -X POST http://elasticsearch:9200/utm/_doc -d @-
```

### Create Report
```python
import json
with open('commando_findings.json') as f:
    findings = json.load(f)

print(f"Critical: {findings['critical_findings']}")
print(f"High: {findings['high_findings']}")
print(f"Tests: {', '.join(findings['techniques'])}")
```

## Key Metrics to Track

1. **Total techniques tested**: How many attack vectors covered?
2. **Critical findings**: How many privilege escalation paths exist?
3. **Detection rate**: % of red team attacks detected by blue team?
4. **Time to remediate**: Days to fix critical findings?
5. **Defense improvements**: # of new controls deployed?

## Next Steps

- [ ] Run `python utm.py --commando detection`
- [ ] Read findings in `commando_findings.json`
- [ ] Review `COMMANDO_GUIDE.md` for details
- [ ] Run `--purple-report` for recommendations
- [ ] Implement top 3 critical fixes
- [ ] Schedule monthly purple team exercises

---

**Quick Help**: `python utm.py --help`  
**Full Guide**: Read [COMMANDO_GUIDE.md](COMMANDO_GUIDE.md)  
**Latest Tests**: `python -m pytest test_utm_commando.py -v`
