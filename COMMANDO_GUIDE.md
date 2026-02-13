# Mandiant Commando Integration Guide

## Overview

**Mandiant Commando** has been integrated into the UTM Security Orchestrator as a **purple team testing framework** for defensive validation and security posture assessment.

### What is Mandiant Commando?

Mandiant Commando is Mandiant's (now Google Cloud Security) offensive security testing platform. Our integration allows you to:

- **Simulate** attacker techniques safely (offline, sandboxed)
- **Validate** that your defenses would detect real attacks
- **Test** detection capabilities for MITRE ATT&CK techniques
- **Identify** security gaps before threat actors do
- **Run purple team exercises** (red team vs blue team)

## Key Features

### 1. MITRE ATT&CK Technique Simulation (10 techniques)

| Technique ID | Technique Name | Attack Stage | UTM Test |
|--------------|---|---|---|
| **T1059** | Command & Scripting Interpreter | Execution | `test_command_execution()` |
| **T1547** | Boot or Logon Autostart Execution | Persistence | `test_persistence_mechanism()` |
| **T1134** | Access Token Manipulation | Privilege Escalation | `test_privilege_escalation()` |
| **T1036** | Masquerading | Defense Evasion | `test_file_masquerading()` |
| **T1110** | Brute Force | Credential Access | `test_brute_force_capability()` |
| **T1087** | Account Discovery | Discovery | Built into auditing |
| **T1570** | Lateral Tool Transfer | Lateral Movement | `test_lateral_movement()` |
| **T1115** | Clipboard Data | Collection | Built into monitoring |
| **T1071** | Application Layer Protocol (C2) | Command & Control | `test_c2_beacon_detection()` |
| **T1041** | Exfiltration Over C2 | Exfiltration | Built into network monitoring |

### 2. Four Operating Modes

```
SIMULATION    - Safe offline attack simulation (no actual commands executed)
DETECTION     - Look for signs of compromise in logs/events
VALIDATION    - Test if defenses would block/detect attacks
PURPLE_TEAM   - Full red team attack vs blue team defense exercise
```

### 3. Safety Guarantees

All Commando tests are:
- ✅ **Sandboxed**: No actual exploitation or system modification
- ✅ **Offline**: No external C2 or malware downloads
- ✅ **Reversible**: Can be disabled/reverted entirely
- ✅ **Policy-Controlled**: Require explicit technique enablement
- ✅ **Logged**: All tests logged to `commando_tests.log`

## Usage

### Quick Start: Detection Mode

Run a basic purple team detection test:

```bash
python utm.py --commando detection
```

**Output:**
```
[*] MANDIANT COMMANDO - Purple Team Exercise
    Mode: detection | Detection-focused

  [*] Test 1: Command execution detection...
      [!] PowerShell execution detected - requires monitoring
  [*] Test 2: Persistence mechanism detection...
      [!] Registry Run keys require continuous monitoring
  [*] Test 3: Privilege escalation paths...
      [!] Token impersonation is a critical attack vector
  [OK] Commando test summary:
      Techniques tested: 5
      Critical findings: 2
      High findings: 1
```

### Generate Purple Team Recommendations

Get actionable recommendations for security improvements:

```bash
python utm.py --purple-report
```

**Output:**
```
[PURPLE TEAM EXERCISE RECOMMENDATIONS]
  Recommendations for continuous improvement:
    - 1. Deploy Splunk or ELK for SIEM correlation
    - 2. Implement EDR (CrowdStrike, Microsoft Defender, Velociraptor)
    - 3. Enable Windows Event Log forwarding (4688, 4698, 4720)
    - 4. Configure firewall rules for Command & Control detection
    - 5. Run monthly purple team exercises
    
  Critical security controls:
    - EDR on all endpoints (MITRE ATT&CK detection)
    - Network segmentation (DLP, firewall rules)
    - Enforce MFA and RBAC
    - Regular patching cycle (0-day management)
```

### Simulation Mode: Full Test

Simulate all major attack techniques:

```bash
python utm.py --commando simulation --json
```

See findings exported to `commando_findings.json`.

### Validation Mode: Defense Testing

Test if current defenses would catch attacks:

```bash
python utm.py --commando validation
```

### Purple Team Mode: Red vs Blue

Schedule monthly purple team exercises to test:

```bash
python utm.py --commando purple_team
```

Generates After-Action Report (AAR) with:
- Red team attacks simulated
- Blue team detections achieved
- Detection rate percentage
- Training needs identified
- Next exercize recommendations

## Integration with UTM Workflow

### Full Scan with Commando

```bash
python utm.py --commando detection
```

Runs all UTM phases PLUS Commando tests:
1. **Phase 1**: Threat Intelligence (1781 IPs)
2. **Phase 2**: Compliance Audit (registry, hardening)
3. **Phase 3**: Activity Monitoring (network connections)
4. **Phase 4**: Commando Purple Team Tests (5 major techniques)

### Incident Response Integration

If an alert is triggered during `--monitor` or `--audit`, run Commando tests to validate defenses:

```bash
# Step 1: Run full scan
python utm.py --audit --ti --commando detection

# Step 2: Review findings in commando_findings.json
type commando_findings.json | more

# Step 3: Implement recommendations from SECURITY_PLAYBOOK.md
```

## API: Using Commando Programmatically

### Basic Simulation

```python
from utm_commando import CommandoSimulator, CommandoMode, AttackTechnique

# Create simulator
sim = CommandoSimulator(mode=CommandoMode.SIMULATION)

# Enable specific techniques
sim.enable_technique(AttackTechnique.EXECUTION)
sim.enable_technique(AttackTechnique.PERSISTENCE)

# Run tests
result1 = sim.test_command_execution("powershell.exe -NoProfile")
print(result1['is_dangerous'])  # True

result2 = sim.test_persistence_mechanism("registry_run_key")
print(result2['stage'])  # "PERSISTENCE"

# Export findings
sim.export_findings("my_findings.json")

# Get report
report = sim.generate_report()
print(f"Total findings: {report['total_findings']}")
```

### Purple Team Exercise

```python
from utm_commando import PurpleTeamExercise, CommandoSimulator, AttackTechnique

# Create exercise
exercise = PurpleTeamExercise("Monthly Red Team - Feb 2026")

# Red team simulates attacks
simulator = CommandoSimulator(mode=CommandoMode.SIMULATION)
red_techniques = [
    AttackTechnique.EXECUTION,
    AttackTechnique.PERSISTENCE,
    AttackTechnique.PRIVILEGE_ESCALATION
]

exercise.run_red_team_ops(simulator, red_techniques)

# Blue team records detections
exercise.blue_team_detections = ["T1059", "T1547"]  # Detected 2 of 3

# Generate After-Action Report
aar = exercise.generate_afte_action_report()
print(f"Detection Rate: {aar['detection_rate']}")  # "66.7%"
```

### Integration with SecurityOrchestrator

```python
from utm import SecurityOrchestrator

agent = SecurityOrchestrator(config_path='registry.yaml')

# Run Commando tests
report = agent.run_commando_tests(mode='detection')

# Get recommendations
purple_recs = agent.generate_purple_team_report()
for rec in purple_recs['recommendations']:
    print(rec)
```

## Interpreting Results

### Finding Severity Levels

| Level | Description | Action |
|-------|---|---|
| **Critical** | Privilege escalation or token manipulation | Immediate: Deploy EDR, enable audit logs |
| **High** | Persistence or C2 channels | Urgent: Update SIEM rules, network segmentation |
| **Medium** | Command execution or credential access | Important: Enable log forwarding, MFA |
| **Low** | Discovery/collection techniques | Monitor: Regular threat intelligence updates |

### Common Findings Explained

#### 1. **PowerShell Execution (T1059)**
**Indicator**: `test_command_execution("powershell.exe -NoProfile")`

**Why it matters**: PowerShell is powerful but often silently allowed

**Defense**: 
- Enable PowerShell transcript logging (Event ID 4103)
- Constrained Language Mode in production
- AMSI (Antimalware Scan Interface) enabled

#### 2. **Registry Run Keys (T1547)**
**Indicator**: `test_persistence_mechanism("registry_run_key")`

**Why it matters**: Survives reboot, achieves persistence

**Defense**:
- Monitor `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- File Integrity Monitoring (FIM)
- Endpoint Detection & Response (EDR)

#### 3. **Token Impersonation (T1134)**
**Indicator**: `test_privilege_escalation("token_impersonation")`

**Why it matters**: Can escalate to SYSTEM without re-authentication

**Defense**:
- Monitor `SeImpersonate` privilege events (4672)
- Limit privileged processes
- Windows Defender Exploit Guard

#### 4. **C2 Beacons (T1071)**
**Indicator**: `test_c2_beacon_detection("dns_tunneling")`

**Why it matters**: Command & Control channels = active compromise

**Defense**:
- DNS filtering (Cisco Umbrella, Cloudflare)
- Network IDS/IPS (Suricata, Snort)
- TLS inspection and certificate validation

## Output Files

### commando_tests.log

Timestamped log of all tests:
```
2026-02-13T13:04:48.399379 | [+] COMMANDO: Enabled technique EXECUTION (T1059)
2026-02-13T13:04:48.400123 | [*] COMMANDO: Test started - Command execution
2026-02-13T13:04:48.401456 | [+] COMMANDO: Findings exported to commando_findings.json
```

### commando_findings.json

Structured findings for SOAR/SIEM integration:

```json
{
  "test_mode": "detection",
  "timestamp": "2026-02-13T13:04:48.399379",
  "total_techniques_tested": 5,
  "techniques": ["T1059", "T1547", "T1134", "T1071", "T1570"],
  "critical_findings": 1,
  "high_findings": 2,
  "findings_summary": {
    "critical": [
      {
        "technique": "T1134 - Access Token Manipulation",
        "escalation_method": "token_impersonation",
        "mitigation": "Keep OS patched, minimize privileged processes"
      }
    ],
    "high": [...]
  },
  "purple_team_recommendations": [...]
}
```

## Recommended Schedule

### Immediate (This Week)
1. Run `python utm.py --commando detection` to assess detection gaps
2. Review `commando_findings.json`
3. Read recommendations from `--purple-report`

### Short-term (This Month)
1. Enable PowerShell logging (T1059 detection)
2. Deploy EDR on critical systems (CrowdStrike, Defender)
3. Create MITRE ATT&CK incident response runbooks
4. Set up Windows Event Log forwarding to SIEM

### Medium-term (This Quarter)
1. Run monthly purple team exercises (`--commando purple_team`)
2. Deploy Splunk or ELK for SIEM correlation
3. Implement network segmentation
4. Enable MFA on all privileged accounts

### Long-term (This Year)
1. Achieve 80%+ detection rate on purple team exercises
2. Zero critical findings from Commando tests
3. Quarterly tabletop exercises based on findings
4. Board-level reporting on security posture

## Testing & Validation

### Run Unit Tests

```bash
python -m pytest test_utm_commando.py -v
```

**Results**:
```
test_utm_commando.py::TestCommandoSimulator::test_initialization PASSED
test_utm_commando.py::TestCommandoSimulator::test_command_execution_test PASSED
test_utm_commando.py::TestCommandoSimulator::test_persistence_test PASSED
test_utm_commando.py::TestCommandoSimulator::test_c2_beacon_detection PASSED
...
========================= 18 passed in 0.19s =========================
```

## Integration with Other Tools

### Splunk Integration

```spl
index=utm source="commando_findings.json" 
| search critical_findings > 0 
| fields timestamp, techniques, critical_findings
| timechart avg(critical_findings) by technique
```

### Elasticsearch Integration

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "test_mode": "detection" } },
        { "range": { "timestamp": { "gte": "now-7d" } } }
      ]
    }
  }
}
```

### Microsoft Sentinel Integration

Import `commando_findings.json` to Microsoft Sentinel for:
- Threat dashboards
- Risk scoring
- Automated response playbooks

## Troubleshooting

### "Technique not enabled" message

**Problem**: Test returns `{"status": "disabled"}`

**Solution**: Explicitly enable techniques in SIMULATION or DETECTION mode:
```python
sim.enable_technique(AttackTechnique.PERSISTENCE)
```

### Tests running slowly

**Problem**: Tests taking > 5 seconds

**Solution**: Run in SIMULATION mode (offline), not DETECTION (monitors assets)

### Missing findings

**Problem**: No critical_findings reported

**Solution**: Run in PURPLE_TEAM mode with full red team operations simulation

## Links & References

- **MITRE ATT&CK**: https://attack.mitre.org
- **Mandiant APT Reports**: https://www.mandiant.com/
- **Security Orchestration**: See `OPERATIONAL_GUIDE.md`
- **Incident Response**: See `SECURITY_PLAYBOOK.md`
- **Deployment**: See `DEPLOYMENT_GUIDE.md`

## Support

For issues or questions:
1. Check `commando_tests.log` for detailed test execution
2. Review findings in `commando_findings.json`
3. Consult [playbooks/helpdesk_playbook.md](playbooks/helpdesk_playbook.md)
4. Run validation tests: `python -m pytest test_utm_commando.py -v`
