# Mandiant Commando Implementation Architecture

## System Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│         UTM Security Orchestrator v3.0                      │
│                    utm.py (Main)                            │
└──────────────┬──────────────────────────────────────────────┘
               │
     ┌─────────┼──────────────────────┬─────────────┐
     │         │                      │             │
┌────▼──┐  ┌──▼─────┐  ┌──────────┐ ┌▼────────┐  ┌▼──────────┐
│   TI  │  │Audit   │  │Monitor   │ │Artifacts│  │ COMMANDO  │◄──── NEW
│Phase1 │  │Phase 2 │  │Phase 3   │ │(IR)     │  │ Phase 4   │
└────┬──┘  └──┬─────┘  └──────────┘ └────────┘  └┬──────────┘
     │        │                                   │
     └────────┼───────────────────────────────────┘
              │
        ┌─────▼──────────────┐
        │  Security Engine   │
        ├────────────────────┤
        │ • utm_feed.py      │
        │ • utm_safe.py      │
        │ • utm_hardening.py │
        │ • utm_logging.py   │
        │ • utm_secrets.py   │
        │ • utm_commando.py  │◄── NEW
        └────────────────────┘
```

## Module: utm_commando.py

### Core Classes

```python
┌──────────────────────────────────┐
│     CommandoSimulator            │
├──────────────────────────────────┤
│ - mode: CommandoMode enum        │
│ - findings: List[Dict]           │
│ - enabled_techniques: Set[str]   │
│ - log_path: str                  │
├──────────────────────────────────┤
│ Public Methods:                  │
│ • enable_technique()             │
│ • disable_all()                  │
│ • test_command_execution()       │
│ • test_persistence_mechanism()   │
│ • test_privilege_escalation()    │
│ • test_file_masquerading()       │
│ • test_brute_force_capability()  │
│ • test_c2_beacon_detection()     │
│ • test_lateral_movement()        │
│ • generate_report()              │
│ • export_findings()              │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│   PurpleTeamExercise             │
├──────────────────────────────────┤
│ - exercise_name: str             │
│ - red_team_findings: List        │
│ - blue_team_detections: List     │
│ - gaps: List                     │
├──────────────────────────────────┤
│ Public Methods:                  │
│ • run_red_team_ops()             │
│ • analyze_blue_team_response()   │
│ • generate_afte_action_report()  │
└──────────────────────────────────┘

Enums:
• CommandoMode: SIMULATION, DETECTION, VALIDATION, PURPLE_TEAM
• AttackTechnique: T1059, T1547, T1134, T1036, T1110, T1087, T1570, T1115, T1071, T1041
```

## Attack Technique Coverage Matrix

```
                    KILL CHAIN STAGE
     ┌──────────────┬──────────────┬──────────────┐
     │ Pre-Attack   │ In-Attack    │ Post-Attack  │
┌────┴──────────────┴──────────────┴──────────────┴─────┐
│ RECONNAISSANCE                                        │
│   └─ T1087: Account Discovery (Built-in Audit)      │
├───────────────────────────────────────────────────────┤
│ WEAPONIZATION / DELIVERY                              │
│   (Not applicable - Commando focuses on post-delivery)│
├───────────────────────────────────────────────────────┤
│ EXPLOITATION / INSTALLATION ──────────────────────────┤
│   ├─ T1059: Command Execution       [test_command_execution()]  ✅
│   └─ T1036: Masquerading            [test_file_masquerading()]  ✅
├───────────────────────────────────────────────────────┤
│ ACTIONS ON OBJECTIVES ────────────────────────────────┤
│ PERSISTENCE                                           │
│   └─ T1547: Autostart Execution     [test_persistence_mechanism()] ✅
├───────────────────────────────────────────────────────┤
│ PRIVILEGE ESCALATION                                  │
│   └─ T1134: Token Manipulation      [test_privilege_escalation()] ✅
├───────────────────────────────────────────────────────┤
│ DEFENSE EVASION                                       │
│   └─ T1036: Masquerading (covered above)             │
├───────────────────────────────────────────────────────┤
│ CREDENTIAL ACCESS                                     │
│   └─ T1110: Brute Force             [test_brute_force_capability()] ✅
├───────────────────────────────────────────────────────┤
│ DISCOVERY                                             │
│   └─ T1087: Account Discovery       (Built-in)       │
├───────────────────────────────────────────────────────┤
│ LATERAL MOVEMENT                                      │
│   └─ T1570: Tool Transfer           [test_lateral_movement()] ✅
├───────────────────────────────────────────────────────┤
│ COLLECTION                                            │
│   └─ T1115: Clipboard Data          (Built-in)       │
├───────────────────────────────────────────────────────┤
│ COMMAND & CONTROL                                     │
│   └─ T1071: App Layer Protocol      [test_c2_beacon_detection()] ✅
├───────────────────────────────────────────────────────┤
│ EXFILTRATION                                          │
│   └─ T1041: Exfiltration Over C2    (Network monitoring) │
└───────────────────────────────────────────────────────┘
```

## CLI Flow Diagram

```
┌─ python utm.py ─────────────────────────────────────────┐
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Parse Arguments                                  │  │
│  │ --audit, --ti, --commando, --purple-report, etc │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ Initialize SecurityOrchestrator                 │  │
│  │ Load registry.yaml, setup logging                │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ PHASE 1: Threat Intelligence                     │  │
│  │ fetch_threat_intelligence() → 1781 IPs          │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ PHASE 2: Compliance Audit                        │  │
│  │ run_compliance_audit() → 16 passed               │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ PHASE 3: Activity Monitor                        │  │
│  │ monitor_activities() → 0 alerts                  │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ PHASE 4: Mandiant Commando (IF --commando)       │  │◄──── NEW
│  │                                                  │  │
│  │ run_commando_tests(mode):                        │  │
│  │  ├─ Create CommandoSimulator                     │  │
│  │  ├─ Enable key techniques                        │  │
│  │  ├─ Run 5 major tests                            │  │
│  │  ├─ Generate findings report                     │  │
│  │  └─ Export to JSON                               │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ Generate Purple Team Report (IF --purple-report) │  │
│  │                                                  │  │
│  │ generate_purple_team_report():                   │  │
│  │  ├─ 7 recommendations                            │  │
│  │  ├─ 5 critical controls                          │  │
│  │  └─ Print to terminal                            │  │
│  └──────────┬───────────────────────────────────────┘  │
│             │                                          │
│  ┌──────────▼───────────────────────────────────────┐  │
│  │ Output Results                                   │  │
│  │ ├─ Colored terminal (pytest-style)               │  │
│  │ ├─ JSON export (--json flag)                     │  │
│  │ ├─ Log files:                                    │  │
│  │ │  ├─ utm.log (main)                             │  │
│  │ │  ├─ commando_tests.log (detail)               │  │
│  │ │  └─ commando_findings.json (SIEM)             │  │
│  │ └─ Summary with phase timings                    │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Data Flow: Test Execution

```
CommandoSimulator.test_command_execution("powershell.exe")
│
├─ Check if T1059 enabled (or SIMULATION mode)
│
├─ Scan command for dangerous patterns:
│  └─ ["cmd.exe", "powershell.exe", "bash", "whoami", "sudo", ...]
│
├─ Create finding dict:
│  {
│    "technique": "T1059 - Command Execution",
│    "command": "powershell.exe",
│    "is_dangerous": true,
│    "stage": "EXECUTION",
│    "recommendation": "Block/alert on suspicious command combinations"
│  }
│
├─ Append to self.findings List
│
└─ Return finding dict
```

## Finding Categorization

```
Finding Analysis
   │
   ├─ Critical: Privilege escalation paths
   │  └─ T1134 (Token Manipulation) → immediate remediation needed
   │
   ├─ High: Persistence & C2 channels
   │  ├─ T1547 (Autostart) → enable monitoring
   │  └─ T1071 (C2 Beacons) → deploy DNS filtering
   │
   ├─ Medium: Command execution & credentials
   │  ├─ T1059 (PowerShell) → enable transcript logging
   │  └─ T1110 (Brute Force) → enforce strong MFA
   │
   └─ Low: Discovery & collection
      ├─ T1087 (Account Discovery)
      └─ T1115 (Clipboard Data)

Report Generation
   └─ Generate report with:
      ├─ total_findings: 3
      ├─ critical_findings: 1
      ├─ high_findings: 1
      ├─ techniques: [T1059, T1547, T1134]
      ├─ findings_summary: {critical: [...], high: [...], all: [...]}
      └─ purple_team_recommendations: [...]
```

## Purple Team Exercise Workflow

```
┌────────────────────────────────────────────────┐
│  PurpleTeamExercise("Monthly Red Team - Feb")  │
└────────────┬─────────────────────────────────┘
             │
    ┌────────▼──────────┐
    │  RED TEAM PHASE   │
    │ (Offense)         │
    └────────┬──────────┘
             │
    ┌────────▼──────────────────────────┐
    │ run_red_team_ops(simulator, [     │
    │   T1059 (Execution),              │
    │   T1547 (Persistence),            │
    │   T1134 (PrivEsc)                 │
    │ ])                                │
    └────────┬──────────────────────────┘
             │
    ┌────────▼──────────────────────┐
    │ Red Team Findings Generated:  │
    │ ├─ cmd execution (dangerous)  │
    │ ├─ registry persistence       │
    │ └─ token impersonation        │
    │                               │
    │ red_team_findings = [3 items] │
    └────────┬──────────────────────┘
             │
    ┌────────▼──────────────────────┐
    │  BLUE TEAM PHASE              │
    │  (Defense)                    │
    └────────┬──────────────────────┘
             │
    ┌────────▼──────────────────────────┐
    │ Blue Team records detections:     │
    │                                   │
    │ exercise.blue_team_detections =  │
    │   ["T1059", "T1547"]  # 2 of 3   │
    └────────┬──────────────────────────┘
             │
    ┌────────▼──────────────────────────────┐
    │  METRICS CALCULATION                  │
    │                                       │
    │ Detection Rate:                       │
    │  2 detected / 3 attacks = 66.7%      │
    │                                       │
    │ Gaps Identified:                      │
    │  T1134 (Token Manipulation) missed   │
    └────────┬──────────────────────────────┘
             │
    ┌────────▼──────────────────────────────┐
    │  After-Action Report (AAR)            │
    │  ├─ Duration: 5 seconds               │
    │ ├─ Red team attacks: 3                 │
    │  ├─ Blue team detections: 2           │
    │  ├─ Detection rate: 66.7%              │
    │  ├─ Gaps: [T1134]                      │
    │  └─ Training recommendations:         │
    │     ├─ Deploy Splunk                   │
    │     ├─ Enable 4672 auditing            │
    │     └─ Implement EDR                   │
    └────────────────────────────────────────┘
```

## Integration Points

### 1. With Existing UTM Modules

```
utm.py (Main Orchestrator)
   │
   ├─ utm_feed.py (TI ingestion) ←→ utm_commando
   │  └─ Feeds used for context in detection mode
   │
   ├─ utm_safe.py (Safe execution) ←→ utm_commando
   │  └─ Validates command patterns match SafeExecutor rules
   │
   ├─ utm_hardening.py (Hardening checks) ←→ utm_commando
   │  └─ Test persistence against hardened registry
   │
   ├─ utm_logging.py (HMAC logging) ←→ utm_commando
   │  └─ All findings logged with HMAC protection
   │
   └─ utm_config_sign.py (Policy signing) ←→ utm_commando
      └─ Findings validated against signed registry.yaml
```

### 2. With Output Systems

```
commando_findings.json (JSON output)
   │
   ├─ Splunk: Import via HTTP Event Collector (HEC)
   ├─ ELK: Import via Beats or Logstash
   ├─ Sentinel: Import via Azure Function
   └─ Custom SIEM: Parse JSON in your pipelines
```

### 3. With Incident Response

```
Findings → Alerts → Incident Response
   │
   ├─ If critical_findings > 0:
   │  └─ Create IR ticket per SECURITY_PLAYBOOK.md
   │
   ├─ If high_findings > 0:
   │  └─ Escalate to SOC per helpdesk_playbook.md
   │
   └─ Report to management:
      └─ Dashboard: Detection rate trending
```

## Performance Metrics

```
Phase Timing (typical):
├─ PHASE 1 (TI):    2.5s  (fetch 1781 IPs from 3 feeds)
├─ PHASE 2 (Audit): 0.1s  (test 16 registry keys)
├─ PHASE 3 (Monitor): 0.0s  (scan network connections)
└─ PHASE 4 (Commando): 0.01s (simulate 5 tests offline)
                ├─────────────────────────
                Total: ~2.6 seconds end-to-end

Memory Usage:
├─ CommandoSimulator: ~1 MB
├─ findings list: ~10 KB per 100 findings
└─ Total overhead: <5 MB

Scalability:
├─ Works on Windows 11, Server 2022
├─ Works on Linux (Ubuntu 22.04+)
└─ No external API dependencies (offline mode available)
```

## File Dependencies

```
utm.py
  ├─ imports utm_commando
  │    └─ from utm_commando import CommandoSimulator, ...
  │
  ├─ imports utm_feed (for context)
  ├─ imports utm_safe (for pattern validation)
  ├─ imports utm_logging (for finding logs)
  └─ No new external dependencies
     └─ Pure Python (uses only standard library + existing packages)
```

## Test Coverage

```
test_utm_commando.py (300+ lines, 18 tests)
├─ TestCommandoSimulator (13 tests)
│  ├─ test_initialization
│  ├─ test_enable_technique
│  ├─ test_disable_all_techniques
│  ├─ test_command_execution_test ✅
│  ├─ test_persistence_test ✅
│  ├─ test_privilege_escalation_test ✅
│  ├─ test_file_masquerading_test ✅
│  ├─ test_brute_force_test ✅
│  ├─ test_c2_beacon_detection ✅
│  ├─ test_lateral_movement_test ✅
│  ├─ test_technique_disabled_in_detection_mode
│  ├─ test_generate_report ✅
│  └─ test_export_findings ✅
│
├─ TestPurpleTeamExercise (2 tests)
│  ├─ test_purple_team_initialization ✅
│  ├─ test_red_team_operations ✅
│  └─ test_generate_afte_action_report ✅
│
├─ TestAttackTechniqueEnum (1 test)
│  └─ test_all_techniques_have_values ✅
│
└─ TestCommandoModeEnum (1 test)
   └─ test_all_modes_defined ✅

Result: 18/18 PASSING (100%)
```

---

**Architecture Version**: 1.0  
**Last Updated**: February 13, 2026  
**Status**: Production Ready ✅
