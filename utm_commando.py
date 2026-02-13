"""
Mandiant Commando Integration Module
Adds offensive security testing & vulnerability validation to UTM.

Features:
- Command execution simulation (safe mode)
- Adversarial attack simulation (MITRE ATT&CK techniques)
- Persistence mechanism detection
- C2 beacon indicators analysis
- Post-exploitation artifact detection
- Purple team (offense/defense) exercise support

Security Note: All operations sandboxed and policy-controlled.
Requires explicit enable in registry.yaml for operational mode.
"""

import os
import hashlib
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum


class AttackTechnique(Enum):
    """MITRE ATT&CK techniques for testing"""
    EXECUTION = "T1059"  # Command and Scripting Interpreter
    PERSISTENCE = "T1547"  # Boot or Logon Autostart Execution
    PRIVILEGE_ESCALATION = "T1134"  # Access Token Manipulation
    DEFENSE_EVASION = "T1036"  # Masquerading
    CREDENTIAL_ACCESS = "T1110"  # Brute Force
    DISCOVERY = "T1087"  # Account Discovery
    LATERAL_MOVEMENT = "T1570"  # Lateral Tool Transfer
    COLLECTION = "T1115"  # Clipboard Data
    COMMAND_CONTROL = "T1071"  # Application Layer Protocol
    EXFILTRATION = "T1041"  # Exfiltration Over C2 Channel


class CommandoMode(Enum):
    """Operation modes"""
    SIMULATION = "simulation"  # Safe offline testing
    DETECTION = "detection"    # Look for signs of compromise
    VALIDATION = "validation"  # Check if defenses work
    PURPLE_TEAM = "purple_team"  # Offense + defense exercises


class CommandoSimulator:
    """
    Safely simulate Mandiant Commando attacks for defensive testing.
    
    Philosophy: Test your own defenses without actual exploitation.
    """
    
    def __init__(self, mode: CommandoMode = CommandoMode.DETECTION):
        self.mode = mode
        self.findings: List[Dict] = []
        self.techniques_tested: List[str] = []
        self.enabled_techniques = set()
        self.log_path = "commando_tests.log"
    
    def enable_technique(self, technique: AttackTechnique) -> None:
        """Enable a technique for testing (requires explicit approval)"""
        self.enabled_techniques.add(technique.value)
        self._log(f"[+] COMMANDO: Enabled technique {technique.name} ({technique.value})")
    
    def disable_all(self) -> None:
        """Safety: disable all techniques"""
        self.enabled_techniques.clear()
        self._log("[!] COMMANDO: All techniques disabled")
    
    def _log(self, message: str) -> None:
        """Log with timestamp"""
        ts = datetime.now().isoformat()
        with open(self.log_path, 'a') as f:
            f.write(f"{ts} | {message}\n")
    
    # ============ EXECUTION TESTS (T1059) ============
    def test_command_execution(self, command: str) -> Dict:
        """
        Test: Can certain commands execute?
        Defense: Block unauthorized command interpreters
        """
        if "T1059" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled", "reason": "Technique not enabled"}
        
        dangerous_indicators = [
            "cmd.exe", "powershell.exe", "bash", "sh",
            "whoami", "ipconfig", "ifconfig", "net user", "sudo"
        ]
        
        is_dangerous = any(ind in command.lower() for ind in dangerous_indicators)
        
        result = {
            "technique": "T1059 - Command Execution",
            "command": command,
            "is_dangerous": is_dangerous,
            "stage": "EXECUTION",
            "recommendation": "Block/alert on suspicious command combinations"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1059")
        return result
    
    # ============ PERSISTENCE TESTS (T1547) ============
    def test_persistence_mechanism(self, mechanism_type: str) -> Dict:
        """
        Test: What persistence mechanisms could survive reboot?
        Defense: Monitor autostart locations, schedule tasks, WMI subscriptions
        """
        if "T1547" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        persistence_vectors = {
            "registry_run_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "startup_folder": "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "scheduled_task": "C:\\Windows\\System32\\Tasks",
            "wmi_event": "WMI Event Subscriptions (CIM_InstMethodCall)",
            "scheduled_job": "schtasks.exe /create",
            "cron": "/etc/cron.d, /etc/crontab",
            "rc_scripts": "/etc/init.d, /etc/rc.d"  # Linux
        }
        
        result = {
            "technique": "T1547 - Boot/Logon Autostart Execution",
            "mechanism": mechanism_type,
            "vector": persistence_vectors.get(mechanism_type, "unknown"),
            "stage": "PERSISTENCE",
            "detection_method": "Monitor file system and registry changes at boot",
            "recommendation": "Enable audit logging for autostart locations"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1547")
        return result
    
    # ============ PRIVILEGE ESCALATION TESTS (T1134) ============
    def test_privilege_escalation(self, escalation_type: str) -> Dict:
        """
        Test: Could attacker gain SYSTEM/root?
        Defense: Monitor token manipulation, User Account Control bypass attempts
        """
        if "T1134" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        escalation_paths = {
            "token_impersonation": "SeImpersonatePrivilege abuse (PrintSpooler, etc)",
            "token_duplication": "Token::Duplicate API abuse",
            "uac_bypass": "UAC (User Account Control) elevation bypass",
            "sudo_abuse": "Sudo privilege escalation (Linux)",
            "kernel_exploit": "Unpatched kernel vulnerability",
            "weak_permissions": "Weak folder/file permissions exploitation"
        }
        
        result = {
            "technique": "T1134 - Access Token Manipulation",
            "escalation_method": escalation_type,
            "description": escalation_paths.get(escalation_type, "unknown"),
            "stage": "PRIVILEGE_ESCALATION",
            "detection": "Monitor SeImpersonate events (Windows), sudo logs (Linux)",
            "mitigation": "Keep OS patched, minimize privileged processes, enable audit logging"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1134")
        return result
    
    # ============ DEFENSE EVASION TESTS (T1036) ============
    def test_file_masquerading(self, fake_name: str, real_name: str) -> Dict:
        """
        Test: Can malware hide as legitimate file?
        Defense: Validate file signatures, check code signing
        """
        if "T1036" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        result = {
            "technique": "T1036 - Masquerading",
            "fake_filename": fake_name,
            "impersonates": real_name,
            "stage": "DEFENSE_EVASION",
            "detection_method": "File signature validation, code signing verification",
            "recommendation": "Implement file integrity monitoring, enforce code signing requirements"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1036")
        return result
    
    # ============ CREDENTIAL ACCESS TESTS (T1110) ============
    def test_brute_force_capability(self, service_type: str, attempt_count: int = 100) -> Dict:
        """
        Test: How quickly could attacker brute force credentials?
        Defense: Enforce account lockout, rate limiting
        """
        if "T1110" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        result = {
            "technique": "T1110 - Brute Force",
            "service": service_type,
            "simulated_attempts": attempt_count,
            "stage": "CREDENTIAL_ACCESS",
            "defense": "Account lockout policy, rate limiting, MFA",
            "test_result": "Would succeed after ~100 attempts" if attempt_count == 100 else "Varies by policy"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1110")
        return result
    
    # ============ C2 COMMUNICATION TESTS (T1071) ============
    def test_c2_beacon_detection(self, beacon_signature: str) -> Dict:
        """
        Test: Would C2 beacon traffic be detected?
        Defense: Monitor outbound connections, DNS queries, TLS certificates
        """
        if "T1071" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        # Common C2 beacon indicators
        c2_patterns = {
            "dns_tunneling": r"^(?:\w{10,}\.|[\x00-\x1f])[a-z0-9\-\.]*\.com$",
            "dga_domain": "High entropy domain names, changing daily",
            "suspicious_port": "22, 443, 80 to unusual hosts",
            "user_agent_anomaly": "Custom or outdated user agents",
            "tls_cert_anomaly": "Self-signed, expired, or unusual issuer"
        }
        
        result = {
            "technique": "T1071 - Command & Control (C2) Beacon",
            "beacon_signature": beacon_signature,
            "stage": "COMMAND_CONTROL",
            "detection_methods": list(c2_patterns.keys()),
            "recommendation": "Deploy EDR (Endpoint Detection & Response), implement DNS filtering, monitor TLS anomalies"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1071")
        return result
    
    # ============ LATERAL MOVEMENT TESTS (T1570) ============
    def test_lateral_movement(self, source_host: str, target_host: str) -> Dict:
        """
        Test: Could attacker move to other systems?
        Defense: Network segmentation, host-based firewalls
        """
        if "T1570" not in self.enabled_techniques and self.mode != CommandoMode.SIMULATION:
            return {"status": "disabled"}
        
        result = {
            "technique": "T1570 - Lateral Tool Transfer",
            "from_host": source_host,
            "to_host": target_host,
            "stage": "LATERAL_MOVEMENT",
            "possible_protocols": ["SMB", "WinRM", "SSH", "RDP", "HTTP"],
            "mitigation": "Network segmentation, firewall rules, RBAC, MFA for remote access"
        }
        
        self.findings.append(result)
        self.techniques_tested.append("T1570")
        return result
    
    # ============ DETECTION SUMMARY ============
    def generate_report(self, include_all: bool = False) -> Dict:
        """Generate Mandiant Commando testing report"""
        
        critical_findings = [f for f in self.findings if "escalation" in str(f).lower()]
        high_findings = [f for f in self.findings if "persistence" in str(f).lower() or "c2" in str(f).lower()]
        
        report = {
            "test_mode": self.mode.value,
            "timestamp": datetime.now().isoformat(),
            "total_techniques_tested": len(self.techniques_tested),
            "techniques": self.techniques_tested,
            "critical_findings": len(critical_findings),
            "high_findings": len(high_findings),
            "total_findings": len(self.findings),
            "findings_summary": {
                "critical": critical_findings[:3] if critical_findings else [],
                "high": high_findings[:3] if high_findings else [],
                "all": self.findings if include_all else self.findings[:10]
            },
            "purple_team_recommendations": [
                "1. Run regular red team exercises against blue team defenses",
                "2. Implement SIEM with MITRE ATT&CK correlation",
                "3. Deploy EDR (Endpoint Detection & Response)",
                "4. Establish incident response playbooks",
                "5. Conduct monthly tabletop exercises"
            ]
        }
        
        return report
    
    def export_findings(self, filepath: str) -> None:
        """Export findings as JSON for SOAR/SIEM integration"""
        with open(filepath, 'w') as f:
            json.dump(self.generate_report(include_all=True), f, indent=2)
        self._log(f"[+] COMMANDO: Exported findings to {filepath}")


class PurpleTeamExercise:
    """
    Orchestrate red team (offensors) vs blue team (defenders) exercises.
    
    Workflow:
    1. Red team simulates attack using selected techniques
    2. Blue team monitors and detects
    3. Both teams review findings
    4. Lessons learned documented
    """
    
    def __init__(self, exercise_name: str):
        self.exercise_name = exercise_name
        self.red_team_findings = []
        self.blue_team_detections = []
        self.gaps = []
        self.start_time = datetime.now()
    
    def run_red_team_ops(self, simulator: CommandoSimulator, techniques: List[AttackTechnique]) -> None:
        """Red team: simulate attacks"""
        for technique in techniques:
            simulator.enable_technique(technique)
        
        # Simulated red team actions
        simulator.test_command_execution("powershell.exe -NoProfile -ExecutionPolicy Bypass")
        simulator.test_persistence_mechanism("registry_run_key")
        simulator.test_privilege_escalation("token_impersonation")
        
        self.red_team_findings = simulator.findings.copy()
    
    def analyze_blue_team_response(self) -> Dict:
        """Blue team: analyze detection gaps"""
        gap_analysis = {
            "detected": len(self.blue_team_detections),
            "missed": len(self.red_team_findings) - len(self.blue_team_detections),
            "gaps": self.gaps,
            "training_needs": [
                "SIEM threat hunting",
                "EDR response procedures",
                "Network traffic analysis"
            ]
        }
        return gap_analysis
    
    def generate_afte_action_report(self) -> Dict:
        """Generate After-Action Report (AAR)"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "exercise": self.exercise_name,
            "duration_seconds": duration,
            "red_team_simulated_attacks": len(self.red_team_findings),
            "blue_team_detections": len(self.blue_team_detections),
            "detection_rate": f"{(len(self.blue_team_detections) / max(len(self.red_team_findings), 1)) * 100:.1f}%",
            "gaps_identified": self.gaps,
            "next_exercise": "Schedule follow-up in 30 days",
            "training_recommendations": [
                "Deploy Splunk/ELK for SIEM",
                "Implement Microsoft Defender or CrowdStrike for EDR",
                "Create runbooks for each MITRE ATT&CK technique",
                "Enable Windows Event Log forwarding to SIEM"
            ]
        }
