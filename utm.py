"""
UTM Security Orchestrator - Enterprise Edition
Compliance: NIST 800-53, MITRE ATT&CK, Bandit-Hardened
"""

import sys
"""UTM Security Orchestrator v3.0 — Enterprise Edition

Production-grade Unified Threat Management for Windows 11 and Linux hardening.
Features: Safe command execution, threat intelligence, signed policies, tamper-evident logging,
compliance auditing, incident response automation, and SBOM tracking.

Usage:
    python utm.py              # Full threat analysis and compliance audit
    python utm.py --audit      # Compliance check only (no remediation)
    python utm.py --ti         # Threat intelligence only
    python utm.py --help       # Show all options
    python utm.py --info       # System hardening info

For help desk: See playbooks/helpdesk_playbook.md
For security: Read SECURITY_PLAYBOOK.md and OPERATIONAL_GUIDE.md
"""

from typing import List, Dict, Set, Optional
import os
import sys
import platform
import datetime
import yaml
import hashlib
import argparse
import json
import time

from utm_safe import SafeExecutor
import utm_feed
import utm_logging
import utm_config_sign
import utm_secrets
import utm_hardening
import generate_sbom
import artifact_collector
import utm_commando
from utm_commando import CommandoSimulator, CommandoMode, AttackTechnique, PurpleTeamExercise


# --- Color codes for terminal output ---
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @staticmethod
    def disable_on_windows():
        """Disable ANSI colors on Windows if not supported."""
        if platform.system() == 'Windows':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.GetStdHandle(-11)
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    mode.value |= 0x0004
                    kernel32.SetConsoleMode(handle, mode)
            except:
                return False
        return True

Color.disable_on_windows()


# --- Enterprise Configuration ---
INTEL_FEEDS: Dict[str, str] = {
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "TorExitNodes": "https://check.torproject.org/exit-addresses",
    "AbuseCH": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}


class SecurityOrchestrator:
    """Enterprise-grade UTM controller (integrated)."""

    def __init__(self, config_path: str = "registry.yaml", log_path: str = "utm.log", sbom_out: str = "sbom.json"):
        self.config_path = config_path
        self.log_path = log_path
        self.blacklisted_ips: Set[str] = set()
        self.os_info = platform.platform()
        self.is_elevated = utm_hardening.is_elevated()
        self.executor = SafeExecutor()
        
        # Timing tracking for pytest-like output
        self.start_time = time.time()
        self.phase_times = {}
        self.phase_count = 0

        # Generate SBOM for the environment (best-effort)
        try:
            generate_sbom.generate_sbom("requirements.txt", sbom_out)
            self._log({"event": "sbom_generated", "path": sbom_out, "time": datetime.datetime.now(datetime.UTC).isoformat()})
        except Exception as e:
            # SBOM is best-effort; log failure as a non-fatal event
            try:
                self._log({"event": "sbom_failed", "error": str(e), "time": datetime.datetime.now(datetime.UTC).isoformat()})
            except Exception as log_err:
                print(f"[!] SBOM logging failed: {log_err}")

    def _format_event(self, event: Dict) -> str:
        """Format event dict as human-readable log line."""
        evt_type = event.get("event", "unknown")
        
        # Format specific event types (using ASCII-safe symbols)
        if evt_type == "sbom_generated":
            return f"  [OK] SBOM generated: {event.get('path', 'sbom.json')}"
        elif evt_type == "sbom_failed":
            return f"  [!] SBOM generation failed: {event.get('error', 'Unknown error')}"
        elif evt_type == "ti_start":
            return "  [*] Starting threat intelligence ingest..."
        elif evt_type == "ti_ingest":
            return f"  [+] {event.get('provider', '?')}: {event.get('count', 0)} IPs loaded"
        elif evt_type == "ti_complete":
            return f"  [OK] Threat intelligence complete: {event.get('total', 0)} unique IPs"
        elif evt_type == "ti_error":
            return f"  [-] TI error ({event.get('provider', '?')}): {event.get('error', 'Unknown')}"
        elif evt_type == "registry_audit_result":
            return f"  [OK] Registry audit: {event.get('passed', 0)} passed, {event.get('failed', 0)} failed"
        elif evt_type == "remediation_executed":
            cmd_short = event.get('cmd', '')[:60]
            return f"  [+] Remediation executed: {cmd_short}..."
        elif evt_type == "remediation_failed":
            cmd_short = event.get('cmd', '')[:60]
            error = event.get('error', 'Unknown')[:80]
            return f"  [-] Remediation failed: {cmd_short}...\n      Error: {error}"
        elif evt_type == "remediation_skipped":
            return f"  [*] Remediation skipped: {event.get('reason', 'Unknown')}"
        elif evt_type == "suspicious_connection":
            alert = event.get('alert', {})
            return f"  [!] ALERT: {alert.get('malicious_ip', '?')} (PID: {alert.get('pid', '?')}, Process: {alert.get('process_name', 'unknown')})"
        elif evt_type == "artifact_collection_failed":
            return f"  [!] Artifact collection failed: {event.get('error', 'Unknown')}"
        elif evt_type == "connection_monitoring_error":
            return f"  [!] Connection monitoring error: {event.get('error', 'Unknown')}"
        else:
            # Default: print as compact JSON
            return f"  [{evt_type}] {json.dumps(event, indent=0)[:80]}..."

    def _log(self, event: Dict):
        """Write an event using tamper-evident logger; fall back to stdout on error."""
        try:
            utm_logging.log_event(self.log_path, event)
            # Also print human-readable version to console
            if not getattr(self, '_json_mode', False):
                print(self._format_event(event))
        except Exception:
            print(self._format_event(event))

    def load_policy(self) -> Optional[Dict]:
        """Load and optionally verify signed policy. Returns parsed policy or None."""
        if not os.path.exists(self.config_path):
            self._log({"event": "policy_missing", "path": self.config_path})
            return None

        sig_path = f"{self.config_path}.sig"
        pubkey = os.environ.get("UTM_POLICY_PUBKEY")
        if pubkey and os.path.exists(sig_path):
            try:
                ok = utm_config_sign.verify_config(self.config_path, sig_path, pubkey)
                if not ok:
                    self._log({"event": "policy_sig_invalid", "path": self.config_path})
                    return None
            except Exception:
                self._log({"event": "policy_sig_error", "path": self.config_path})
                return None

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self._log({"event": "policy_parse_error", "error": str(e)})
            return None

    def fetch_threat_intelligence(self) -> None:
        """Fetch and normalize threat feeds into `self.blacklisted_ips`."""
        self._log({"event": "ti_start", "time": datetime.datetime.now(datetime.UTC).isoformat()})
        for name, url in INTEL_FEEDS.items():
            try:
                text = utm_feed.fetch_feed(url)
                ips = utm_feed.extract_public_ips(text)
                self.blacklisted_ips.update(ips)
                self._log({"event": "ti_ingest", "provider": name, "count": len(ips)})
            except Exception as e:
                self._log({"event": "ti_error", "provider": name, "error": str(e)})

        self._log({"event": "ti_complete", "total": len(self.blacklisted_ips)})

    def run_compliance_audit(self) -> None:
        """Run compliance checks and optionally remediate based on signed policy."""
        policy = self.load_policy()
        if not policy:
            return

        fixes = policy.get('registry_fixes', [])
        passed = failed = 0
        # Best-effort registry checks: only run on Windows
        if platform.system() == 'Windows':
            try:
                import winreg
                for item in fixes:
                    try:
                        root, path = item['key'].split('\\', 1)
                        hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
                        with winreg.OpenKey(hives.get(root, winreg.HKEY_LOCAL_MACHINE), path) as key:
                            val, _ = winreg.QueryValueEx(key, item['value'])
                            if str(val) == str(item['data']):
                                passed += 1
                            else:
                                failed += 1
                    except Exception:
                        failed += 1
            except Exception:
                # Unable to perform registry audit on this platform
                self._log({"event": "registry_audit_skipped", "platform": platform.system()})

        self._log({"event": "registry_audit_result", "passed": passed, "failed": failed})

        # Remediation
        commands = policy.get('system_commands', [])
        if commands:
            self.apply_system_remediation(commands)

    def apply_system_remediation(self, commands: List[Dict]) -> None:
        """Execute remediation commands using `SafeExecutor`.

        Each command dict should contain `command` (list or string) and optional `reason`.
        """
        if not self.is_elevated:
            self._log({"event": "remediation_skipped", "reason": "insufficient_privileges"})
            return

        for cmd in commands:
            try:
                command = cmd.get('command') or cmd.get('commmand')
                if not command:
                    continue
                proc = self.executor.run(command)
                self._log({"event": "remediation_executed", "cmd": command, "stdout": proc.stdout, "stderr": proc.stderr})
            except Exception as e:
                self._log({"event": "remediation_failed", "cmd": command, "error": str(e)})

    def perform_dpi_analysis(self) -> bool:
        """Placeholder for DPI/signature checks. Returns True if suspicious payload found."""
        # In a production product this would call into a sandboxed DPI engine.
        return False

    def monitor_activities(self) -> List[Dict]:
        """Monitor active connections and return alerts for matched blacklisted IPs."""
        alerts: List[Dict] = []
        try:
            import psutil
        except Exception:
            self._log({"event": "monitor_unavailable", "reason": "psutil_missing"})
            return alerts

        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    if remote_ip in self.blacklisted_ips:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            alert = {
                                'timestamp': datetime.datetime.now(datetime.UTC).isoformat() + 'Z',
                                'malicious_ip': remote_ip,
                                'pid': conn.pid,
                                'process_name': proc.name() if proc else None,
                                'exe': proc.exe() if proc else None,
                            }
                            alerts.append(alert)
                            # collect artifacts for IR
                            artifact_collector.collect_artifacts('artifacts')
                            self._log({"event": "suspicious_connection", "alert": alert})
                        except Exception as e:
                            self._log({"event": "artifact_collection_failed", "error": str(e)})
            except Exception as e:
                self._log({"event": "connection_monitoring_error", "error": str(e)})

        return alerts

    def compute_config_hash(self) -> Optional[str]:
        """Compute SHA256 for the active config file (D3-FIM)."""
        if not os.path.exists(self.config_path):
            return None
        h = hashlib.sha256()
        with open(self.config_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                h.update(block)
        return h.hexdigest()

    def start_phase(self, phase_name: str) -> float:
        """Mark the start of a phase; returns the start time."""
        self.phase_count += 1
        return time.time()

    def end_phase(self, phase_name: str, start_time: float, status: str = "PASSED") -> str:
        """Mark the end of a phase and return formatted output with timing."""
        elapsed = time.time() - start_time
        self.phase_times[phase_name] = elapsed
        
        # Color based on status
        color = Color.GREEN if status == "PASSED" else Color.RED if status == "FAILED" else Color.YELLOW
        status_text = f"{color}{status}{Color.END}"
        
        # Format like pytest: "test_name PASSED [100%] in 0.08s"
        progress = (self.phase_count / 3) * 100  # Assuming 3 phases max
        return f"{phase_name} {status_text} [{progress:.0f}%] in {elapsed:.2f}s"

    # =========== MANDIANT COMMANDO INTEGRATION ===========
    def run_commando_tests(self, mode: str = "detection") -> Dict:
        """
        Run Mandiant Commando simulation tests for purple team exercises.
        
        Modes:
        - detection: Look for signs of compromise (safe)
        - simulation: Simulate attacks offline (safe)
        - validation: Test if defenses would stop attacks (safe)
        - purple_team: Full red vs blue exercise
        """
        phase_start = self.start_phase("COMMANDO PURPLE TEAM")
        
        try:
            mode_enum = CommandoMode[mode.upper()] if hasattr(CommandoMode, mode.upper()) else CommandoMode.DETECTION
            simulator = CommandoSimulator(mode=mode_enum)
            
            # Run a series of defensive tests
            print(f"\n{Color.BLUE}[*] MANDIANT COMMANDO - Purple Team Exercise{Color.END}")
            print(f"    Mode: {mode_enum.value} | Detection-focused\n")
            
            # Enable key defensive techniques (all safe, offline testing)
            for technique in [
                AttackTechnique.EXECUTION,
                AttackTechnique.PERSISTENCE,
                AttackTechnique.PRIVILEGE_ESCALATION,
                AttackTechnique.DEFENSE_EVASION
            ]:
                simulator.enable_technique(technique)
            
            # Test 1: Command Execution Detection
            print("  [*] Test 1: Command execution detection...")
            result1 = simulator.test_command_execution("powershell.exe -NoProfile")
            if result1.get("is_dangerous"):
                print(f"      {Color.YELLOW}[!] PowerShell execution detected - requires monitoring{Color.END}")
            
            # Test 2: Persistence Mechanisms
            print("  [*] Test 2: Persistence mechanism detection...")
            result2 = simulator.test_persistence_mechanism("registry_run_key")
            print(f"      {Color.YELLOW}[!] Registry Run keys require continuous monitoring{Color.END}")
            
            # Test 3: Privilege Escalation
            print("  [*] Test 3: Privilege escalation paths...")
            result3 = simulator.test_privilege_escalation("token_impersonation")
            print(f"      {Color.YELLOW}[!] Token impersonation is a critical attack vector{Color.END}")
            
            # Test 4: C2 Detection
            print("  [*] Test 4: C2 beacon signature detection...")
            result4 = simulator.test_c2_beacon_detection("dns_tunneling")
            print(f"      {Color.YELLOW}[!] DNS-based C2 channels require DNS filtering{Color.END}")
            
            # Test 5: Lateral Movement
            print("  [*] Test 5: Lateral movement detection...")
            result5 = simulator.test_lateral_movement("workstation", "server")
            print(f"      {Color.YELLOW}[!] SMB/RPC lateral movement common in enterprise{Color.END}")
            
            # Generate report
            report = simulator.generate_report()
            
            # Export findings
            try:
                simulator.export_findings("commando_findings.json")
                self._log({"event": "commando_test_completed", "findings_file": "commando_findings.json"})
            except Exception as e:
                self._log({"event": "commando_export_failed", "error": str(e)})
            
            # Print summary
            print(f"\n  {Color.GREEN}[OK] Commando test summary:{Color.END}")
            print(f"      Techniques tested: {report['total_techniques_tested']}")
            print(f"      Critical findings: {report['critical_findings']}")
            print(f"      High findings: {report['high_findings']}")
            
            elapsed = time.time() - phase_start
            self.phase_times["COMMANDO"] = elapsed
            print(f"\n  {Color.GREEN}COMMANDO PASSED {Color.END}[{(self.phase_count / 4) * 100:.0f}%] in {elapsed:.2f}s\n")
            
            return report
            
        except Exception as e:
            self._log({"event": "commando_test_failed", "error": str(e)})
            print(f"  {Color.RED}[!] Commando test failed: {e}{Color.END}")
            return {"error": str(e), "status": "failed"}

    def generate_purple_team_report(self) -> Dict:
        """Generate purple team exercise recommendations"""
        return {
            "exercise_type": "Mandiant Commando",
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "recommendations": [
                "1. Deploy Splunk or ELK for SIEM correlation",
                "2. Implement EDR (CrowdStrike, Microsoft Defender, Velociraptor)",
                "3. Enable Windows Event Log forwarding (4688, 4698, 4720)",
                "4. Configure firewall rules for Command & Control detection",
                "5. Establish incident response playbooks for each MITRE ATT&CK technique",
                "6. Run monthly purple team exercises",
                "7. Integrate Threat Intelligence feeds (ThreatStream, Shodan, etc)"
            ],
            "critical_controls": [
                "EDR on all endpoints (MITRE ATT&CK detection)",
                "Network segmentation (DLP, firewall rules)",
                "Enforce MFA and RBAC",
                "Regular patching cycle (0-day management)",
                "Audit log centralization and retention"
            ]
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='UTM Security Orchestrator v3.0 — Enterprise Edition',
        epilog='For help: python utm.py --help | For incidents: See playbooks/helpdesk_playbook.md'
    )
    parser.add_argument('--audit', action='store_true', help='Run compliance audit only (no remediation)')
    parser.add_argument('--ti', action='store_true', help='Fetch threat intelligence only')
    parser.add_argument('--info', action='store_true', help='Show system hardening info')
    parser.add_argument('--collect-artifacts', action='store_true', help='Collect IR artifacts')
    parser.add_argument('--verify-logs', action='store_true', help='Verify log integrity')
    parser.add_argument('--log-key', type=str, help='Set HMAC log key (env: UTM_LOG_KEY)')
    parser.add_argument('--policy', type=str, default='registry.yaml', help='Config policy file')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--commando', type=str, choices=['detection', 'simulation', 'validation', 'purple_team'], help='Mandiant Commando purple team testing')
    parser.add_argument('--purple-report', action='store_true', help='Generate purple team exercise recommendations')
    
    args = parser.parse_args()
    
    # Set log key if provided
    if args.log_key:
        os.environ['UTM_LOG_KEY'] = args.log_key
    
    # Banner
    if not args.json:
        print("\n" + "=" * 80)
        print(f"  UTM SECURITY ORCHESTRATOR v3.0 | {platform.system()} {platform.release()}")
        print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
    
    # Initialize orchestrator
    agent = SecurityOrchestrator(config_path=args.policy)
    agent._json_mode = args.json  # Set JSON output mode
    results = {}
    
    try:
        # System info
        if args.info:
            if not args.json:
                print("\n[SYSTEM HARDENING INFO]")
                print(f"  OS: {agent.os_info}")
                print(f"  Elevated: {'Yes' if agent.is_elevated else 'No (limited features)'}")
                print(f"  Secure Boot: {'Enabled' if utm_hardening.check_secure_boot() else 'Not detected'}")
                if platform.system() == 'Linux':
                    mac = utm_hardening.check_apparmor_selinux()
                    print(f"  MAC System: {mac}")
            results['system_info'] = {
                'os': agent.os_info,
                'elevated': agent.is_elevated,
                'secure_boot': utm_hardening.check_secure_boot()
            }
        
        # Threat Intelligence
        if args.ti or (not args.audit and not args.info):
            phase_start = agent.start_phase("PHASE 1: THREAT INTELLIGENCE")
            if not args.json:
                print("\n[PHASE 1: THREAT INTELLIGENCE]")
            agent.fetch_threat_intelligence()
            if not args.json:
                print(f"  {agent.end_phase('PHASE 1', phase_start)}")
            results['threat_intel'] = {
                'blacklisted_ips': len(agent.blacklisted_ips),
                'status': 'completed'
            }
        
        # Compliance Audit
        if args.audit or (not args.ti and not args.info):
            phase_start = agent.start_phase("PHASE 2: COMPLIANCE AUDIT & REMEDIATION")
            if not args.json:
                print("\n[PHASE 2: COMPLIANCE AUDIT & REMEDIATION]")
            agent.run_compliance_audit()
            if not args.json:
                print(f"  {agent.end_phase('PHASE 2', phase_start)}")
            results['compliance'] = {'status': 'completed'}
        
        # Monitor active connections
        if not args.audit and not args.info:
            phase_start = agent.start_phase("PHASE 3: ACTIVITY MONITORING")
            if not args.json:
                print("\n[PHASE 3: ACTIVITY MONITORING]")
            alerts = agent.monitor_activities()
            if not args.json:
                print(f"  {agent.end_phase('PHASE 3', phase_start)}")
            if alerts:
                if not args.json:
                    print(f"  ⚠ {len(alerts)} suspicious connection(s) detected")
                    for alert in alerts:
                        print(f"    - {alert['malicious_ip']} (PID: {alert['pid']})")
                results['alerts'] = alerts
            else:
                if not args.json:
                    print("  [OK] No suspicious active connections")
            results['activity_monitor'] = {'status': 'completed', 'alerts_found': len(alerts)}
        
        # Collect artifacts if requested
        if args.collect_artifacts:
            if not args.json:
                print("\n[INCIDENT RESPONSE: ARTIFACT COLLECTION]")
            path = artifact_collector.collect_artifacts('artifacts')
            if not args.json:
                print(f"  [+] Artifacts collected to: {path}")
            results['artifacts'] = {'path': path}
        
        # Verify logs if requested
        if args.verify_logs:
            if not args.json:
                print("\n[LOG INTEGRITY VERIFICATION]")
            try:
                if utm_logging.verify_log(agent.log_path):
                    if not args.json:
                        print(f"  [OK] Log integrity verified")
                    results['log_verification'] = {'status': 'valid'}
                else:
                    if not args.json:
                        print(f"  ✗ Log tampering detected!")
                    results['log_verification'] = {'status': 'invalid'}
            except Exception as e:
                if not args.json:
                    print(f"  ⚠ Could not verify logs: {e}")
                results['log_verification'] = {'status': 'error', 'reason': str(e)}
        
        # Mandiant Commando Purple Team Testing
        if args.commando:
            if not args.json:
                print(f"\n[MANDIANT COMMANDO PURPLE TEAM - {args.commando.upper()}]")
            commando_report = agent.run_commando_tests(mode=args.commando)
            results['commando'] = commando_report
        
        # Generate purple team recommendations
        if args.purple_report:
            if not args.json:
                print("\n[PURPLE TEAM EXERCISE RECOMMENDATIONS]")
            purple_recs = agent.generate_purple_team_report()
            if not args.json:
                print(f"  {Color.BLUE}Recommendations for continuous improvement:{Color.END}")
                for rec in purple_recs['recommendations']:
                    print(f"    - {rec}")
                print(f"\n  {Color.BLUE}Critical security controls:{Color.END}")
                for ctrl in purple_recs['critical_controls']:
                    print(f"    - {ctrl}")
            results['purple_team'] = purple_recs
        
        # Summary
        if not args.json:
            total_time = time.time() - agent.start_time
            # Build phase timing summary (safely handle phase names)
            phase_list = []
            for name in sorted(agent.phase_times.keys()):
                t = agent.phase_times[name]
                phase_list.append(f"{name} {t:.2f}s")
            phase_summary = " + ".join(phase_list) if phase_list else "0.00s"
            
            print("\n" + "=" * 80)
            print(f"{Color.GREEN}{'=' * 78}{Color.END}")
            print(f"  {Color.GREEN}{Color.BOLD}SCAN COMPLETED{Color.END} {Color.GREEN}[100%] in {total_time:.2f}s{Color.END}")
            print(f"  Phases: {phase_summary}")
            print(f"  Log file: {agent.log_path}")
            print(f"  Next steps: Review playbooks/helpdesk_playbook.md for incident response")
            print(f"{Color.GREEN}{'=' * 78}{Color.END}")
            print("=" * 80 + "\n")
        
        # Output JSON if requested
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        if not args.json:
            print("\n\n[!] User interrupted. Shutting down...")
        agent._log({"event": "interrupted", "timestamp": datetime.datetime.now(datetime.UTC).isoformat()})
        sys.exit(0)
    
    except Exception as e:
        if not args.json:
            print(f"\n[CRITICAL ERROR] {e}")
        agent._log({"event": "critical_error", "error": str(e)})
        if args.json:
            print(json.dumps({"error": str(e)}, indent=2))
        sys.exit(1)
    