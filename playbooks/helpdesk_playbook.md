# Help Desk Playbooks — UTM Orchestrator

This document provides short, actionable playbooks for help-desk staff to triage common alerts produced by the UTM Orchestrator.

Each playbook contains: Severity, Initial Triage, Commands/Artifacts to collect, Containment Steps, Escalation Criteria, and Communication Templates.

---

## 1) Suspicious Remote Connection (Malicious IP)

- Severity: Medium → High (depending on process or data access)
- Initial Triage:
  - Confirm alert timestamp and remote IP from alert payload.
  - Verify if IP is on the current blacklist: check `agent.blacklisted_ips` or the feeds.
- Artifacts to collect:
  - Active connections: `netstat -ano` (Windows) or `ss -tnp` (Linux)
  - Process owning connection: `tasklist /FI "PID eq <pid>"` or `ps -p <pid> -o pid,cmd`
  - Binary path and hash: locate executable and compute SHA256.
  - Screenshot capture (if GUI) and user report.
- Containment Steps (Help Desk):
  - If process is unknown or malicious, capture process dump and stop the process (with manager approval).
  - Temporarily block remote IP at host firewall using documented safe-exec command (or add to blocklist via UI).
- Escalation: escalate to SOC when:
  - Process persists after restart, or
  - Binary hash is known-malicious, or
  - Multiple hosts report same IP within short window.
- Communication Template (to end-user):
  - "We detected a suspicious outbound connection from your workstation to {remote_ip}. We've isolated the connection and are investigating. Please save any open work and avoid connecting to unknown networks."

---

## 2) Configuration Tamper / Policy Mismatch

- Severity: High
- Initial Triage:
  - Verify `registry.yaml` signature (if configured) or compute current SHA256 and compare with baseline.
  - Check recent modifications (file modified timestamp, owner).
- Artifacts:
  - `sha256sum registry.yaml` (or PowerShell: `Get-FileHash`)
  - System event logs for process creating/modifying files.
  - Relevant audit entries from orchestration logs (HMAC log entries).
- Containment Steps:
  - Revert to last-known-good signed policy; remove any unauthorized entries from system.
  - Block further automatic remediation until SOC approves.
- Escalation:
  - If signature verification fails or unknown signer is detected, escalate to SOC and infosec.
- Communication Template:
  - "We detected changes to the security policy on your device. We've restored the approved policy and are investigating the source. Please do not reboot until we confirm."

---

## 3) Malware Execution / Suspicious Process

- Severity: High / Critical
- Initial Triage:
  - Check process parentage, command-line, and digital signature of binary.
  - Collect memory/process dumps if possible (secured channel)
- Artifacts:
  - `tasklist /v` or `ps auxwww`
  - Process command-line: `wmic process where processid=<pid> get CommandLine`
  - File hash, and check against threat intel (VT, internal DB)
- Containment Steps:
  - Isolate host from network (air-gap or VLAN quarantine).
  - Suspend/terminate process after capture; collect forensic copies of related files.
- Escalation:
  - Always escalate to Incident Response team for unknown or unsigned executables, or if data exfiltration suspected.
- Communication Template:
  - "A potentially malicious program was detected and quarantined on your workstation. Please do not use the system and await further instructions."

---

## 4) Repeated Authentication Failures / Account Lockout

- Severity: Low → Medium
- Initial Triage:
  - Confirm account name, source IP(s), and time window.
  - Check for related alerts across multiple hosts.
- Artifacts:
  - Authentication logs (Windows Event ID 4625), firewall logs, VPN logs.
- Containment Steps:
  - Temporarily disable or lock account if suspicious activity continues.
  - Request user to reset password and enable MFA if available.
- Escalation:
  - Escalate to SOC if brute-force pattern or known malicious IPs involved.
- Communication Template:
  - "We've noticed repeated failed login attempts for your account. Please reset your password and enable MFA. Contact IT if you did not attempt these logins."

---

## Generic Help-Desk Collection Checklist

- Timestamped notes of all actions and who authorized them.
- Copies of relevant logs and preserved hashes of modified files.
- Avoid executing unknown binaries; prefer read-only forensic collection when uncertain.
- If evidence of compromise is strong, preserve the host for IR and avoid routine reboots.

---

## Contacts & Escalation Matrix

- Level 1 (Help Desk): initial triage and containment.
- Level 2 (SOC/Threat Intel): artifact analysis, threat hunting.
- Level 3 (IR/Forensics): deep investigation, remediation plans.

Include phone numbers and secure chat channels in your internal distribution list.

---

## Playbook Maintenance

- Keep these playbooks under version control in the repository and review quarterly.
- Link automated alerts to the appropriate playbook by alert type.
