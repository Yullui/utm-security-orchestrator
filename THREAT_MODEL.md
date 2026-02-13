# UTM Security Orchestrator - Threat Model

## Executive Summary

This document formalizes the threat model using **STRIDE** methodology and maps vulnerabilities to **MITRE ATT&CK** defensive techniques and **NIST 800-53** mitigations.

---

## Part 1: STRIDE Analysis

### STRIDE Categories
- **S**poofing: Identity spoofing
- **T**ampering: Data alteration
- **R**epudiation: Denial of actions
- **I**nformation Disclosure: Confidentiality breach
- **D**enial of Service: Availability loss
- **E**levation of Privilege: Unauthorized privilege gain

---

## Threat 1: Malicious Payload Injection (cmd['id'])

### Attack Vector
```python
# VULNERABLE: Raw string concatenation
cmd = f"powershell.exe {user_input}"

# If user_input = "; rm -rf /tmp"
# Actual cmd = "powershell.exe ; rm -rf /tmp"
```

### STRIDE Category
- **Tampering**: Malicious command injection
- **Elevation of Privilege**: Execution as orchestrator user

### Threat Chain (MITRE ATT&CK)
```
T1059 (Command Execution)
  └─ T1027 (Obfuscation)
      └─ T1036 (Masquerading)
          └─ T1543 (Create or Modify System Process)
```

### Current Mitigations ✅
```python
# utm_safe.py - SafeExecutor
class SafeExecutor:
    ALLOWLIST = {
        'powershell.exe': True,
        'ipconfig': True,
        'netstat': True,
        # ... explicit whitelist only
    }
    
    def run(self, command):
        # 1. Parse command to list (not string concat)
        cmd_list = shlex.split(command)
        
        # 2. Validate first element is in whitelist
        if cmd_list[0] not in self.ALLOWLIST:
            raise Exception(f"Command not allowed: {cmd_list[0]}")
        
        # 3. Use subprocess.run with list (prevents shell injection)
        return subprocess.run(cmd_list, ...)
```

### Residual Risk
- **Severity**: MEDIUM
- **Likelihood**: LOW (whitelist enforced)
- **Impact**: Command execution as orchestrator UID

### NIST 800-53 Controls
- **AC-3**: Access Control Enforcement
- **SI-10**: Information System Monitoring and Auditing
- **SI-2**: Software Updates/Patches

### Mitigation Enhancement
```python
# Add signature verification
def validate_command(cmd_str: str) -> bool:
    # 1. Parse to AST (not direct string)
    try:
        ast.parse(cmd_str)
    except SyntaxError:
        return False
    
    # 2. Check against known-good hashes (code signing)
    cmd_hash = hashlib.sha256(cmd_str.encode()).hexdigest()
    if cmd_hash not in SIGNED_COMMANDS:
        log("WARNING: Unsigned command", cmd_str)
        # Require approval for unsigned commands
        return False
    
    return True
```

---

## Threat 2: Registry Policy Tampering (Persistent Backdoor)

### Attack Vector
Attacker modifies `registry.yaml` to insert backdoor in compliance checks.

### STRIDE Category
- **Tampering**: Configuration file alteration
- **Elevation of Privilege**: Persistent execution

### Threat Chain (MITRE ATT&CK)
```
T1547 (Boot or Logon Autostart Execution)
  └─ T1027 (Obfuscation)
      └─ T1140 (Deobfuscation)
```

### Current Mitigations ✅
```python
# utm_config_sign.py - Ed25519 policy verification
class ConfigVerifier:
    def verify_policy(self, policy_path: str, signature_path: str) -> bool:
        # 1. Load policy
        with open(policy_path, 'rb') as f:
            policy_data = f.read()
        
        # 2. Load signature
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        # 3. Verify Ed25519 signature
        public_key.verify(signature, policy_data)
        return True
```

### Residual Risk
- **Severity**: HIGH
- **Likelihood**: MEDIUM (requires file write access)
- **Impact**: Persistent compromise

### NIST 800-53 Controls
- **CA-7**: Continuous Monitoring
- **CM-3**: Change Control
- **SI-7**: Software, Firmware, and Information Integrity

### Mitigation Enhancement Required ✅
```python
# Hash-chain integrity verification
class ConfigIntegrityChain:
    def __init__(self):
        self.previous_hash = "0" * 64
    
    def verify_and_chain(self, policy_path: str) -> bool:
        # 1. Load and hash policy
        with open(policy_path, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        
        # 2. Verify Ed25519 signature
        # ... (existing code)
        
        # 3. Chain to previous (detect replacement tampering)
        chained_hash = hashlib.sha256(
            (self.previous_hash + current_hash).encode()
        ).hexdigest()
        
        # 4. Write chain record (immutable log)
        self._log_chain_record(chained_hash)
        
        self.previous_hash = current_hash
        return True
```

---

## Threat 3: Log Tampering & Repudiation (Forensic Integrity)

### Attack Vector
Attacker modifies `utm.log` to hide command execution.

### STRIDE Category
- **Tampering**: Log alteration
- **Repudiation**: Deniability of compromise

### Threat Chain (MITRE ATT&CK)
```
T1070 (Indicator Removal)
  └─ T1070.001 (Clear Windows Event Logs)
      └─ T1562 (Impair Defenses)
```

### Current Mitigations ✅
```python
# utm_logging.py - HMAC-SHA256 integrity
class TamperEvidenceLogger:
    def __init__(self, log_path: str, hmac_key: str):
        self.log_path = log_path
        self.hmac_key = hmac_key.encode()
    
    def log(self, event: Dict) -> None:
        # 1. Serialize event
        event_str = json.dumps(event, sort_keys=True)
        
        # 2. Compute HMAC
        h = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
        hmac_digest = h.hexdigest()
        
        # 3. Write event + HMAC
        with open(self.log_path, 'a') as f:
            f.write(f"{event_str}|{hmac_digest}\n")
    
    def verify(self) -> bool:
        # 1. Read all lines
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
        
        # 2. Verify each HMAC
        for line in lines:
            event_str, claimed_hmac = line.rsplit('|', 1)
            h = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
            if h.hexdigest() != claimed_hmac.strip():
                raise IntegrityError("Log tampering detected!")
        
        return True
```

### Residual Risk
- **Severity**: MEDIUM
- **Likelihood**: LOW (requires HMAC key)
- **Impact**: Forensic timeline corruption

### NIST 800-53 Controls
- **AU-3**: Content of Audit Records
- **AU-12**: Audit Generation
- **AU-9**: Protection of Audit Information

### Mitigation Enhancement Required ✅
```python
# Hash-chain event linking (blockchain-style)
class ChainedAuditLog:
    def __init__(self, log_path: str, hmac_key: str):
        self.log_path = log_path
        self.hmac_key = hmac_key
        self.event_chain = []  # Link to previous event
    
    def log(self, event: Dict) -> str:
        # 1. Get previous hash (or "0" if first)
        prev_hash = self.event_chain[-1] if self.event_chain else "0" * 64
        
        # 2. Build event with chain reference
        event_with_chain = {
            **event,
            "previous_hash": prev_hash,
            "sequence_number": len(self.event_chain)
        }
        
        # 3. Serialize and HMAC
        event_str = json.dumps(event_with_chain, sort_keys=True)
        h = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
        event_hash = h.hexdigest()
        
        # 4. Write chain record
        with open(self.log_path, 'a') as f:
            f.write(f"{event_str}|{event_hash}\n")
        
        self.event_chain.append(event_hash)
        return event_hash
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify chained log integrity. Returns (is_valid, tampering_indices)"""
        tampering_detected = []
        
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
        
        prev_hash = "0" * 64
        
        for idx, line in enumerate(lines):
            event_str, claimed_hash = line.rsplit('|', 1)
            event_dict = json.loads(event_str)
            
            # 1. Verify HMAC
            h = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
            if h.hexdigest() != claimed_hash.strip():
                tampering_detected.append(idx)
                continue
            
            # 2. Verify chain linkage
            if event_dict.get('previous_hash') != prev_hash:
                tampering_detected.append(idx)
                continue
            
            # 3. Verify sequence
            if event_dict.get('sequence_number') != idx:
                tampering_detected.append(idx)
                continue
            
            prev_hash = claimed_hash.strip()
        
        return len(tampering_detected) == 0, tampering_detected
```

---

## Threat 4: Privilege Escalation (Orchestrator Compromise)

### Attack Vector
Attacker gains control of UTM process → executes commands as system.

### STRIDE Category
- **Elevation of Privilege**: Unauthorized privilege gain

### Threat Chain (MITRE ATT&CK)
```
T1134 (Access Token Manipulation)
  └─ T1547 (Boot/Logon Autostart Execution)
      └─ T1543 (Create or Modify System Process)
```

### Current Mitigations ✅
```python
# utm_hardening.py - Privilege check
def is_elevated() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# utm.py - Privilege enforcement
if not self.is_elevated:
    self._log({"event": "remediation_skipped", "reason": "insufficient_privileges"})
    return
```

### Residual Risk
- **Severity**: CRITICAL
- **Likelihood**: MEDIUM (requires process compromise)
- **Impact**: System compromise

### NIST 800-53 Controls
- **AC-2**: Account Management
- **AC-3**: Access Control Enforcement
- **IA-2**: Authentication

### Mitigation Enhancement Required ✅
```python
# Privilege separation + capability restriction
class IsolatedExecutor:
    """Execute commands in restricted environment"""
    
    def __init__(self, container_image: str = "python:3.11-slim"):
        self.container_image = container_image
        self.capabilities_drop = [
            "NET_RAW",      # Can't create raw sockets
            "SYS_ADMIN",    # Can't use unshare/namespace
            "CHOWN",        # Can't change file ownership
            "DAC_OVERRIDE", # Can't bypass permission checks
            "SETUID",       # Can't setuid
            "SETGID",       # Can't setgid
        ]
    
    def run_isolated(self, command: str) -> subprocess.CompletedProcess:
        """Execute command in container with dropped capabilities"""
        
        # Use Docker or Podman for isolation
        docker_cmd = [
            "docker", "run", "--rm",
            "--user", "1000:1000",  # Non-root
            "--network", "none",     # No network
            "--cap-drop", "ALL",     # Drop all capabilities
            *[f"--cap-add={cap}" for cap in self._safe_caps()],
            "--tmpfs", "/tmp:noexec,nosuid,nodev",  # Restrictive /tmp
            "--read-only",           # Read-only root filesystem
            "-v", f"{self.safe_volume}:/work:rw",   # Only allow /work
            self.container_image,
            "python", "-c", command
        ]
        
        return subprocess.run(docker_cmd, capture_output=True, timeout=30)
    
    def _safe_caps(self) -> List[str]:
        """Minimal capabilities needed"""
        return [
            "NET_BIND_SERVICE",  # Bind to ports (if needed)
            "CHOWN",             # Change owner in container
        ]
```

---

## Threat 5: Supply Chain Compromise (Dependency Injection)

### Attack Vector
Compromised dependency (requests, PyYAML, cryptography) injects malicious code.

### STRIDE Category
- **Tampering**: Code injection via dependencies
- **Elevation of Privilege**: Arbitrary code execution

### Threat Chain (MITRE ATT&CK)
```
T1195 (Supply Chain Compromise)
  └─ T1195.001 (Compromise Software Dependencies and Development Tools)
      └─ T1566 (Phishing)
```

### Current Mitigations ✅
```
requirements.txt:
requests==2.28.0        # Pinned version
PyYAML==6.0             # Pinned version
cryptography==40.0      # Pinned version
```

### Residual Risk
- **Severity**: CRITICAL
- **Likelihood**: LOW (requires compromised PyPI package)
- **Impact**: Complete system compromise

### NIST 800-53 Controls
- **SA-3**: System Development Life Cycle
- **SA-4**: Acquisition Process
- **SA-9**: External Information System Services

### Mitigation Enhancement Required ✅
```python
# Verify dependency integrity
class DependencySigVerifier:
    def __init__(self):
        # PEP 740: Trusted publishing with OIDC
        # Or use Software Bill of Materials (SBOM)
        self.sbom = self._load_sbom()
    
    def _load_sbom(self) -> Dict:
        """Load SBOM generated by generate_sbom.py"""
        with open('sbom.json', 'r') as f:
            return json.load(f)
    
    def verify_dependencies(self) -> Tuple[bool, List[str]]:
        """Verify all imported packages match SBOM"""
        suspicious = []
        
        for component in self.sbom.get('components', []):
            package_name = component.get('name')
            version = component.get('version')
            purl = component.get('purl')
            
            # 1. Check if package is in requirements.txt
            # 2. Verify version matches
            # 3. (Optional) Download and verify hash against PyPI
            
            # Example hash verification:
            pypi_hash = self._get_pypi_hash(package_name, version)
            if pypi_hash != component.get('hashes', [{}])[0].get('value'):
                suspicious.append(f"{package_name}=={version}")
        
        return len(suspicious) == 0, suspicious
    
    def _get_pypi_hash(self, name: str, version: str) -> str:
        """Fetch expected hash from PyPI (or pre-computed list)"""
        # In production: verify via PyPI API or signed hash list
        pass
```

---

## Threat 6: Network-based Attacks (TI Feed Poisoning)

### Attack Vector
Attacker compromises threat feed source (EmergingThreats, TorExitNodes) → injects false IPs.

### STRIDE Category
- **Tampering**: Data corruption
- **Information Disclosure**: False positives leak network topology

### Threat Chain (MITRE ATT&CK)
```
T1583 (Acquire Infrastructure)
  └─ T1583.004 (Acquire Infrastructure - Server)
      └─ T1087 (Account Discovery)
```

### Current Mitigations ✅
```python
# utm_feed.py - TLS verification
requests.get(url, verify=True)  # HTTPS certificate validation

# utm.py - IP validation
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
```

### Residual Risk
- **Severity**: MEDIUM
- **Likelihood**: MEDIUM (requires MITM or feed compromise)
- **Impact**: False alerts, DoS against monitored IPs

### NIST 800-53 Controls
- **SC-7**: Boundary Protection
- **SC-8**: Transmission Confidentiality and Integrity
- **SI-4**: Information System Monitoring

### Mitigation Enhancement Required ✅
```python
# Verify feed authenticity with GPG signatures
class SignedThreatFeed:
    def __init__(self, feed_url: str, gpg_key_id: str):
        self.feed_url = feed_url
        self.gpg_key_id = gpg_key_id
        self.gpg = gnupg.GPG()
    
    def fetch_and_verify(self) -> List[str]:
        """Fetch feed and verify GPG signature"""
        
        # 1. Download feed
        response = requests.get(self.feed_url, verify=True)
        feed_data = response.text
        
        # 2. Download signature
        sig_response = requests.get(f"{self.feed_url}.asc", verify=True)
        signature = sig_response.text
        
        # 3. Verify signature
        verified = self.gpg.verify(signature, feed_data)
        if not verified.valid:
            raise IntegrityError(f"Feed signature invalid: {self.feed_url}")
        
        # 4. Parse feed
        ips = []
        for line in feed_data.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                ips.append(line)
        
        return ips
```

---

## Summary Table

| Threat | STRIDE | MITRE ATT&CK | Current Control | Enhancement | NIST 800-53 |
|--------|--------|---|---|---|---|
| Cmd Injection | Tampering, Elevation | T1059, T1027 | SafeExecutor whitelist | Command signing | AC-3, SI-10 |
| Registry Tampering | Tampering, Elevation | T1547, T1140 | Ed25519 signature | Hash-chain integrity | CA-7, CM-3, SI-7 |
| Log Tampering | Tampering, Repudiation | T1070, T1562 | HMAC-SHA256 | Chained event integrity | AU-3, AU-9 |
| Privilege Escalation | Elevation | T1134, T1547 | Privilege check | Container isolation | AC-2, AC-3, IA-2 |
| Supply Chain | Tampering, Elevation | T1195, T1566 | Pinned versions | GPG verification of SBOM | SA-3, SA-4, SA-9 |
| TI Poisoning | Tampering, Disclosure | T1583, T1087 | TLS verification | GPG-signed feeds | SC-7, SC-8, SI-4 |

---

## Risk Acceptance & Residual Risk

### Critical Vulnerabilities (Require Immediate Enhancement)
- Privilege escalation (requires container isolation)
- Registry tampering (requires hash-chaining)
- Supply chain (requires SBOM verification)

### Medium Vulnerabilities (Should Be Enhanced)
- Command injection (should add command signing)
- Log tampering (should add event chaining)
- TI poisoning (should add feed signing)

### Monitoring & Detection
- Enable Windows Event Log 4688 (process execution)
- Monitor registry.yaml access (File Integrity Monitoring)
- Alert on HMAC verification failures
- Alert on invalid TI feed IPs

---

## Incident Response Procedures

### Scenario 1: Log Tampering Detected
```
1. Stop orchestrator immediately
2. Verify integrity of all logs: chained_audit_log.verify_integrity()
3. Identify tampering range (sequence numbers)
4. Notify security team
5. Preserve logs as forensic evidence
6. Review actions taken during tampered period
7. Assume compromise during that window
```

### Scenario 2: Registry Policy Changed
```
1. Verify Ed25519 signature of registry.yaml
2. If invalid signature:
   - Kill orchestrator
   - Alert: "CRITICAL: Unauthorized policy change"
3. If valid signature but unexpected change:
   - Review change approval logs (CM-3)
   - Notify change management
4. Rollback to previous signed version
```

### Scenario 3: Privilege Escalation Detected
```
1. Migrate to container-based execution (IsolatedExecutor)
2. Revoke orchestrator's admin/sudo privileges
3. Require MFA for elevated operations
4. Review all actions taken while elevated
5. Audit other systems for similar compromise
```

---

**Version**: 1.0
**Last Updated**: February 13, 2026
**Classification**: Internal Use / Security Team
