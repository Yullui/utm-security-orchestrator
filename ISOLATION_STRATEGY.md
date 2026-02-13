# Isolation Strategy: Container-Based Execution

UTM Security Orchestrator moves from privilege-based security to **capability-based, container-isolated execution**.

---

## Part A: Current State vs. Target State

### Current (Vulnerable)
```
┌─────────────────────────────────────────┐
│  UTM Security Orchestrator (pid: 1234)  │
│  Running as: Administrator / root       │
│                                         │
│  ┌─────────────────────────────────────┤
│  │ SafeExecutor.run('ipconfig')         │
│  │ → subprocess.run(['ipconfig'])       │
│  │ → Inherits parent process UID/GID   │
│  │ → Full filesystem access            │
│  │ → Full network access               │
│  │ → Can start any process             │
│  └─────────────────────────────────────┤
└─────────────────────────────────────────┘
```

**Risks**:
- ❌ If SafeExecutor is compromised → full system compromise
- ❌ Command whitelist can be bypassed via symlinks
- ❌ Filesystem access is unrestricted
- ❌ Network access is unrestricted

### Target (Hardened)
```
┌─────────────────────────────────────────────────────────┐
│  UTM Security Orchestrator (pid: 1234)                  │
│  Running as: Administrator / root (orchestrator layer)  │
│                                                         │
│  ┌──────────────────────────────────────────────────────┤
│  │ IsolatedExecutor.run_isolated('ipconfig')            │
│  │                                                      │
│  │ docker run --rm \                                    │
│  │   --user 1000:1000           ← Non-root UID/GID    │
│  │   --cap-drop=ALL             ← Drop all capabilities│
│  │   --cap-add=NETnetwork       ← Only if needed      │
│  │   --network=none             ← No network access   │
│  │   --read-only /              ← Immutable root FS   │
│  │   -v /work:/work:rw          ← Only /work writable │
│  │   --tmpfs /tmp               ← Ephemeral /tmp      │
│  │   python:3.11-slim \                               │
│  │   python -c "ipconfig"       ← Executed inside    │
│  │                                                      │
│  └──────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────┘
```

**Benefits**:
- ✅ Compromised workload cannot escape container
- ✅ Unable to modify filesystem (immutable root)
- ✅ No network access unless explicitly allowed
- ✅ Cannot escalate privileges (no SETUID capability)
- ✅ Cannot access host resources (namespace isolation)

---

## Part B: Linux Capabilities Restriction

### What are Linux Capabilities?

Linux capabilities are units of privilege traditionally held by the root user. Instead of "all or nothing" (root), capabilities allow fine-grained privilege.

**Examples**:
- `CAP_NET_RAW`: Create raw sockets (for crafted packets)
- `CAP_SYS_ADMIN`: Unshare namespaces, mount filesystems
- `CAP_SETUID`: Change effective UID (privilege escalation)
- `CAP_CHOWN`: Change file ownership
- `CAP_DAC_OVERRIDE`: Bypass file permission checks

### UTM Capability Strategy

#### Safe Capabilities (Allowed)
```python
SAFE_CAPS = [
    "CAP_NET_BIND_SERVICE",   # Bind to ports < 1024 (if needed)
    "CAP_SETGID",              # Change group (for artifacts collection)
]
```

#### Dangerous Capabilities (Dropped)
```python
DROP_CAPS = [
    "CAP_NET_RAW",        # ❌ Can create raw sockets (craft packets)
    "CAP_SYS_ADMIN",      # ❌ Can unshare namespaces (escape)
    "CAP_SETUID",         # ❌ Can setuid to other users (escalate)
    "CAP_SETGID",         # ❌ Can setgid to other groups (escalate)
    "CAP_CHOWN",          # ❌ Can change file ownership
    "CAP_DAC_OVERRIDE",   # ❌ Can bypass permission checks
    "CAP_DAC_READ_SEARCH",# ❌ Can read any file
    "CAP_SYS_PTRACE",     # ❌ Can trace any process
    "CAP_KILL",           # ❌ Can kill any process
]
```

### Implementation

```python
# /usr/bin/docker-entrypoint.sh
#!/bin/bash
set -e

# Drop ALL capabilities, then add only safe ones
exec docker run --rm \
    --user 1000:1000 \
    --cap-drop=ALL \
    --cap-add=CAP_NET_BIND_SERVICE \
    --cap-add=CAP_SETGID \
    --security-opt=no-new-privileges:true \
    --tmpfs /tmp:noexec,nosuid,nodev,size=100m \
    --tmpfs /run:noexec,nosuid,nodev,size=100m \
    --read-only / \
    -v /work:/work:rw \
    python:3.11-slim \
    "$@"
```

---

## Part C: Container Isolation Implementation

### IsolatedExecutor Class

```python
# utm_isolation.py
import subprocess
import json
from typing import List, Optional
from enums import SecurityLevel

class IsolatedExecutor:
    """Execute commands in isolated Docker containers"""
    
    def __init__(self, 
                 container_image: str = "python:3.11-slim",
                 security_level: SecurityLevel = SecurityLevel.HIGH):
        self.container_image = container_image
        self.security_level = security_level
        self.safe_caps = ["NET_BIND_SERVICE", "SETGID"]
        self.drop_all_caps = True
    
    def run_isolated(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Execute command in isolated container.
        
        Args:
            command: Command to execute
            timeout: Max execution time (seconds)
        
        Returns:
            subprocess.CompletedProcess with stdout/stderr
        
        Raises:
            subprocess.TimeoutExpired: If timeout exceeded
            subprocess.CalledProcessError: If command fails
        """
        
        # Build Docker command with security hardening
        docker_cmd = self._build_secure_docker_cmd(command)
        
        # Execute with timeout
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired as e:
            # Kill container after timeout
            subprocess.run(["docker", "kill", e.cmd[-1]], capture_output=True)
            raise
    
    def _build_secure_docker_cmd(self, command: str) -> List[str]:
        """Build Docker command with defense-in-depth hardening"""
        
        docker_cmd = [
            "docker", "run", "--rm",
            
            # 1. User/Group isolation
            "--user", "1000:1000",      # Non-root UID/GID
            
            # 2. Capability restrictions
            "--cap-drop=ALL",           # Drop all capabilities
            *[f"--cap-add={cap}" for cap in self.safe_caps],
            "--security-opt", "no-new-privileges:true",
            
            # 3. Network isolation
            "--network", "none",        # No network access
            
            # 4. Filesystem isolation
            "--read-only",              # Read-only root filesystem
            "-v", f"{self.safe_volume}:/work:rw",  # Only /work writable
            
            # 5. Memory/CPU limits
            "--memory", "512m",         # Max 512 MB RAM
            "--cpus", "1.0",            # Max 1 CPU core
            
            # 6. Ephemeral filesystems
            "--tmpfs", "/tmp:noexec,nosuid,nodev,size=100m",
            "--tmpfs", "/run:noexec,nosuid,nodev,size=50m",
            
            # 7. Logging
            "--log-driver", "json-file",
            "--log-opt", "max-size=10m",
            
            # 8. Container image
            self.container_image,
            
            # 9. Command to execute
            "bash", "-c", command
        ]
        
        return docker_cmd
    
    @property
    def safe_volume(self) -> str:
        """Return safe volume mount path"""
        return "/tmp/utm_execution"
    
    def cleanup(self) -> None:
        """Remove orphaned containers"""
        subprocess.run(
            ["docker", "container", "prune", "-f"],
            capture_output=True
        )
```

### Integration with utm.py

```python
# utm.py - Updated apply_system_remediation()
def apply_system_remediation(self, commands: List[Dict]) -> None:
    """Execute remediation in isolated containers"""
    
    # Use IsolatedExecutor instead of SafeExecutor
    executor = IsolatedExecutor(security_level=SecurityLevel.HIGH)
    
    for cmd in commands:
        command = cmd.get('command') or cmd.get('commmand')
        if not command:
            continue
        
        try:
            # Execute in isolated container
            proc = executor.run_isolated(command, timeout=30)
            
            self._log({
                "event": "remediation_executed",
                "cmd": command,
                "isolated": True,
                "container": executor.container_image,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode
            })
        except subprocess.TimeoutExpired:
            self._log({
                "event": "remediation_timeout",
                "cmd": command,
                "timeout_seconds": 30
            })
        except Exception as e:
            self._log({
                "event": "remediation_failed",
                "cmd": command,
                "error": str(e)
            })
```

---

## Part D: Escape Attack Scenarios & Mitigations

### Attack 1: Capability Abuse (CAP_SYS_ADMIN)

**Attack**: Attacker with `CAP_SYS_ADMIN` calls `unshare()` to escape namespace

```bash
# Inside compromised container (if SYS_ADMIN enabled)
$ unshare --uts --ipc --pid "/bin/bash"
# → Now in new namespace, can see host processes
```

**Mitigation**: ✅ Drop `CAP_SYS_ADMIN` (not in safe_caps)
```python
--cap-drop=ALL
# CAP_SYS_ADMIN not in SAFE_CAPS → Dropped
```

### Attack 2: Filesystem Escape (Mount)

**Attack**: Attacker with `CAP_SYS_ADMIN` mounts host filesystem

```bash
# Inside compromised container (if SYS_ADMIN enabled)
$ mount /host /mnt
# → Access to host filesystem
```

**Mitigation**: ✅ Drop `CAP_SYS_ADMIN` + read-only root FS
```python
--read-only /              # Can't modify root filesystem
--cap-drop SYS_ADMIN       # Can't use mount()
```

### Attack 3: Privilege Escalation (SETUID)

**Attack**: Attacker with `CAP_SETUID` executes setuid binary

```bash
# Inside container
$ /usr/bin/sudo /bin/bash
# → Escalated to root (if setuid binary exists)
```

**Mitigation**: ✅ Drop `CAP_SETUID` + run as non-root
```python
--cap-drop=ALL                # SETUID dropped
--user 1000:1000             # Running as UID 1000 (non-root)
--security-opt no-new-privileges:true  # Prevent setuid bit usage
```

### Attack 4: Network Breakout (RAW_SOCKET)

**Attack**: Attacker with `CAP_NET_RAW` creates raw socket to host

```bash
# Inside compromised container (if NET_RAW enabled)
$ python -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# → Can craft arbitrary packets to host
"
```

**Mitigation**: ✅ Drop `CAP_NET_RAW` + network isolation
```python
--network none             # No network access to host
--cap-drop CAP_NET_RAW    # Can't create raw sockets
```

### Attack 5: Information Leak (DAC_READ_SEARCH)

**Attack**: Read arbitrary files despite permissions

```bash
# Inside container (if DAC_READ_SEARCH enabled)
$ cat /etc/shadow
# → Read sensitive files without permission
```

**Mitigation**: ✅ Drop `CAP_DAC_READ_SEARCH` + volume mounts
```python
--cap-drop=ALL                   # DAC_READ_SEARCH dropped
-v /work:/work:rw              # Only /work readable/writable
```

---

## Part E: Kubernetes Deployment (Future)

For large-scale deployments, use Kubernetes Pod Security Policies:

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: utm-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  allowedCapabilities:
    - NET_BIND_SERVICE
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  runAsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  readOnlyRootFilesystem: true
  seLinux:
    rule: 'MustRunAs'
    seLinuxOptions:
      level: "s0:c123,c456"
```

---

## Part F: Testing Isolation

### Test 1: Verify Capabilities Are Dropped

```python
def test_dropped_capabilities():
    executor = IsolatedExecutor()
    
    # Try to use dropped capability
    result = executor.run_isolated("""
        import ctypes
        try:
            # This requires CAP_SYS_ADMIN
            ctypes.CDLL('libc.so.6').unshare(0x04000000)
            print("FAIL: unshare succeeded (SYS_ADMIN not dropped)")
        except OSError as e:
            print(f"PASS: unshare failed: {e}")
    """)
    
    assert "PASS" in result.stdout
```

### Test 2: Verify Read-Only Root

```python
def test_readonly_root_fs():
    executor = IsolatedExecutor()
    
    result = executor.run_isolated("""
        try:
            with open('/etc/passwd.corrupted', 'w') as f:
                f.write('corrupted')
            print("FAIL: Write succeeded (root not read-only)")
        except (IOError, OSError) as e:
            print(f"PASS: Write failed: {e}")
    """)
    
    assert "PASS" in result.stdout
```

### Test 3: Verify No Network Access

```python
def test_network_isolation():
    executor = IsolatedExecutor()
    
    result = executor.run_isolated("""
        import socket
        import sys
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('8.8.8.8', 53))
            print("FAIL: Network connection succeeded")
            sys.exit(1)
        except (socket.error, OSError) as e:
            print(f"PASS: Network blocked: {e}")
    """, timeout=5)
    
    assert "PASS" in result.stdout
```

---

## Part G: Performance & Tradeoffs

| Aspect | Raw Subprocess | Container Isolation |
|--------|---|---|
| **Startup Time** | 10 ms | 500 ms (container overhead) |
| **Security** | Low ❌ | High ✅ |
| **Complexity** | Simple | Moderate |
| **Dependencies** | Python | Docker/Podman + Python |
| **Suitable For** | Development | Production |

**Recommendation**: 
- Development: Use SafeExecutor (faster)
- Production: Use IsolatedExecutor (secure)

---

## Part H: Rollout Strategy

### Phase 1: Development (Week 1)
- [ ] Implement IsolatedExecutor class
- [ ] Write capability tests
- [ ] Add to requirements.txt

### Phase 2: Testing (Week 2-3)
- [ ] Run isolation tests
- [ ] Benchmark performance
- [ ] Test with real registry.yaml commands

### Phase 3: Staging (Week 4)
- [ ] Deploy to staging environment
- [ ] Monitor performance
- [ ] Conduct security review

### Phase 4: Production (Month 2)
- [ ] Deploy to production
- [ ] Enable gradual rollout (10% → 50% → 100%)
- [ ] Monitor for any escapes or issues

---

## Summary

**Isolation Strategy transforms UTM from**:
- ❌ Privilege-based security (trust orchestrator is safe)

**To**:
- ✅ Capability-based security (containers are isolated)

This is the shift from **"scripted orchestrator"** to **"security control plane"**.

---

**Version**: 1.0
**Status**: Design Complete | Implementation Pending
**Target Deployment**: February 2026 (Phase 4)
