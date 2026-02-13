import subprocess
import shlex
from typing import List, Set, Union
import os

ALLOWED_BINARIES: Set[str] = {
    "powershell.exe",
    "net.exe",
    "reg.exe",
    "systemctl",
    "iptables",
    "auditctl",
    "python.exe",
}


def is_valid_input(s: str) -> bool:
    """Reject inputs containing shell metacharacters or excessively long content."""
    if not isinstance(s, str):
        return False
    if len(s) == 0 or len(s) > 1024:
        return False
    # Disallow common command-chaining characters
    if any(c in s for c in (';', '|', '&', '$', '`', '>', '<')):
        return False
    return True


def sanitize_to_args(cmd: Union[str, List[str]]) -> List[str]:
    """Return a list of args for subprocess.run after basic validation.

    Raises ValueError on invalid input.
    """
    if isinstance(cmd, list):
        args = cmd
    else:
        if not is_valid_input(cmd):
            raise ValueError("Command contains disallowed characters or is malformed")
        args = shlex.split(cmd)

    if not args:
        raise ValueError("Empty command")

    return args


class SafeExecutor:
    """Executes commands without shell=True and enforces an allowlist of binaries.

    Usage:
        se = SafeExecutor()
        se.run(['python', '-c', "print('ok')"])
    """

    def __init__(self, allowed_binaries: Set[str] = ALLOWED_BINARIES):
        self.allowed = {b.lower() for b in allowed_binaries}

    def run(self, cmd: Union[str, List[str]]) -> subprocess.CompletedProcess:
        args = sanitize_to_args(cmd)
        exe = os.path.basename(args[0]).lower()
        if exe not in self.allowed:
            raise RuntimeError(f"Binary '{exe}' not allowed by policy")

        # Use subprocess.run without shell for safety; capture output for tests/logging
        proc = subprocess.run(args, check=True, capture_output=True, text=True, shell=False)
        return proc
