import os
import sys
import pytest
from utm_safe import is_valid_input, SafeExecutor


def test_is_valid_input_rejects():
    assert not is_valid_input("echo hello; rm -rf /")


def test_is_valid_input_accepts():
    assert is_valid_input("ping")


def test_run_disallowed_binary():
    se = SafeExecutor(allowed_binaries={"allowed.exe"})
    with pytest.raises(RuntimeError):
        se.run([sys.executable, "-c", "print('x')"])


def test_run_allowed_python():
    exe = os.path.basename(sys.executable).lower()
    se = SafeExecutor(allowed_binaries={exe})
    proc = se.run([sys.executable, "-c", "print('ok')"])
    assert proc.stdout.strip() == "ok"
