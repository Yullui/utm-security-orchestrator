import os
import tempfile
from utm_logging import log_event, verify_log


def test_logging_and_verification(monkeypatch):
    monkeypatch.setenv("UTM_LOG_KEY", "testkey123")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        log_event(path, {"msg": "first", "level": "info"})
        log_event(path, {"msg": "second", "level": "warn"})
        assert verify_log(path) is True
        # tamper a line
        with open(path, "r+", encoding="utf-8") as f:
            data = f.read()
            f.seek(0)
            f.write(data.replace("second", "tampered"))
        assert verify_log(path) is False
    finally:
        os.remove(path)
