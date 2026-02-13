import os
import hmac
import json
import hashlib
from typing import Dict, Any

LOG_KEY_ENV = "UTM_LOG_KEY"


def _get_key() -> bytes:
    key = os.environ.get(LOG_KEY_ENV)
    if not key:
        raise RuntimeError(f"Missing log HMAC key: set env {LOG_KEY_ENV}")
    return key.encode("utf-8")


def log_event(path: str, event: Dict[str, Any]) -> None:
    """Append a JSON event with HMAC to `path` (append-only).

    Each line is a JSON object with an added `hmac` field computed over the
    canonical JSON bytes of the event (sorted keys).
    """
    key = _get_key()
    # canonicalize
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    record = {"event": event, "hmac": mac}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def verify_log(path: str) -> bool:
    """Verify each line's HMAC integrity. Returns True if all valid."""
    key = _get_key()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            event = rec.get("event")
            hmac_stored = rec.get("hmac")
            if event is None or hmac_stored is None:
                return False
            payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
            mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, hmac_stored):
                return False
    return True
