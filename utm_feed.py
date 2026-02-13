import requests
import hashlib
import re
import ipaddress
from typing import Set, Optional

# Maximum allowed feed size in bytes (protects against huge responses)
MAX_FEED_BYTES = 1_000_000


def fetch_feed(url: str, expected_sha256: Optional[str] = None, timeout: int = 10) -> str:
    """Fetches a threat feed safely, enforces size limits and optional checksum.

    - Uses `verify=True` to enforce TLS verification.
    - Streams content, enforces `MAX_FEED_BYTES`.
    - Optionally verifies SHA256 checksum of raw bytes.
    """
    resp = requests.get(url, timeout=timeout, verify=True, stream=True)
    resp.raise_for_status()

    hasher = hashlib.sha256()
    parts = []
    total = 0
    for chunk in resp.iter_content(4096):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_FEED_BYTES:
            raise ValueError("Feed exceeded maximum allowed size")
        hasher.update(chunk)
        parts.append(chunk)

    data = b"".join(parts)
    if expected_sha256:
        if hasher.hexdigest() != expected_sha256:
            raise ValueError("Feed checksum mismatch")

    return data.decode("utf-8", errors="ignore")


def extract_public_ips(feed_text: str) -> Set[str]:
    """Extracts and returns deduplicated public IPv4 addresses from feed text."""
    tokens = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", feed_text)
    out = set()
    for t in tokens:
        try:
            ip = ipaddress.ip_address(t)
            if not ip.is_private:
                out.add(str(ip))
        except ValueError:
            continue
    return out
