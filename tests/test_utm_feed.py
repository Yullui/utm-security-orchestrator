import hashlib
import pytest

import utm_feed


class DummyResp:
    def __init__(self, chunks: list, status_code=200):
        self._chunks = chunks
        self.status_code = status_code

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise Exception("Bad status")

    def iter_content(self, chunk_size=4096):
        for c in self._chunks:
            yield c


def test_extract_public_ips():
    txt = "Allowed: 8.8.8.8\nInternal: 10.0.0.1\nBad: 999.999.999.999"
    ips = utm_feed.extract_public_ips(txt)
    assert "8.8.8.8" in ips
    assert "10.0.0.1" not in ips


def test_fetch_feed_checksum_and_size(monkeypatch):
    chunks = [b"hello\n", b"world\n"]
    resp = DummyResp(chunks)

    def fake_get(url, timeout, verify, stream):
        assert verify is True
        return resp

    monkeypatch.setattr("requests.get", fake_get)

    # compute expected sha256
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    expected = h.hexdigest()

    out = utm_feed.fetch_feed("https://example.test/feed", expected_sha256=expected)
    assert "hello" in out and "world" in out


def test_fetch_feed_too_large(monkeypatch):
    # produce chunks that exceed MAX_FEED_BYTES
    big_chunk = b"A" * (utm_feed.MAX_FEED_BYTES // 2)
    chunks = [big_chunk, big_chunk, b"extra"]
    resp = DummyResp(chunks)

    def fake_get(url, timeout, verify, stream):
        return resp

    monkeypatch.setattr("requests.get", fake_get)

    with pytest.raises(ValueError):
        utm_feed.fetch_feed("https://example.test/feed")
