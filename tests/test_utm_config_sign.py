import tempfile
import pytest

from utm_config_sign import sign_config, verify_config


def test_sign_and_verify():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception:
        pytest.skip("cryptography not installed")

    # generate keypair
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    fd1, priv_path = tempfile.mkstemp()
    fd2, pub_path = tempfile.mkstemp()
    fd3, cfg_path = tempfile.mkstemp()
    fd4, sig_path = tempfile.mkstemp()
    try:
        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        with open(cfg_path, "wb") as f:
            f.write(b"policy: allow")

        sign_config(cfg_path, priv_path, sig_path)
        assert verify_config(cfg_path, sig_path, pub_path) is True
        # tamper config
        with open(cfg_path, "ab") as f:
            f.write(b"tamper")
        assert verify_config(cfg_path, sig_path, pub_path) is False
    finally:
        import os
        os.close(fd1); os.close(fd2); os.close(fd3); os.close(fd4)
        os.remove(priv_path); os.remove(pub_path); os.remove(cfg_path); os.remove(sig_path)
