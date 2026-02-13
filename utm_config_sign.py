from typing import Optional


def _ensure_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except Exception as e:
        raise RuntimeError("cryptography package is required for config signing") from e


def load_private_key(path: str):
    Ed25519PrivateKey, _, serialization = _ensure_crypto()
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    _, Ed25519PublicKey, serialization = _ensure_crypto()
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_config(config_path: str, privkey_path: str, sig_out: str) -> None:
    key = load_private_key(privkey_path)
    with open(config_path, "rb") as f:
        data = f.read()
    sig = key.sign(data)
    with open(sig_out, "wb") as f:
        f.write(sig)


def verify_config(config_path: str, sig_path: str, pubkey_path: str) -> bool:
    pub = load_public_key(pubkey_path)
    with open(config_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    try:
        pub.verify(sig, data)
        return True
    except Exception:
        return False
