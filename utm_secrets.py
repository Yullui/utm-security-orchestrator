import os
from typing import Optional


def get_secret(name: str) -> Optional[str]:
    """Retrieve secret from environment. Placeholder for Vault integration.

    Looks for `UTM_SECRET_<NAME>` env var first.
    """
    envname = f"UTM_SECRET_{name.upper()}"
    return os.environ.get(envname)
