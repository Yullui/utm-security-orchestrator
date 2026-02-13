import json
from typing import List

def generate_sbom(requirements_path: str, out_path: str) -> None:
    """Simple SBOM generator: parse requirements.txt and emit JSON list of packages."""
    pkgs: List[dict] = []
    with open(requirements_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
            else:
                name, ver = line, ""
            pkgs.append({"name": name, "version": ver})

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"sbom": pkgs}, f, indent=2)
