import os
import json
import datetime
import psutil


def collect_artifacts(out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    artifacts = {}
    artifacts['timestamp'] = datetime.datetime.now(datetime.UTC).isoformat() + 'Z'
    artifacts['processes'] = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            artifacts['processes'].append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    artifacts['net_connections'] = []
    for c in psutil.net_connections(kind='inet'):
        try:
            artifacts['net_connections'].append({'pid': c.pid, 'laddr': c.laddr._asdict() if c.laddr else None, 'raddr': c.raddr._asdict() if c.raddr else None, 'status': c.status})
        except Exception:
            continue

    out_path = os.path.join(out_dir, 'artifacts.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(artifacts, f, indent=2)
    return out_path
