from __future__ import annotations

import socket
from typing import Dict, Optional


def parse_os_release(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def get_os_release(read_file) -> Dict[str, str]:
    content = read_file("/etc/os-release")
    if not content:
        return {}
    return parse_os_release(content)


def get_primary_ip(run_cmd) -> Optional[str]:
    try:
        completed = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    except Exception:
        return None

    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        addr = parts[3].split("/")[0]
        if addr:
            return addr
    return None


def get_hostname() -> str:
    return socket.gethostname()


def get_fqdn() -> str:
    return socket.getfqdn()
