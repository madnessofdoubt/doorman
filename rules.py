"""Host matching shared by the browser addon and the strict proxy."""

from pathlib import Path


def load_host_list(path: Path) -> set[str]:
    """Lowercased hostnames from one-per-line file, '#' starts a comment."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()

    hosts = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip().lower().rstrip(".")
        if entry:
            hosts.add(entry)
    return hosts


def matches(host: str, entries: set[str]) -> bool:
    """True if host is an entry, or a subdomain of one."""
    if not host or not entries:
        return False
    host = host.lower().rstrip(".")
    return any(host == e or host.endswith("." + e) for e in entries)
