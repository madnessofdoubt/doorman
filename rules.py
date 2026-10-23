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
        if not entry:
            continue
        if entry.startswith("*."):
            entry = entry[2:]
        hosts.add(entry)
    return hosts


def matches(host: str, entries: set[str]) -> bool:
    """True if host is an entry, or a subdomain of one."""
    if not host or not entries:
        return False
    host = host.lower().rstrip(".")
    return any(host == e or host.endswith("." + e) for e in entries)


def host_key(host: str) -> str:
    """Normalized hostname used in logs and for default-order decisions."""
    return (host or "").lower().rstrip(".")


def allowed(host: str, allow: set[str], block: set[str], default: str = "deny") -> bool:
    """Blocklist wins, then the allowlist, then `default`.

    `default` is the policy for hosts on neither list: "deny" is
    allowlist-only, "allow" is blocklist-only. It applies even when the
    allowlist is non-empty; otherwise a populated allowlist would silently
    override default=allow."""
    host = host_key(host)
    if not host:
        return False
    if block and matches(host, block):
        return False
    if allow and matches(host, allow):
        return True
    return default == "allow"
