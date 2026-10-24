"""Host matching shared by the browser addon and the strict proxy."""

from pathlib import Path
from urllib.parse import urlparse


def normalize_host(value: str) -> str:
    """Bare lowercased hostname from a list entry or request target.

    Accepts a scheme and path ("https://Example.COM:443/x"), a bare host:port,
    a bracketed IPv6 literal, a leading "*." and a trailing dot. Returns ""
    when nothing usable is left.
    """
    value = (value or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if "://" in value:
        try:
            value = urlparse(value).hostname or ""
        except ValueError:
            return ""
    elif value.startswith("["):
        end = value.find("]")
        if end != -1:
            value = value[1:end]
    elif value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host
    value = value.rstrip(".")
    return value[2:] if value.startswith("*.") else value


def load_host_list(path: Path) -> set[str]:
    """Lowercased hostnames from one-per-line file, '#' starts a comment.

    An unreadable file is an empty policy, which denies everything.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()

    hosts = set()
    for line in text.splitlines():
        entry = normalize_host(line.split("#", 1)[0])
        if entry:
            hosts.add(entry)
    return hosts


def matches(host: str, entries: set[str]) -> bool:
    """True if host is an entry, or a subdomain of one."""
    if not host or not entries:
        return False
    host = normalize_host(host)
    if not host:
        return False
    return any(host == e or host.endswith("." + e) for e in entries)


def host_key(host: str) -> str:
    """Normalized hostname used in logs and for default-order decisions."""
    return normalize_host(host)


def allowed(host: str, allow: set[str], default: str = "deny") -> bool:
    """Allowlist first, then `default`.

    `default` is the policy for hosts not on the allowlist: "deny" is
    allowlist-only, "allow" allows everything."""
    host = host_key(host)
    if not host:
        return False
    if allow and matches(host, allow):
        return True
    return default == "allow"
