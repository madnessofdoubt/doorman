from pathlib import Path
from urllib.parse import urlparse
from mitmproxy import http, ctx

BASE_DIR = Path(__file__).parent
ALLOWLIST_FILE = BASE_DIR / "allowlist.txt"

BLOCKED_HOSTS = {
    "example.com",
}

MEDIA_PREFIXES = ("image/", "video/")
EXTRA_MEDIA_TYPES = {
    "application/vnd.apple.mpegurl",
    "application/x-mpegurl",
    "application/dash+xml",
    "application/vnd.yt-ump",
    "application/vnd.ms-sstr+xml",
    "application/octet-stream",
}


def allowlist() -> set[str]:
    try:
        text = ALLOWLIST_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()

    result = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip().lower().rstrip(".")
        if entry:
            result.add(entry)
    return result


def matches(host: str, entries: set[str]) -> bool:
    if not host or not entries:
        return False
    host = host.lower().rstrip(".")
    return any(host == e or host.endswith("." + e) for e in entries)


def referer_host(flow: http.HTTPFlow) -> str:
    referer = flow.request.headers.get("referer", "")
    if not referer:
        return ""
    try:
        return (urlparse(referer).hostname or "").lower()
    except ValueError:
        return ""


def is_media(content_type: str) -> bool:
    mime = content_type.split(";", 1)[0].strip().lower()
    return mime.startswith(MEDIA_PREFIXES) or mime in EXTRA_MEDIA_TYPES


def is_allowed(flow: http.HTTPFlow) -> bool:
    allowed = allowlist()
    return matches(flow.request.pretty_host, allowed) or matches(referer_host(flow), allowed)


_config_checked = False


def announce_config() -> None:
    global _config_checked
    if _config_checked:
        return
    _config_checked = True

    if not ALLOWLIST_FILE.exists():
        ctx.log.warn(f"allowlist NOT FOUND: {ALLOWLIST_FILE} - nothing is exempt")

    ctx.log.info(
        f"config: {len(BLOCKED_HOSTS)} blocked hosts, "
        f"{len(allowlist())} allowlisted hosts"
    )


def request(flow: http.HTTPFlow) -> None:
    announce_config()

    # Allowlisted host (or allowlisted page) -> don't filter this flow at all.
    if is_allowed(flow):
        return

    host = flow.request.pretty_host.lower()

    if host in BLOCKED_HOSTS:
        ctx.log.info(f"Blocked host: {host}")
        flow.response = http.Response.make(
            403,
            b"Blocked by internet blocker\n",
            {"Content-Type": "text/plain; charset=utf-8"},
        )


def response(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return

    # Same exemption check as the request hook - no shared state needed.
    if is_allowed(flow):
        return

    content_type = flow.response.headers.get("content-type", "")
    if not is_media(content_type):
        return

    ctx.log.info(f"Blocked media: {flow.request.pretty_url} ({content_type})")
    flow.response.status_code = 403
    flow.response.content = b"Media blocked\n"
    flow.response.headers["content-type"] = "text/plain; charset=utf-8"
    flow.response.headers.pop("content-encoding", None)
