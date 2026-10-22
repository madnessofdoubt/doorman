from email.message import Message
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import ctx, http

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
}

DOWNLOAD_TYPES = {
    "application/octet-stream",
    "application/x-bittorrent",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/zstd",
    "application/x-apple-diskimage",
    "application/x-iso9660-image",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
    "application/x-msi",
    "application/x-ms-installer",
    "application/vnd.android.package-archive",
    "application/x-deb",
    "application/x-rpm",
    "application/x-executable",
    "application/x-sharedlib",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/epub+zip",
    "application/rtf",
}

DOWNLOAD_EXTENSIONS = {
    ".torrent", ".iso", ".img", ".dmg",
    ".exe", ".msi", ".apk", ".deb", ".rpm", ".appimage",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf", ".epub", ".pdf",
    ".tar.zst", ".tar.zst.sig", ".iso.torrent",
}

# Empty allowlists must use set(); {} otherwise.
ALLOWED_DOWNLOAD_TYPES: set[str] = set()
ALLOWED_DOWNLOAD_EXTENSIONS: set[str] = {".tar.zst", ".appimage", ".crx"}

# Consumed by the page even when Google labels it attachment.
INLINE_TYPES: set[str] = {
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/html",
    "application/xml",
    "text/xml",
    "application/x-protobuf",
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


def is_allowed(flow: http.HTTPFlow) -> bool:
    allowed = allowlist()
    return matches(flow.request.pretty_host, allowed) or matches(referer_host(flow), allowed)


def mime_of(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


def is_media(content_type: str) -> bool:
    mime = mime_of(content_type)
    return mime.startswith(MEDIA_PREFIXES) or mime in EXTRA_MEDIA_TYPES

def suffixes_of_name(name: str) -> set[str]:
    """All trailing extensions: a.tar.zst.sig -> .sig, .zst.sig, .tar.zst.sig."""
    parts = Path(name).name.lower().split(".")
    return {"." + ".".join(parts[i:]) for i in range(1, len(parts))}


def disposition_filename(content_disposition: str) -> str:
    """Filename from a Content-Disposition header, if there is one."""
    if not content_disposition:
        return ""
    message = Message()
    message["content-disposition"] = content_disposition
    return message.get_filename() or ""


def names_of(flow: http.HTTPFlow, content_disposition: str) -> list[str]:
    """Lowercased basenames from the URL path and the offered filename."""
    names = [Path(urlparse(flow.request.pretty_url).path).name.lower()]
    filename = disposition_filename(content_disposition)
    if filename:
        names.append(Path(filename).name.lower())
    return names


def allowed_extension(names: list[str]) -> bool:
    """True if an allowed extension is the final extension of any name."""
    return any(suffixes_of_name(name) & ALLOWED_DOWNLOAD_EXTENSIONS for name in names)


def blocked_extension(names: list[str], extensions: set[str]) -> str | None:
    """Longest blocked extension found at a dot boundary in any name.

    This also catches derived files: .tar.zst matches archive.tar.zst.sig.
    """
    matches = [
        ext
        for name in names
        for ext in extensions
        if name.endswith(ext) or (ext + ".") in name
    ]
    return max(matches, key=lambda ext: (len(ext), ext)) if matches else None


def is_download_url(url: str) -> str | None:
    """Extension-based check - works before the server is contacted."""
    name = Path(urlparse(url).path).name.lower()
    if allowed_extension([name]):
        return None
    return blocked_extension([name], DOWNLOAD_EXTENSIONS)


def is_allowed_download(flow: http.HTTPFlow) -> bool:
    """True if the response is a download the allowlists exempt."""
    resp = flow.response
    if resp is None:
        return False

    if mime_of(resp.headers.get("content-type", "")) in ALLOWED_DOWNLOAD_TYPES:
        return True

    disposition = resp.headers.get("content-disposition", "").lower()
    return allowed_extension(names_of(flow, disposition))


def download_reason(flow: http.HTTPFlow) -> str | None:
    resp = flow.response
    if resp is None:
        return None

    mime = mime_of(resp.headers.get("content-type", ""))
    disposition = resp.headers.get("content-disposition", "").lower()
    names = names_of(flow, disposition)

    if mime in ALLOWED_DOWNLOAD_TYPES:
        return None
    if allowed_extension(names):
        return None

    if disposition.startswith("attachment") and mime not in INLINE_TYPES:
        return "content-disposition"
    if mime in DOWNLOAD_TYPES:
        return f"type {mime}"

    blocked = blocked_extension(names, DOWNLOAD_EXTENSIONS)
    if blocked:
        return f"extension {blocked}, type {mime or 'none'}"
    return None


def block_body(flow: http.HTTPFlow, message: bytes) -> None:
    """Replace the response and drop the upstream body as it arrives."""
    flow.response = http.Response.make(
        403, message, {"Content-Type": "text/plain; charset=utf-8"}
    )

    delivered = False

    def deliver_once(chunk: bytes) -> bytes:
        nonlocal delivered
        if delivered:
            return b""
        delivered = True
        return message

    flow.response.stream = deliver_once


# --- config log ----------------------------------------------------------

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
        f"{len(allowlist())} allowlisted hosts, "
        f"{len(DOWNLOAD_TYPES)} download types, "
        f"{len(DOWNLOAD_EXTENSIONS)} download extensions, "
        f"{len(ALLOWED_DOWNLOAD_TYPES)} allowed types, "
        f"{len(ALLOWED_DOWNLOAD_EXTENSIONS)} allowed extensions"
    )


# --- hooks ---------------------------------------------------------------

def request(flow: http.HTTPFlow) -> None:
    announce_config()

    if is_allowed(flow):
        return

    if not ALLOWED_DOWNLOAD_TYPES:
        suffix = is_download_url(flow.request.pretty_url)
        if suffix:
            ctx.log.info(f"Blocked download link: {flow.request.pretty_url} ({suffix})")
            flow.response = http.Response.make(
                403,
                b"Downloads are blocked by internet blocker\n",
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            return

    host = flow.request.pretty_host.lower()

    if host in BLOCKED_HOSTS:
        ctx.log.info(f"Blocked host: {host}")
        flow.response = http.Response.make(
            403,
            b"Blocked by internet blocker\n",
            {"Content-Type": "text/plain; charset=utf-8"},
        )


def responseheaders(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return

    if is_allowed(flow):
        # Allowlisted sites are exempt; stream so large files are not buffered.
        flow.response.stream = True
        return

    if is_allowed_download(flow):
        # Allowed files would otherwise be buffered in memory in full.
        flow.response.stream = True
        return

    reason = download_reason(flow)
    if reason is None:
        return

    ctx.log.info(f"Blocked download: {flow.request.pretty_url} ({reason})")
    block_body(flow, b"Downloads are blocked by internet blocker\n")


def response(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return

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
