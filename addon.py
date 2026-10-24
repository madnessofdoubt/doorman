import os
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urlparse

from mitmproxy import ctx, http

BASE_DIR = Path(__file__).parent
CONFIG_DIR = Path(os.environ.get("DOORMAN_CONFIG_DIR", "/etc/doorman"))

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


def config_path(name: str) -> Path:
    """Config in /etc/doorman when installed, otherwise beside addon.py.

    No per-file fallback: once /etc/doorman exists, a missing rule file means
    an empty policy, not the old packaged defaults.
    """
    return (CONFIG_DIR if CONFIG_DIR.is_dir() else BASE_DIR) / name


def parse_downloads(text: str) -> tuple[set[str], set[str]]:
    """Allowed download types and extensions from downloads.conf.

    Format: 'type <mime>' and 'ext <suffix>', one per line. '#' comments.
    Unknown lines are ignored so a typo cannot silently allow everything.
    """
    types: set[str] = set()
    extensions: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        value = value.strip().lower()
        if key.lower() == "type":
            types.add(value.split(";", 1)[0].strip())
        elif key.lower() == "ext":
            extensions.add(value if value.startswith(".") else "." + value)
    return types, extensions


try:
    ALLOWED_DOWNLOAD_TYPES, ALLOWED_DOWNLOAD_EXTENSIONS = parse_downloads(
        config_path("downloads.conf").read_text(encoding="utf-8")
    )
except OSError:
    # Missing config means no downloads are allowed.
    ALLOWED_DOWNLOAD_TYPES, ALLOWED_DOWNLOAD_EXTENSIONS = set(), set()


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


def normalize_host(value: str) -> str:
    """Hostname from a list entry or request host, without scheme or port."""
    value = value.strip().lower().rstrip(".")
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
        host, _, port = value.rpartition(":")
        if port.isdigit():
            value = host
    value = value.rstrip(".")
    return value[2:] if value.startswith("*.") else value


def allowlist() -> set[str]:
    try:
        text = config_path("allowlist.txt").read_text(encoding="utf-8")
    except OSError:
        return set()

    result = set()
    for line in text.splitlines():
        entry = normalize_host(line.split("#", 1)[0])
        if entry:
            result.add(entry)
    return result


def matches(host: str, entries: set[str]) -> bool:
    if not host or not entries:
        return False
    host = normalize_host(host)
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
    path = unquote(urlparse(flow.request.pretty_url).path)
    names = [Path(path).name.lower()]
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
    name = Path(unquote(urlparse(url).path)).name.lower()
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

    allowlist_file = config_path("allowlist.txt")
    downloads_file = config_path("downloads.conf")
    if not allowlist_file.exists():
        ctx.log.warn(f"allowlist NOT FOUND: {allowlist_file} - nothing is exempt")
    if not downloads_file.exists():
        ctx.log.warn(f"downloads NOT FOUND: {downloads_file} - all downloads blocked")

    ctx.log.info(
        f"config: {len(BLOCKED_HOSTS)} blocked hosts, "
        f"{len(allowlist())} allowlisted hosts, "
        f"{len(DOWNLOAD_TYPES)} download types, "
        f"{len(DOWNLOAD_EXTENSIONS)} download extensions, "
        f"{len(ALLOWED_DOWNLOAD_TYPES)} allowed types, "
        f"{len(ALLOWED_DOWNLOAD_EXTENSIONS)} allowed extensions"
    )
    ctx.log.info(f"config files: allowlist {allowlist_file}, downloads {downloads_file}")


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

    host = normalize_host(flow.request.pretty_host)

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

    # A 101 is a protocol upgrade (WebSocket). Streaming it as a normal
    # response would break the upgraded connection.
    if flow.response.status_code == 101:
        return

    if is_allowed(flow):
        # Allowlisted sites are exempt; stream so large files are not buffered.
        flow.response.stream = True
        return

    if is_allowed_download(flow):
        # Allowed files would otherwise be buffered in memory in full.
        flow.response.stream = True
        return

    content_type = flow.response.headers.get("content-type", "")
    if is_media(content_type):
        # Block at headers, before the body is buffered in full.
        ctx.log.info(f"Blocked media: {flow.request.pretty_url} ({content_type})")
        block_body(flow, b"Media blocked\n")
        return

    reason = download_reason(flow)
    if reason is None:
        return

    ctx.log.info(f"Blocked download: {flow.request.pretty_url} ({reason})")
    block_body(flow, b"Downloads are blocked by internet blocker\n")


def response(flow: http.HTTPFlow) -> None:
    if flow.response is None:
        return

    if is_allowed(flow) or is_allowed_download(flow):
        return

    content_type = flow.response.headers.get("content-type", "")
    if not is_media(content_type):
        return

    ctx.log.info(f"Blocked media: {flow.request.pretty_url} ({content_type})")
    flow.response.status_code = 403
    flow.response.content = b"Media blocked\n"
    flow.response.headers["content-type"] = "text/plain; charset=utf-8"
    flow.response.headers.pop("content-disposition", None)
    flow.response.headers.pop("content-encoding", None)
