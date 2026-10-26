#!/usr/bin/env python3
"""Host allowlist proxy. Says yes or no by hostname, without decrypting TLS.

    python strict_proxy.py --dry-run     # log decisions, allow everything
    python strict_proxy.py               # log decisions, deny what is not listed

Accepts CONNECT tunnels (what HTTP proxying uses), plain HTTP requests, and
raw TLS streams (what a transparent redirect delivers). TLS is never decrypted:
the SNI in the ClientHello is read, then bytes are piped untouched.
"""

import argparse
import asyncio
import base64
import binascii
import re
import signal
import sys
from pathlib import Path

from rules import allowed, load_host_list

BASE_DIR = Path(__file__).parent
DEFAULT_ALLOWLIST = BASE_DIR / "strict_allowlist.txt"
DEFAULT_APPS_DIR = Path("/etc/doorman/apps")
DEFAULT_APP_PORTS = Path("/etc/doorman/apps/ports.conf")
APP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
MAX_SNI_PEEK = 16 * 1024


def parse_sni(data: bytes) -> str | None:
    """SNI hostname from a TLS ClientHello, or None if absent/malformed."""
    if len(data) < 9 or data[0] != TLS_HANDSHAKE or data[5] != TLS_CLIENT_HELLO:
        return None

    # Clamp the declared length to the bytes actually read. A truncated
    # ClientHello must never make the parser index past its buffer.
    end = min(9 + ((data[6] << 16) | (data[7] << 8) | data[8]), len(data))
    i = 9 + 2 + 32  # handshake header, then client version + random
    if i >= end:
        return None

    i += 1 + data[i]  # session id
    if i + 2 > end:
        return None
    i += 2 + ((data[i] << 8) | data[i + 1])  # cipher suites
    if i >= end:
        return None
    i += 1 + data[i]  # compression methods
    if i + 2 > end:
        return None
    extensions_end = min(i + 2 + ((data[i] << 8) | data[i + 1]), end)
    i += 2

    while i + 4 <= extensions_end:
        ext_type = (data[i] << 8) | data[i + 1]
        ext_len = (data[i + 2] << 8) | data[i + 3]
        i += 4
        if ext_type == 0x0000:  # server_name
            if i + 5 > extensions_end:
                return None
            name_len = (data[i + 3] << 8) | data[i + 4]
            name = data[i + 5 : i + 5 + name_len]
            return name.decode("ascii", "replace").lower().rstrip(".") or None
        i += ext_len
    return None


def request_target(line: bytes) -> tuple[str | None, int]:
    """Host and port from an absolute-form HTTP request line."""
    m = re.match(rb"^[A-Z]+ (https?)://([^/\s:]+)(?::(\d+))?", line)
    if not m:
        return None, 0
    port = int(m.group(3)) if m.group(3) else (443 if m.group(1) == b"https" else 80)
    return m.group(2).decode("ascii", "replace").lower().rstrip("."), port


def header_target(headers: bytes, default_port: int) -> tuple[str | None, int]:
    """Host and port from a Host header."""
    m = re.search(rb"^host:[ \t]*([^\r\n/]+)", headers, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None, 0
    value = m.group(1).decode("ascii", "replace").strip().lower().rstrip(".")
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return value, default_port


def parse_connect_target(target: str) -> tuple[str, int] | None:
    """Host and port from CONNECT authority form, bracketed IPv6 included."""
    target = target.strip()
    if not target:
        return None

    if target.startswith("["):
        host, sep, rest = target[1:].partition("]")
        if not sep:
            return None
        if not rest:
            port = 443
        elif rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        else:
            return None
    elif ":" in target:
        host, _, port_text = target.rpartition(":")
        if not port_text.isdigit():
            return None
        port = int(port_text)
    else:
        host, port = target, 443

    host = host.strip().lower().rstrip(".")
    if not host or not 1 <= port <= 65535:
        return None
    if ":" in host and not target.startswith("["):
        return None  # unbracketed IPv6 is not a valid authority
    return host, port


def parse_proxy_app(headers: bytes) -> tuple[bool, str | None]:
    """(auth header present, app name) from Proxy-Authorization.

    A missing header means "no per-app policy". A present but malformed
    header returns (True, None), so the caller can answer 407 instead of
    silently falling back to the global list.
    """
    if not re.search(rb"(?im)^proxy-authorization:", headers):
        return False, None

    match = re.search(
        rb"(?im)^proxy-authorization:[ \t]*Basic[ \t]+([A-Za-z0-9+/=]+)[ \t]*\r?$",
        headers,
    )
    if not match:
        return True, None
    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode(
            "utf-8", "replace"
        )
    except (ValueError, binascii.Error):
        return True, None
    username, _, _password = decoded.partition(":")
    app = username.strip().lower()
    if not APP_NAME_RE.fullmatch(app):
        return True, None
    return True, app


def strip_proxy_headers(head: bytes) -> bytes:
    """Remove proxy credentials before forwarding a request to an origin."""
    head = re.sub(rb"(?im)^proxy-authorization:[^\r\n]*\r?\n", b"", head)
    head = re.sub(rb"(?im)^proxy-connection:[^\r\n]*\r?\n", b"", head)
    return head


def load_app_ports(path: Path) -> list[tuple[int, str]]:
    """Port-to-app mappings from a file of 'port app' lines."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    ports: dict[int, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit():
            print(f"WARN app port line ignored: {line}", flush=True)
            continue
        port = int(parts[0])
        app = parts[1].lower()
        if not 1 <= port <= 65535 or not APP_NAME_RE.fullmatch(app):
            print(f"WARN app port line ignored: {line}", flush=True)
            continue
        if port in ports:
            print(f"WARN duplicate app port ignored: {port}", flush=True)
            continue
        ports[port] = app
    return sorted(ports.items())


class Guard:
    def __init__(
        self,
        allowlist: Path,
        mode: str,
        default: str = "deny",
        apps_dir: Path | None = None,
    ) -> None:
        self.allowlist = allowlist
        self.mode = mode  # "log" or "enforce"
        self.default = default  # policy for hosts not on the allowlist
        self.allowed = load_host_list(allowlist)
        self.apps_dir = apps_dir if apps_dir is not None else DEFAULT_APPS_DIR
        self._app_cache: dict[str, tuple[int, set[str]]] = {}
        self.pending_head: bytes | None = None

    def reload(self) -> None:
        hosts = load_host_list(self.allowlist)
        if not hosts and not self.allowlist.exists():
            print(f"WARN allowlist missing: {self.allowlist}", flush=True)
        self.allowed = hosts

    def app_allowed(self, app: str) -> set[str]:
        """Extra hosts for one app, re-read when the app file changes."""
        if not APP_NAME_RE.fullmatch(app):
            return set()
        path = self.apps_dir / f"{app}.txt"
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            self._app_cache.pop(app, None)
            return set()

        cached = self._app_cache.get(app)
        if cached is None or cached[0] != mtime:
            hosts = load_host_list(path)
            self._app_cache[app] = (mtime, hosts)
            print(f"APP {app} allowlisted={len(hosts)}", flush=True)
            return hosts
        return cached[1]

    def permit(self, host: str, app: str | None = None) -> bool:
        """Policy answer, before dry-run is applied."""
        allow = self.allowed
        if app:
            extra = self.app_allowed(app)
            if extra:
                allow = allow | extra
        return allowed(host or "", allow, self.default)

    def decide(self, host: str | None, app: str | None = None) -> bool:
        """Log one decision for host; return whether it may pass."""
        ok = self.permit(host or "", app)
        verdict = "ALLOW" if ok else "DENY"
        if not ok and self.mode == "log":
            verdict = "DRYRUN"
        label = f"{app}:{host or '-'}" if app else (host or "-")
        print(f"{verdict} {label}", flush=True)
        return ok or self.mode == "log"

    async def auth_required(self, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="doorman"\r\n'
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        app_hint: str | None = None,
        auth: tuple[str, str] | None = None,
        upstream: tuple[str, int] | None = None,
    ) -> None:
        try:
            await self.route(reader, writer, app_hint, auth, upstream)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        except asyncio.LimitOverrunError:
            print("WARN request headers too large", flush=True)
        except Exception as exc:  # one malformed client must not kill the task
            print(f"ERROR {type(exc).__name__}: {exc}", flush=True)
        finally:
            writer.close()

    async def route(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        app_hint: str | None = None,
        auth: tuple[str, str] | None = None,
        upstream: tuple[str, int] | None = None,
    ) -> None:
        first = await reader.read(1)
        if not first:
            return

        if auth is not None:
            # An upstream proxy is configured, so the client may send the
            # request in any form. Challenge once when it has no credentials.
            if not await self.prompt_auth(reader, writer):
                return
            headers = self.pending_head or b""
            self.pending_head = None
            await self.forward(reader, writer, headers, None, 0, auth, upstream)
            return

        if first == b"\x16":  # TLS ClientHello: read the record, then peek SNI
            header = first + await reader.readexactly(4)
            record_len = (header[3] << 8) | header[4]
            data = header + await reader.readexactly(min(record_len, MAX_SNI_PEEK - 5))
            sni = parse_sni(data)
            if not self.decide(sni, app_hint):
                return
            await self.tunnel(
                reader, writer, data, sni, 443, auth, upstream, reply=False
            )
            return

        headers = first + await reader.readuntil(b"\r\n\r\n")
        auth_present, app = parse_proxy_app(headers)
        if app_hint:
            app = app_hint
        elif auth_present and app is None:
            print("BADAUTH", flush=True)
            await self.auth_required(writer)
            return
        line = headers.split(b"\r\n", 1)[0]
        if line.startswith(b"CONNECT "):
            parts = line.split()
            target = (
                parse_connect_target(parts[1].decode("ascii", "replace"))
                if len(parts) > 1
                else None
            )
            if target is None:
                print("BAD CONNECT target", flush=True)
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                return
            host, port = target
            if not self.decide(host, app):
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                return
            await self.tunnel(
                reader, writer, b"", host, port, auth, upstream, reply=True
            )
            return

        host, port = request_target(line)
        if not host:
            host, port = header_target(headers, 80)
        if not self.decide(host, app):
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            return
        await self.forward(reader, writer, headers, host, port or 80, auth, upstream)

    async def prompt_auth(self, reader, writer) -> bool:
        """Ask for proxy credentials with a 407, then wait for the real request.

        The challenged request is discarded; only the next header block is
        forwarded upstream.
        """
        await self.auth_required(writer)
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return False
        if not head.strip():
            return False
        self.pending_head = head
        return True

    async def tunnel(
        self,
        reader,
        writer,
        buffered: bytes,
        host: str | None,
        port: int,
        auth=None,
        upstream: tuple[str, int] | None = None,
        reply: bool = True,
    ) -> None:
        """Connect to host:port (or an upstream proxy) and pipe bytes."""
        target = upstream if upstream is not None else (host, port)
        try:
            up_reader, up_writer = await asyncio.open_connection(*target)
        except OSError as exc:
            print(f"UPSTREAM {host}:{port} failed: {exc}", flush=True)
            if reply:
                body = f"cannot reach {host}:{port}: {exc}\n".encode()
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
            return
        if reply:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        if not await self.send_upstream(
            reader, writer, up_reader, up_writer, buffered, auth
        ):
            return
        if buffered:
            up_writer.write(buffered)
            await up_writer.drain()
        await self.pipe(reader, writer, up_reader, up_writer)

    async def forward(
        self,
        reader,
        writer,
        head: bytes,
        host: str | None,
        port: int,
        auth: tuple[str, str] | None = None,
        upstream: tuple[str, int] | None = None,
    ) -> None:
        if not host:
            return
        head = strip_proxy_headers(head)
        target = upstream if upstream is not None else (host, port)
        # A proxy receives absolute-form requests; origins expect origin-form.
        request_line, sep, rest = head.partition(b"\r\n")
        m = re.match(rb"^([A-Z]+) https?://[^/\s]+([^\s]*) (HTTP/\d\.\d)$", request_line)
        if m:
            request_line = b" ".join([m.group(1), m.group(2) or b"/", m.group(3)])
            head = request_line + sep + rest
        try:
            up_reader, up_writer = await asyncio.open_connection(*target)
        except OSError as exc:
            print(f"UPSTREAM {host}:{port} failed: {exc}", flush=True)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        if not await self.send_upstream(
            reader, writer, up_reader, up_writer, head, auth
        ):
            return
        await self.pipe(reader, writer, up_reader, up_writer)

    async def authenticate(self, up_reader, up_writer, auth) -> bytes:
        """Log in to an upstream proxy that answered 407.

        Returns the buffered bytes of the upstream's reply, if it sent more
        than the status line. Raises OSError when the login fails.
        """
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        up_writer.write(
            b"Proxy-Authorization: Basic " + token.encode() + b"\r\n"
        )
        await up_writer.drain()
        try:
            rsp = await asyncio.wait_for(
                up_reader.readuntil(b"\r\n\r\n"), timeout=15
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise OSError(f"upstream proxy closed during login: {exc}") from exc
        except asyncio.TimeoutError as exc:
            raise OSError("upstream proxy login timed out") from exc

        status = rsp.split(b"\r\n", 1)[0].decode("latin-1")
        parts = status.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if not 200 <= code < 400:
            raise OSError(f"upstream proxy login failed: {status}")
        print(f"UPSTREAM-AUTH ok ({auth[0]})", flush=True)
        return rsp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in rsp else b""

    async def send_upstream(
        self, reader, writer, up_reader, up_writer, head: bytes, auth
    ) -> bool:
        """Send the request line to an upstream proxy, adding credentials.

        The caller writes the buffered ClientHello or request headers after
        this returns True. Returns False when the upstream rejected the login.
        """
        line, sep, rest = head.partition(b"\r\n")
        is_connect = line.startswith(b"CONNECT ")
        if auth is None:
            up_writer.write(line + sep)
            await up_writer.drain()
            if not is_connect:
                up_writer.write(rest)
                await up_writer.drain()
            return True

        up_writer.write(line + b"\r\n")
        await up_writer.drain()
        try:
            rsp = await asyncio.wait_for(
                up_reader.readuntil(b"\r\n\r\n"), timeout=15
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            rsp = b""
        except asyncio.TimeoutError:
            rsp = b""

        status = rsp.split(b"\r\n", 1)[0].decode("latin-1") if rsp else ""
        fields = status.split()
        code = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0

        if rsp and code != 407:
            # No credentials needed: pass the answer through.
            up_writer.write(rest)
            await up_writer.drain()
            writer.write(rsp)
            await writer.drain()
            return True

        try:
            buffered = await self.authenticate(up_reader, up_writer, auth)
        except OSError as exc:
            print(f"UPSTREAM-AUTH failed: {exc}", flush=True)
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            return False

        up_writer.write(line + b"\r\n" + rest)
        await up_writer.drain()
        if is_connect:
            writer.write(
                b"HTTP/1.1 200 Connection Established\r\n\r\n"
            )
            await writer.drain()
        if buffered:
            writer.write(buffered)
            await writer.drain()
        return True

    async def pipe(self, reader, writer, up_reader, up_writer) -> None:
        async def copy(src, dst):
            try:
                while chunk := await src.read(65536):
                    dst.write(chunk)
                    await dst.drain()
            finally:
                dst.close()

        await asyncio.gather(copy(reader, up_writer), copy(up_reader, writer))


def install_sighup(guard: Guard) -> None:
    """Reload the allowlist on SIGHUP, for `systemctl reload doorman-strict`."""

    def reload() -> None:
        before = len(guard.allowed)
        guard.reload()
        print(f"RELOAD allowlisted={len(guard.allowed)} (was {before})", flush=True)

    try:
        asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, reload)
    except (NotImplementedError, RuntimeError):
        pass


async def main(args) -> None:
    guard = Guard(args.allowlist, args.mode, args.default, args.apps_dir)
    upstream = None
    if args.upstream:
        up_host, _, port_text = args.upstream.rpartition(":")
        upstream = (up_host or args.upstream, int(port_text or 8080))
        if not args.upstream_user:
            print("WARN --upstream set without --upstream-user", flush=True)
    upstream_auth = None
    if args.upstream_user:
        upstream_auth = (args.upstream_user, args.upstream_password)
        if upstream is None:
            print("WARN --upstream-user set without --upstream", flush=True)
    server = await asyncio.start_server(
        lambda reader, writer: guard.handle(
            reader, writer, auth=upstream_auth, upstream=upstream
        ),
        args.listen_host,
        args.listen_port,
    )
    extra_ports = []

    for port, app in load_app_ports(args.app_ports_file):
        try:
            extra = await asyncio.start_server(
                lambda reader, writer, app=app: guard.handle(
                    reader,
                    writer,
                    app_hint=app,
                    auth=upstream_auth,
                    upstream=upstream,
                ),
                args.listen_host,
                port,
            )
        except OSError as exc:
            print(f"WARN app port {port} for {app} failed: {exc}", flush=True)
            continue
        extra_ports.append((port, app))
    install_sighup(guard)
    print(
        f"strict proxy on {args.listen_host}:{args.listen_port} "
        f"mode={args.mode} default={args.default} "
        f"allowlisted={len(guard.allowed)} apps={guard.apps_dir} "
        f"app_ports={extra_ports} logged",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8081)
    parser.add_argument(
        "--apps-dir",
        type=Path,
        default=DEFAULT_APPS_DIR,
        help="directory of per-app allowlists, <app>.txt (default: "
        "/etc/doorman/apps)",
    )
    parser.add_argument(
        "--app-ports-file",
        type=Path,
        default=DEFAULT_APP_PORTS,
        help="port-to-app mappings for clients that cannot send proxy "
        "credentials (default: /etc/doorman/apps/ports.conf)",
    )
    parser.add_argument(
        "--default",
        choices=("deny", "allow"),
        default="deny",
        help="policy for hosts not on the allowlist: deny (allowlist-only) "
        "or allow (allow everything) (default: deny)",
    )
    parser.add_argument(
        "--upstream",
        default="",
        help="forward allowed traffic through HOST:PORT instead of connecting "
        "directly (for a host where direct traffic is blocked)",
    )
    parser.add_argument(
        "--upstream-user",
        default="",
        help="username for an upstream proxy that answers 407",
    )
    parser.add_argument(
        "--upstream-password",
        default="",
        help="password for the upstream proxy",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log decisions but allow everything",
    )
    args = parser.parse_args()
    args.mode = "log" if args.dry_run else "enforce"
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
