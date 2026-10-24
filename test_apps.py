"""Checks for per-app proxy credentials and allowlists."""

import base64
import tempfile
import unittest
from pathlib import Path

from strict_proxy import Guard, parse_proxy_app, strip_proxy_headers


def basic(user: str, password: str = "doorman") -> bytes:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n".encode()


class ProxyAuthTest(unittest.TestCase):
    def test_missing_header_is_not_an_error(self) -> None:
        self.assertEqual(parse_proxy_app(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), (False, None))

    def test_valid_app_name(self) -> None:
        present, app = parse_proxy_app(b"CONNECT x:443 HTTP/1.1\r\n" + basic("Steam"))
        self.assertTrue(present)
        self.assertEqual(app, "steam")

    def test_malformed_or_unsafe_auth(self) -> None:
        for header in (
            b"Proxy-Authorization: Basic !!!\r\n",
            b"Proxy-Authorization: Bearer token\r\n",
            b"Proxy-Authorization: Basic " + basic("../evil")[len(b"Proxy-Authorization: Basic ") :],
            b"Proxy-Authorization: Basic\r\n",
        ):
            with self.subTest(header=header):
                self.assertEqual(parse_proxy_app(header), (True, None))

    def test_lowercase_header_is_read(self) -> None:
        header = b"proxy-authorization: basic " + base64.b64encode(b"firefox:x") + b"\r\n"
        self.assertEqual(parse_proxy_app(header), (True, "firefox"))


class AppAllowlistTest(unittest.TestCase):
    def make_guard(self, tmp: str):
        root = Path(tmp)
        global_list = root / "strict_allowlist.txt"
        global_list.write_text("global.test\n", encoding="utf-8")
        apps_dir = root / "apps"
        apps_dir.mkdir()
        (apps_dir / "steam.txt").write_text("steam.test\n", encoding="utf-8")
        return Guard(global_list, "enforce", "deny", apps_dir), apps_dir

    def test_app_entries_add_only_for_that_app(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            guard, _ = self.make_guard(tmp)
            self.assertTrue(guard.permit("global.test"))
            self.assertTrue(guard.permit("global.test", "firefox"))
            self.assertTrue(guard.permit("steam.test", "steam"))
            self.assertFalse(guard.permit("steam.test", "firefox"))
            self.assertFalse(guard.permit("steam.test"))

    def test_app_file_is_reloaded_when_it_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            guard, apps_dir = self.make_guard(tmp)
            self.assertFalse(guard.permit("later.test", "steam"))
            (apps_dir / "steam.txt").write_text("later.test\n", encoding="utf-8")
            self.assertTrue(guard.permit("later.test", "steam"))

    def test_invalid_app_name_cannot_escape_the_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            guard, _ = self.make_guard(tmp)
            self.assertEqual(guard.app_allowed("../strict_allowlist"), set())


class StripHeadersTest(unittest.TestCase):
    def test_proxy_headers_are_removed(self) -> None:
        head = (
            b"GET http://x.test/ HTTP/1.1\r\n"
            b"Host: x.test\r\n"
            b"Proxy-Authorization: Basic abc\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"X-Test: y\r\n\r\n"
        )
        stripped = strip_proxy_headers(head)
        self.assertNotIn(b"Proxy-Authorization", stripped)
        self.assertNotIn(b"Proxy-Connection", stripped)
        self.assertIn(b"Host: x.test", stripped)
        self.assertIn(b"X-Test: y", stripped)
        self.assertIn(b"GET http://x.test/ HTTP/1.1", stripped)


if __name__ == "__main__":
    unittest.main()
