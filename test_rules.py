"""Small checks for the shared matcher and the SNI parser."""

import random
import ssl
import tempfile
import unittest
from pathlib import Path

from rules import allowed, load_host_list, matches, normalize_host
from strict_proxy import Guard, parse_connect_target, parse_sni


def client_hello(server_hostname: str | None = None) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class RulesTest(unittest.TestCase):
    def test_host_and_subdomains_match(self) -> None:
        entries = {"example.com"}
        self.assertTrue(matches("example.com", entries))
        self.assertTrue(matches("www.example.com", entries))
        self.assertTrue(matches("a.b.example.com", entries))

    def test_lookalikes_do_not_match(self) -> None:
        entries = {"example.com"}
        self.assertFalse(matches("badexample.com", entries))
        self.assertFalse(matches("example.com.evil.net", entries))
        self.assertFalse(matches("", entries))
        self.assertFalse(matches("example.com", set()))

    def test_load_ignores_comments_and_blanks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.txt"
            path.write_text("# comment\n\nExample.COM.  # trailing\n", encoding="utf-8")
            self.assertEqual(load_host_list(path), {"example.com"})

    def test_missing_file_is_empty(self) -> None:
        self.assertEqual(load_host_list(Path("/nonexistent/doorman-allowlist")), set())

    def test_wildcard_prefix_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.txt"
            path.write_text("*.example.com\n", encoding="utf-8")
            self.assertEqual(load_host_list(path), {"example.com"})

    def test_entries_accept_scheme_and_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.txt"
            path.write_text("https://Example.COM:8443/path\n", encoding="utf-8")
            self.assertEqual(load_host_list(path), {"example.com"})

    def test_normalize_host(self) -> None:
        self.assertEqual(normalize_host("https://Example.COM:443/x"), "example.com")
        self.assertEqual(normalize_host("example.com:8080"), "example.com")
        self.assertEqual(normalize_host("example.com."), "example.com")
        self.assertEqual(normalize_host("*.Example.COM."), "example.com")
        self.assertEqual(normalize_host("[::1]:8080"), "::1")
        self.assertEqual(normalize_host(""), "")


class PolicyTest(unittest.TestCase):
    def test_strict_default_denies_everything(self) -> None:
        self.assertFalse(allowed("anything.com", set(), "deny"))
        self.assertTrue(allowed("anything.com", set(), "allow"))

    def test_default_applies_with_nonempty_allowlist(self) -> None:
        allow = {"example.com"}
        self.assertTrue(allowed("steamcommunity.com", allow, "allow"))
        self.assertFalse(allowed("steamcommunity.com", allow, "deny"))
        self.assertTrue(allowed("www.example.com", allow, "deny"))

    def test_empty_host_is_never_allowed(self) -> None:
        self.assertFalse(allowed("", set(), "allow"))


class ConnectTargetTest(unittest.TestCase):
    def test_host_and_port(self) -> None:
        self.assertEqual(parse_connect_target("example.com:443"), ("example.com", 443))
        self.assertEqual(parse_connect_target("Example.COM:8443"), ("example.com", 8443))
        self.assertEqual(parse_connect_target("example.com"), ("example.com", 443))

    def test_bracketed_ipv6(self) -> None:
        self.assertEqual(parse_connect_target("[::1]:8443"), ("::1", 8443))
        self.assertEqual(parse_connect_target("[2001:db8::1]"), ("2001:db8::1", 443))

    def test_malformed_targets_are_rejected(self) -> None:
        for target in (
            "",
            ":443",
            "example.com:",
            "example.com:abc",
            "example.com:0",
            "example.com:65536",
            "[::1]:https",
            "[::1",
            "2001:db8::1",  # unbracketed IPv6 is not valid authority form
        ):
            with self.subTest(target=target):
                self.assertIsNone(parse_connect_target(target))


class ReloadTest(unittest.TestCase):
    def test_reload_picks_up_new_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.txt"
            path.write_text("example.com\n", encoding="utf-8")
            guard = Guard(path, "enforce", "deny")
            self.assertTrue(guard.permit("example.com"))
            self.assertTrue(guard.permit("new.example.com"))  # subdomain
            self.assertFalse(guard.permit("other.test"))

            path.write_text("example.com\nother.test\n", encoding="utf-8")
            guard.reload()
            self.assertTrue(guard.permit("other.test"))


class SniTest(unittest.TestCase):
    def test_reads_sni(self) -> None:
        self.assertEqual(parse_sni(client_hello("www.example.com")), "www.example.com")
        self.assertEqual(parse_sni(client_hello("a.b.c.youtube.com")), "a.b.c.youtube.com")

    def test_no_sni_is_none(self) -> None:
        self.assertIsNone(parse_sni(client_hello()))

    def test_truncated_and_garbage_are_none(self) -> None:
        self.assertIsNone(parse_sni(b"\x16\x03\x01\x00\x05abc"))
        self.assertIsNone(parse_sni(b"hello world"))

    def test_truncated_client_hello_never_raises(self) -> None:
        # Every prefix keeps the original (larger) declared record length, so
        # a parser that trusts it would index past the buffer.
        hello = client_hello("www.example.com")
        for size in range(len(hello) + 1):
            result = parse_sni(hello[:size])
            self.assertTrue(result is None or isinstance(result, str))

    def test_random_bytes_never_raise(self) -> None:
        rng = random.Random(20261024)
        for _ in range(2000):
            size = rng.randrange(0, 96)
            data = bytes(rng.randrange(256) for _ in range(size))
            result = parse_sni(data)
            self.assertTrue(result is None or isinstance(result, str))


if __name__ == "__main__":
    unittest.main()
