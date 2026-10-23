"""Small checks for the shared matcher and the SNI parser."""

import ssl
import tempfile
import unittest
from pathlib import Path

from rules import allowed, load_host_list, matches
from strict_proxy import parse_sni


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


class PolicyTest(unittest.TestCase):
    def test_strict_default_denies_everything(self) -> None:
        self.assertFalse(allowed("anything.com", set(), set(), "deny"))
        self.assertTrue(allowed("anything.com", set(), set(), "allow"))

    def test_blocklist_wins_over_allowlist(self) -> None:
        allow, block = {"example.com"}, {"example.com"}
        self.assertFalse(allowed("example.com", allow, block, "deny"))

    def test_default_allow_with_blocklist(self) -> None:
        block = {"steampowered.com"}
        self.assertFalse(allowed("store.steampowered.com", set(), block, "allow"))
        self.assertFalse(allowed("api.steampowered.com", set(), block, "allow"))
        self.assertTrue(allowed("steamcommunity.com", set(), block, "allow"))

    def test_default_applies_with_nonempty_allowlist(self) -> None:
        allow = {"example.com"}
        self.assertTrue(allowed("steamcommunity.com", allow, set(), "allow"))
        self.assertFalse(allowed("steamcommunity.com", allow, set(), "deny"))
        self.assertTrue(allowed("www.example.com", allow, set(), "deny"))

    def test_subdomain_block_does_not_hit_siblings(self) -> None:
        block = {"store.steampowered.com"}
        self.assertFalse(allowed("store.steampowered.com", set(), block, "allow"))
        self.assertTrue(allowed("checkout.steampowered.com", set(), block, "allow"))

    def test_empty_host_is_never_allowed(self) -> None:
        self.assertFalse(allowed("", set(), set(), "allow"))


class SniTest(unittest.TestCase):
    def test_reads_sni(self) -> None:
        self.assertEqual(parse_sni(client_hello("www.example.com")), "www.example.com")
        self.assertEqual(parse_sni(client_hello("a.b.c.youtube.com")), "a.b.c.youtube.com")

    def test_no_sni_is_none(self) -> None:
        self.assertIsNone(parse_sni(client_hello()))

    def test_truncated_and_garbage_are_none(self) -> None:
        self.assertIsNone(parse_sni(b"\x16\x03\x01\x00\x05abc"))
        self.assertIsNone(parse_sni(b"hello world"))


if __name__ == "__main__":
    unittest.main()
