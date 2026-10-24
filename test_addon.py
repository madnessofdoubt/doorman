"""Checks for the browser addon's configuration parsing."""

import unittest

from addon import normalize_host, parse_downloads


class DownloadsConfigTest(unittest.TestCase):
    def test_types_and_extensions(self) -> None:
        types, extensions = parse_downloads(
            "type application/pdf\n"
            "ext .iso\n"
            "ext tar.gz\n"
        )
        self.assertEqual(types, {"application/pdf"})
        self.assertEqual(extensions, {".iso", ".tar.gz"})

    def test_comments_blanks_and_whitespace(self) -> None:
        types, extensions = parse_downloads(
            "# comment\n\n  ext\t.iso   # inline\n"
        )
        self.assertEqual(types, set())
        self.assertEqual(extensions, {".iso"})

    def test_type_parameters_are_dropped(self) -> None:
        types, _ = parse_downloads("type Application/PDF; charset=binary\n")
        self.assertEqual(types, {"application/pdf"})

    def test_unknown_lines_are_ignored(self) -> None:
        self.assertEqual(parse_downloads("nonsense\nallow all\n"), (set(), set()))

    def test_empty_config_allows_nothing(self) -> None:
        self.assertEqual(parse_downloads(""), (set(), set()))


class HostNormalizationTest(unittest.TestCase):
    def test_scheme_and_port_are_stripped(self) -> None:
        self.assertEqual(normalize_host("192.168.0.250:8081"), "192.168.0.250")
        self.assertEqual(normalize_host("http://192.168.0.250:8096/"), "192.168.0.250")
        self.assertEqual(normalize_host("[::1]:8080"), "::1")

    def test_wildcard_and_trailing_dot(self) -> None:
        self.assertEqual(normalize_host("*.Example.COM."), "example.com")


if __name__ == "__main__":
    unittest.main()
