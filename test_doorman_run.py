"""Checks for the installed doorman-run launcher."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parent / "scripts" / "doorman-run-app.sh"
FAKE_APP = r"""#!/bin/sh
printf 'PROXY:%s\n' "$http_proxy"
printf 'GIT_CONFIG_COUNT:%s\n' "${GIT_CONFIG_COUNT:-}"
printf 'GIT_CONFIG_KEY_0:%s\n' "${GIT_CONFIG_KEY_0:-}"
printf 'GIT_CONFIG_VALUE_0:%s\n' "${GIT_CONFIG_VALUE_0:-}"
printf 'GIT_CONFIG_KEY_1:%s\n' "${GIT_CONFIG_KEY_1:-}"
printf 'GIT_CONFIG_VALUE_1:%s\n' "${GIT_CONFIG_VALUE_1:-}"
for arg in "$@"; do printf 'ARG:%s\n' "$arg"; done
"""


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class DoormanRunTest(unittest.TestCase):
    def run_app(
        self,
        apps_dir: Path,
        *,
        steam: bool = False,
        args=(),
        app_name=None,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            fake = bin_dir / "fake-app"
            write_executable(fake, FAKE_APP)

            env = os.environ.copy()
            env["DOORMAN_APPS_DIR"] = str(apps_dir)
            if app_name:
                env["DOORMAN_APP_NAME"] = app_name
            if steam:
                env["DOORMAN_STEAM_CMD"] = str(fake)
                argv = ["sh", str(SCRIPT), "steam", *args]
            else:
                argv = ["sh", str(SCRIPT), str(fake), *args]

            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                env=env,
            )

    def test_creates_empty_allowlist_and_uses_global_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "apps"
            apps_dir.mkdir()
            result = self.run_app(apps_dir, steam=True, args=["https://example.com"])
            self.assertEqual(result.returncode, 0, result.stderr)
            allowlist = apps_dir / "steam.txt"
            self.assertTrue(allowlist.exists())
            self.assertTrue(allowlist.read_text(encoding="utf-8").startswith("#"))
            self.assertIn("PROXY:http://127.0.0.1:8081", result.stdout)
            self.assertIn("ARG:https://example.com", result.stdout)
            self.assertNotIn("steam:doorman", result.stdout)
            self.assertIn("created per-app allowlist", result.stderr)

    def test_uses_app_credentials_when_allowlist_has_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "apps"
            apps_dir.mkdir()
            (apps_dir / "steam.txt").write_text("steam.test\n", encoding="utf-8")
            result = self.run_app(apps_dir, steam=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PROXY:http://steam:doorman@127.0.0.1:8081", result.stdout)
            self.assertIn("using per-app allowlist", result.stderr)

    def test_command_name_comes_from_the_basename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "apps"
            apps_dir.mkdir()
            result = self.run_app(apps_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((apps_dir / "fake-app.txt").exists())
            self.assertIn("PROXY:http://127.0.0.1:8081", result.stdout)

    def test_existing_allowlist_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "apps"
            apps_dir.mkdir()
            allowlist = apps_dir / "steam.txt"
            allowlist.write_text("keep.test\n", encoding="utf-8")
            result = self.run_app(apps_dir, steam=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(allowlist.read_text(encoding="utf-8"), "keep.test\n")

    def test_missing_apps_dir_falls_back_to_global_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "missing"
            result = self.run_app(apps_dir, steam=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PROXY:http://127.0.0.1:8081", result.stdout)
            self.assertIn("is missing", result.stderr)

    def test_git_gets_authenticated_proxy_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apps_dir = Path(tmp) / "apps"
            apps_dir.mkdir()
            (apps_dir / "git.txt").write_text("github.test\n", encoding="utf-8")
            result = self.run_app(apps_dir, app_name="git")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("GIT_CONFIG_COUNT:2", result.stdout)
            self.assertIn("GIT_CONFIG_KEY_0:http.proxy", result.stdout)
            self.assertIn(
                "GIT_CONFIG_VALUE_0:http://git:doorman@127.0.0.1:8081",
                result.stdout,
            )
            self.assertIn("GIT_CONFIG_KEY_1:http.proxyAuthMethod", result.stdout)
            self.assertIn("GIT_CONFIG_VALUE_1:basic", result.stdout)


if __name__ == "__main__":
    unittest.main()
