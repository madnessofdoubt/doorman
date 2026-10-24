"""Checks for the doorman-browser launcher."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

LAUNCHER = Path(__file__).parent / "scripts" / "doorman-browser.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class LauncherTest(unittest.TestCase):
    def run_launcher(
        self,
        running: bool = False,
        args=(),
        own_nss: bool = False,
        profile: bool = False,
        as_root: bool = False,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            write_executable(
                bin_dir / "pgrep",
                "#!/bin/sh\nexit %d\n" % (0 if running else 1),
            )
            # Shadow the real GUI helpers so the guard test cannot pop a
            # notification or a dialog on the machine running the tests.
            for name in ("notify-send", "zenity"):
                write_executable(bin_dir / name, "#!/bin/sh\nexit 1\n")
            if as_root:
                write_executable(bin_dir / "id", "#!/bin/sh\necho 0\n")

            app = bin_dir / "fake-helium"
            write_executable(
                app,
                """#!/bin/sh
for arg in "$@"; do printf 'ARG:%s\\n' "$arg"; done
printf 'NSS_LIB_PARAMS:%s\\n' "$NSS_LIB_PARAMS"
printf 'NSS_DEFAULT_DB_TYPE:%s\\n' "$NSS_DEFAULT_DB_TYPE"
""",
            )

            nssdir = tmp_path / "nssdb"
            if own_nss:
                nssdir.mkdir()

            profile_path = ""
            if profile:
                profile_dir = tmp_path / "profile"
                profile_dir.mkdir()
                profile_path = str(profile_dir)

            conf = tmp_path / "doorman.conf"
            conf.write_text(f"BROWSER_PROFILE={profile_path}\n", encoding="utf-8")

            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
            env["DOORMAN_HELIUM_APPIMAGE"] = str(app)
            env["DOORMAN_NSSDB"] = str(nssdir)
            env["DOORMAN_CONF"] = str(conf)

            return subprocess.run(
                ["sh", str(LAUNCHER), *args],
                capture_output=True,
                text=True,
                env=env,
            )

    def test_launches_normal_profile_through_the_proxy(self) -> None:
        result = self.run_launcher(False, args=["https://example.com"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARG:--proxy-server=http://127.0.0.1:8080", result.stdout)
        self.assertIn("ARG:https://example.com", result.stdout)
        self.assertNotIn("--user-data-dir", result.stdout)

    def test_uses_configured_profile(self) -> None:
        result = self.run_launcher(profile=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"ARG:--user-data-dir=.*/profile")
        self.assertIn("ARG:--proxy-server=http://127.0.0.1:8080", result.stdout)

    def test_refuses_to_run_as_root(self) -> None:
        result = self.run_launcher(as_root=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not root", result.stderr)
        self.assertNotIn("ARG:", result.stdout)

    def test_refuses_when_helium_is_running(self) -> None:
        result = self.run_launcher(True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("already running", result.stderr)
        self.assertNotIn("ARG:", result.stdout)

    def test_uses_doorman_nss_store_when_present(self) -> None:
        result = self.run_launcher(False, own_nss=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NSS_LIB_PARAMS:configdir=", result.stdout)
        self.assertIn("NSS_DEFAULT_DB_TYPE:sql", result.stdout)


if __name__ == "__main__":
    unittest.main()
