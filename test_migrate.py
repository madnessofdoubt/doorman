"""Checks for the doorman-migrate-profile helper."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parent / "scripts" / "doorman-migrate-profile.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class MigrateProfileTest(unittest.TestCase):
    def run_script(self, *, helium_running: bool, args):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config").mkdir()
            bin_dir = home / "bin"
            bin_dir.mkdir()
            write_executable(
                bin_dir / "pgrep",
                "#!/bin/sh\nexit %d\n" % (0 if helium_running else 1),
            )
            write_executable(bin_dir / "id", "#!/bin/sh\necho 1000\n")

            env = os.environ.copy()
            env["HOME"] = str(home)
            env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
            env.pop("XDG_CONFIG_HOME", None)

            return subprocess.run(
                ["sh", str(SCRIPT), *args],
                capture_output=True,
                text=True,
                env=env,
            )

    def make_profiles(self, home: Path):
        source = home / "old-profile"
        (source / "Default").mkdir(parents=True)
        (source / "Default" / "Cookies").write_bytes(b"")
        (source / "SingletonLock").symlink_to("stale")

        target = home / ".config" / "net.imput.helium"
        (target / "Default").mkdir(parents=True)
        (target / "Default" / "Cookies").write_bytes(b"")
        (target / "SingletonLock").symlink_to("stale")
        return source, target

    def test_moves_profile_and_keeps_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config").mkdir()
            source, target = self.make_profiles(home)
            result = self.run_script(
                helium_running=False,
                args=["--from", str(source), "--to", str(target)],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(source.exists())
            self.assertTrue((target / "Default" / "Cookies").exists())
            self.assertFalse((target / "SingletonLock").exists())
            backups = list((home / ".config").glob("net.imput.helium.before-migrate-*"))
            self.assertEqual(len(backups), 1)
            self.assertTrue((backups[0] / "Default" / "Cookies").exists())

    def test_refuses_while_helium_is_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config").mkdir()
            source, target = self.make_profiles(home)
            result = self.run_script(
                helium_running=True,
                args=["--from", str(source), "--to", str(target)],
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Helium is running", result.stderr)
            self.assertTrue(source.exists())
            self.assertTrue((target / "Default" / "Cookies").exists())


if __name__ == "__main__":
    unittest.main()
