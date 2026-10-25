"""Exercise tag-driven versioning with a real Cargo workspace and lockfile."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("set_release_version.py").resolve()


class ReleaseVersionTests(unittest.TestCase):
    def test_tag_drives_manifest_lockfile_and_cargo_metadata(self):
        with tempfile.TemporaryDirectory(prefix="sdrs-version-") as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["app"]\nresolver = "2"\n'
                '[workspace.package]\nversion = "0.0.0-dev"\n',
                encoding="utf-8",
            )
            (root / "app/src").mkdir(parents=True)
            (root / "app/Cargo.toml").write_text(
                '[package]\nname = "release-test-app"\n'
                'version.workspace = true\nedition = "2021"\n',
                encoding="utf-8",
            )
            (root / "app/src/lib.rs").write_text("", encoding="utf-8")
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"], cwd=root, check=True
            )
            for tag in ("v1.0.0", "v1.0.0", "v1.1.0-rc.1"):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT)],
                    cwd=root,
                    env={**os.environ, "RELEASE_TAG": tag, "CARGO_NET_OFFLINE": "true"},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads(subprocess.check_output(
                    ["cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"],
                    cwd=root,
                    text=True,
                ))
                self.assertEqual(metadata["packages"][0]["version"], tag[1:])
                self.assertIn(f'version = "{tag[1:]}"', (root / "Cargo.lock").read_text())
            manifest = (root / "Cargo.toml").read_bytes()
            lockfile = (root / "Cargo.lock").read_bytes()
            for tag in ("", "v01.0.0", "v1.0", "v1.0.0-01", "not-a-version"):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT)],
                    cwd=root,
                    env={**os.environ, "RELEASE_TAG": tag},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode == 0, tag == "", result.stderr)
                self.assertEqual((root / "Cargo.toml").read_bytes(), manifest)
                self.assertEqual((root / "Cargo.lock").read_bytes(), lockfile)


if __name__ == "__main__":
    unittest.main()
