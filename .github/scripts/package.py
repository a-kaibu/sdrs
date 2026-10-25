"""Package the native CLI and GUI binaries built by the release workflow."""

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-version", action="store_true")
    args = parser.parse_args()
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"],
            text=True,
        )
    )
    versions = {package["version"] for package in metadata["packages"]}
    if len(versions) != 1:
        raise SystemExit("All workspace packages must have the same version")
    version = versions.pop()
    tag = os.environ.get("RELEASE_TAG", "")
    if tag and tag != f"v{version}":
        raise SystemExit(f"Tag {tag} does not match Cargo version v{version}")
    if args.check_version:
        if tag:
            print(f"Workspace version v{version} matches release tag")
        else:
            print(f"Workspace version v{version}")
        return

    target = os.environ["TARGET"]
    windows = "windows" in target
    suffix = ".exe" if windows else ""
    binaries = [
        Path("target") / target / "release" / f"{name}{suffix}"
        for name in ("sdrs", "sdrs-gui")
    ]
    for binary in binaries:
        if not binary.is_file():
            raise SystemExit(f"Missing binary: {binary}")

    dist = Path("dist")
    dist.mkdir(exist_ok=True)
    stem = dist / f"sdrs-v{version}-{target}"
    readme = Path("README.md")
    if windows:
        with zipfile.ZipFile(f"{stem}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for file in [*binaries, readme]:
                archive.write(file, file.name)
    else:
        with tarfile.open(f"{stem}.tar.gz", "w:gz") as archive:
            for file in [*binaries, readme]:
                data = file.read_bytes()
                info = tarfile.TarInfo(file.name)
                info.size = len(data)
                info.mode = 0o755 if file in binaries else 0o644
                archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    main()
