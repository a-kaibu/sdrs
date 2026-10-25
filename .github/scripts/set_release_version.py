"""Set the Cargo workspace version from the release Git tag."""

import os
from pathlib import Path
import re
import subprocess


def version_from_tag(tag):
    number = r"(?:0|[1-9][0-9]*)"
    identifier = r"[0-9A-Za-z-]+"
    pattern = (
        rf"v({number}\.{number}\.{number})"
        rf"(?:-({identifier}(?:\.{identifier})*))?"
        rf"(?:\+({identifier}(?:\.{identifier})*))?"
    )
    match = re.fullmatch(pattern, tag)
    if not match:
        raise ValueError(f"Invalid release tag: {tag}; expected vMAJOR.MINOR.PATCH")
    prerelease = match.group(2)
    if prerelease and any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease.split(".")
    ):
        raise ValueError(f"Invalid numeric prerelease identifier in tag: {tag}")
    return tag[1:]


def main():
    tag = os.environ.get("RELEASE_TAG", "")
    if not tag:
        print("No release tag; using the development workspace version")
        return
    try:
        version = version_from_tag(tag)
    except ValueError as err:
        raise SystemExit(str(err)) from err
    manifest = Path("Cargo.toml")
    text, count = re.subn(
        r'(\[workspace\.package\]\s*\nversion\s*=\s*)"[^"]+"',
        lambda match: f'{match.group(1)}"{version}"',
        manifest.read_text(encoding="utf-8"),
    )
    if count != 1:
        raise SystemExit("Expected one [workspace.package] version in Cargo.toml")
    manifest.write_text(text, encoding="utf-8")
    subprocess.run(["cargo", "update", "--workspace"], check=True)
    print(f"Set Cargo workspace and lockfile version to {version} from {tag}")


if __name__ == "__main__":
    main()
