#!/usr/bin/env python3
"""Build the dependency-free Archwright target runtime zipapp."""

from __future__ import annotations

import argparse
import shutil
import tempfile
import zipapp
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    package = repository / "src" / "archwright_mcp"
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="archwright-runtime-") as raw:
        staging = Path(raw)
        shutil.copytree(package, staging / "archwright_mcp")
        zipapp.create_archive(
            staging,
            output,
            interpreter="/usr/bin/python3",
            main="archwright_mcp.target.runtime:main",
            compressed=True,
        )
    output.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
