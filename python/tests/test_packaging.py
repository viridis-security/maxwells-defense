# SPDX-License-Identifier: Apache-2.0
"""INV-4.5: build the actual wheel and inspect its typing marker."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile


def test_built_wheel_contains_typing_marker(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    shutil.copytree(
        project,
        source,
        ignore=shutil.ignore_patterns(
            "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache"
        ),
    )
    output = tmp_path / "wheels"
    output.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from setuptools.build_meta import build_wheel; "
                "build_wheel(sys.argv[1])"
            ),
            str(output),
        ],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1
    with ZipFile(wheels[0]) as wheel:
        marker = "maxwells_defense/py.typed"
        assert marker in wheel.namelist()
        assert wheel.read(marker) == (project / marker).read_bytes()
