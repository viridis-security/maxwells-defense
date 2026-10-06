# SPDX-License-Identifier: Apache-2.0
"""INV-4.5: build the actual wheel and inspect its typing marker."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest


def _copy_build_source(project: Path, source: Path) -> None:
    shutil.copytree(
        project,
        source,
        ignore=shutil.ignore_patterns(
            "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache", ".venv"
        ),
    )


def _build_wheel(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    """Ask pip to create its own build environment from declared requirements."""
    environment = os.environ.copy()
    # pip's store_false option parses environment "true" as build_isolation=1.
    # Override ambient opt-outs while retaining index/network configuration.
    environment["PIP_NO_BUILD_ISOLATION"] = "true"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(output),
            str(source),
        ],
        cwd=source,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _require_build_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode == 0:
        return
    log = result.stdout + result.stderr
    dependency_install_failed = re.search(
        r"installing build dependencies(?:\s*\.\.\.\s*error|"
        r": finished with status ['\"]error['\"]| did not run successfully)"
        r"|pip subprocess to install build dependencies did not run successfully",
        log,
        re.IGNORECASE,
    )
    unavailable = re.search(
        r"NewConnectionError|NameResolutionError|ReadTimeoutError|ConnectTimeout"
        r"|Temporary failure in name resolution|Network is unreachable"
        r"|Connection refused|certificate verify failed"
        r"|(?:Could not find a version that satisfies the requirement|"
        r"No matching distribution found for) (?:setuptools>=64|wheel)(?=\s|$|\()",
        log,
        re.IGNORECASE,
    )
    if dependency_install_failed and unavailable:
        pytest.skip(
            "Isolated wheel build unavailable: pip could not fetch the declared "
            "setuptools/wheel build backend dependencies from the configured "
            "index (network access or packages unavailable); no wheel inspected."
        )
    pytest.fail(f"Isolated wheel build failed:\n{log}")


def _assert_typing_marker(output: Path, project: Path) -> None:
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1, "expected exactly one built wheel"
    with ZipFile(wheels[0]) as wheel:
        marker = "maxwells_defense/py.typed"
        assert marker in wheel.namelist(), f"built wheel is missing {marker}"
        assert wheel.read(marker) == (project / marker).read_bytes()


def test_built_wheel_contains_typing_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PIP_NO_BUILD_ISOLATION", "false")
    project = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    _copy_build_source(project, source)
    output = tmp_path / "wheels"
    output.mkdir()
    _require_build_success(_build_wheel(source, output))
    _assert_typing_marker(output, project)


def test_build_source_does_not_copy_project_virtualenv(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".venv" / "bin").mkdir(parents=True)
    (project / ".venv" / "bin" / "python").write_text("ambient interpreter")
    (project / "pyproject.toml").write_text("declared build configuration")
    source = tmp_path / "source"
    _copy_build_source(project, source)
    assert (source / "pyproject.toml").read_text() == "declared build configuration"
    assert not (source / ".venv").exists()


def test_wheel_command_uses_pip_build_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, output = tmp_path / "source", tmp_path / "wheels"
    observed = []
    original_run = subprocess.run
    index_url = "https://packages.invalid/simple"
    configuration = tmp_path / "pip.conf"
    configuration.write_text("[global]\nno-build-isolation = false\n")
    monkeypatch.setenv("PIP_CONFIG_FILE", str(configuration))
    monkeypatch.setenv("PIP_NO_BUILD_ISOLATION", "false")
    monkeypatch.setenv("PIP_INDEX_URL", index_url)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    _build_wheel(source, output)
    command, options = observed[0]
    assert command == [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "--wheel-dir",
        str(output),
        str(source),
    ]
    assert options["cwd"] == source
    assert options["check"] is False
    environment = options["env"]
    assert environment["PIP_NO_BUILD_ISOLATION"] == "true"
    assert environment["PIP_INDEX_URL"] == index_url
    assert environment["PIP_CONFIG_FILE"] == str(configuration)
    assert os.environ["PIP_NO_BUILD_ISOLATION"] == "false"
    # Parse the exact child environment with pip itself; this invokes no index
    # requests and catches changes to its counterintuitive boolean handling.
    parsed = original_run(
        [
            sys.executable,
            "-c",
            (
                "import json; from pip._internal.commands import create_command; "
                "options, _ = create_command('wheel').parse_args(['--no-deps', '.']); "
                "print(json.dumps({'isolation': options.build_isolation, "
                "'index_url': options.index_url}))"
            ),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(parsed.stdout) == {"isolation": True, "index_url": index_url}


@pytest.mark.parametrize(
    "unavailable",
    (
        "NewConnectionError: failed to establish a new connection",
        "NameResolutionError: Temporary failure in name resolution",
        "ReadTimeoutError: package index did not respond",
        "SSLError: certificate verify failed",
        (
            "Could not find a version that satisfies the requirement setuptools>=64 "
            "(from versions: none)"
        ),
        "No matching distribution found for wheel",
    ),
)
def test_unavailable_isolated_build_dependencies_skip(unavailable: str) -> None:
    result = subprocess.CompletedProcess(
        [], 1, "Installing build dependencies ... error\n", unavailable
    )
    with pytest.raises(pytest.skip.Exception, match="build backend dependencies"):
        _require_build_success(result)


def test_verbose_dependency_install_failure_is_recognized() -> None:
    result = subprocess.CompletedProcess(
        [],
        1,
        "Installing build dependencies: finished with status 'error'\n",
        "Network is unreachable",
    )
    with pytest.raises(pytest.skip.Exception, match="build backend dependencies"):
        _require_build_success(result)


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    (
        (
            "Installing build dependencies ... done\nBuilding wheel ... error\n",
            "FileNotFoundError: README.md",
        ),
        (
            "Installing build dependencies ... error\n",
            "Invalid requirement: setuptools=>64",
        ),
        (
            "Installing build dependencies ... error\n",
            "No matching distribution found for misspelled-build-backend",
        ),
        (
            "Installing build dependencies ... done\nBuilding wheel ... error\n",
            "Network is unreachable inside a faulty custom backend",
        ),
    ),
)
def test_packaging_defects_fail_instead_of_skipping(stdout: str, stderr: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="Isolated wheel build failed"):
        _require_build_success(subprocess.CompletedProcess([], 1, stdout, stderr))


def test_successful_build_does_not_skip_previous_index_warning() -> None:
    _require_build_success(
        subprocess.CompletedProcess([], 0, "", "NewConnectionError before retry")
    )


def test_successful_wheel_without_typing_marker_fails(tmp_path: Path) -> None:
    output = tmp_path / "wheels"
    output.mkdir()
    with ZipFile(output / "fixture.whl", "w") as wheel:
        wheel.writestr("maxwells_defense/__init__.py", "")
    _require_build_success(subprocess.CompletedProcess([], 0, "", ""))
    with pytest.raises(AssertionError, match="missing maxwells_defense/py.typed"):
        _assert_typing_marker(output, tmp_path)
