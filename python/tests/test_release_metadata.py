# SPDX-License-Identifier: Apache-2.0
"""Release metadata stays aligned and capacity arithmetic retains its evidence."""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

import pytest

from maxwells_defense import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_python_javascript_and_runtime_versions_match() -> None:
    """Read the project section without requiring tomllib on Python 3.10."""
    source = (ROOT / "python/pyproject.toml").read_text()
    project = re.search(r"(?ms)^\[project\]\s*\n(.*?)(?=^\[|\Z)", source)
    assert project is not None
    versions = re.findall(r'^version\s*=\s*"([^"]+)"\s*$', project[1], re.MULTILINE)
    assert len(versions) == 1
    javascript = json.loads((ROOT / "javascript/package.json").read_text())
    assert versions[0] == javascript["version"] == __version__


def test_capacity_compute_example_matches_recorded_samples() -> None:
    """The rounded 105-ms sizing example is backed by recorded CPU samples."""
    report = json.loads(
        (ROOT / "docs/benchmarks/2026-10-05-compute.json").read_text()
    )
    samples = report["raw_samples"]
    assert report["source_commit"] == "1b1c347ba03427b1bdd7751ecfe7ce4981f2e653"
    assert report["difficulty"] == 18
    assert len(samples) == report["samples"] == 40
    mean_cpu = statistics.mean(row["solve_process_cpu_seconds"] for row in samples)
    assert report["mean_solve_process_cpu_seconds"] == pytest.approx(mean_cpu)
    assert round(mean_cpu * 1000) == 105
