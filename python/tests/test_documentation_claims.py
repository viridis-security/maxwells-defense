# SPDX-License-Identifier: Apache-2.0
"""WP-2 / INV-V9: public checking claims stay scoped to named evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest


ROOT = Path(__file__).resolve().parents[2]
PUBLIC_SURFACES = (
    "README.md",
    "THEOREMS.md",
    "python/README.md",
    "python/pyproject.toml",
    "python/maxwells_defense/__init__.py",
    "python/maxwells_defense/core.py",
    "javascript/package.json",
)


def test_public_surfaces_do_not_restore_unqualified_proof_claims() -> None:
    """INV-2.1: known inaccurate public/package claims cannot reappear."""
    forbidden = (
        "aristotle-verified",
        "mechanically proved under standard axioms",
        "proven wire-format",
        "spam now pays the energy bill",
        "the defender pays the landauer floor",
        "attacker capturing n protected bits pays",
        "attacker pays exponential energy",
    )
    for relative_path in PUBLIC_SURFACES:
        source = (ROOT / relative_path).read_text().lower()
        for claim in forbidden:
            assert claim not in source, (relative_path, claim)


@pytest.mark.parametrize(
    ("filename", "expected_hash"),
    (
        (
            "statement.lean",
            "b3b1b7358d955449b24b7d9a643d4d0f0ac7606ae3af577a2554a213efece365",
        ),
        (
            "ARISTOTLE_SUMMARY.md",
            "9257704f643d4dcffd5c1ceaf65a6467633057f6d48f28b4847a5c7ac7333fa7",
        ),
    ),
)
def test_historical_evidence_snapshot_is_unchanged(
    filename: str, expected_hash: str
) -> None:
    """INV-2.4: links describe these exact historical bytes, not a fresh run."""
    artifact = ROOT / "docs/artifacts/t-ib-09" / filename
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_hash


def test_axiom_and_explicit_hypotheses_match_the_public_explanation() -> None:
    """INV-2.3: source declarations support the scoped status and table."""
    source = (ROOT / "docs/artifacts/t-ib-09/statement.lean").read_text()
    assert re.findall(r"^axiom (\w+)", source, re.MULTILINE) == [
        "asymmetric_defense_property"
    ]
    assert len(re.findall(r"^theorem \w+", source, re.MULTILINE)) == 4
    for hypothesis in ("h_def", "h_per_request", "h_amp", "h_M_large"):
        assert f"({hypothesis} :" in source
    assert "Aristotle status: STUB" in source
    assert "EXPECTED ARISTOTLE OUTCOMES" in source

    theorems = (ROOT / "THEOREMS.md").read_text()
    assert "one declared external axiom" in theorems
    assert "none invokes the declared axiom" in theorems
    assert "No fresh Lean or Aristotle check" in theorems
    assert "classical distinct queries" in theorems
    assert "modeling SHA-256 as a random oracle" in theorems
    assert "min(1, q / 2^d)" in theorems
    assert "not a Lean-mechanized result" in theorems


def test_local_claim_and_artifact_links_resolve() -> None:
    """INV-2.4: public claim links point to real files and section anchors."""
    documents = (
        "README.md",
        "THEOREMS.md",
        "python/README.md",
        "docs/artifacts/t-ib-09/README.md",
    )
    for relative_path in documents:
        document = ROOT / relative_path
        for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
            link = urlparse(target)
            if link.scheme or link.netloc:
                continue
            destination = (document.parent / unquote(link.path)).resolve()
            assert destination.is_file(), (relative_path, target)
            if link.fragment:
                contents = destination.read_text()
                explicit_anchors = re.findall(r'<a id="([^"]+)">', contents)
                headings = re.findall(r"^#+ (.+)$", contents, re.MULTILINE)
                heading_anchors = [
                    re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
                    for heading in headings
                ]
                assert link.fragment in explicit_anchors + heading_anchors, (
                    relative_path,
                    target,
                )
