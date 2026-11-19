# SPDX-License-Identifier: AGPL-3.0-only
"""Sample configuration and source-preserving build tests."""

import os
import subprocess
from dataclasses import fields
from pathlib import Path

from provmanager import Config


ROOT = Path(__file__).resolve().parents[1]


def test_sample_configuration_contains_every_supported_key() -> None:
    configured = {
        line.split("=", 1)[0]
        for line in (ROOT / "provmanager.conf.example").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    expected = {field.name.upper() for field in fields(Config)}
    assert configured == expected


def test_build_stamps_copy_without_modifying_source(tmp_path: Path) -> None:
    source_before = (ROOT / "provmanager.py").read_bytes()
    environment = os.environ.copy()
    environment["PROVMANAGER_BUILD_DIR"] = str(tmp_path / "output")
    environment["GIT"] = "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
    result = subprocess.run(
        [str(ROOT / "build.sh")], cwd=str(ROOT), env=environment,
        check=True, capture_output=True, text=True, timeout=10,
    )
    built = (tmp_path / "output" / "provmanager.py").read_text(encoding="utf-8")
    assert "PROVMANAGER_VERSION = \"1.0.0-dev." in built
    assert (ROOT / "provmanager.py").read_bytes() == source_before
    assert "Built ProvManager" in result.stdout


def test_release_build_uses_release_version_form(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["PROVMANAGER_BUILD_DIR"] = str(tmp_path / "release")
    environment["GIT"] = "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
    subprocess.run(
        [str(ROOT / "build.sh"), "--release"], cwd=str(ROOT), env=environment,
        check=True, capture_output=True, text=True, timeout=10,
    )
    built = (tmp_path / "release" / "provmanager.py").read_text(encoding="utf-8")
    assignment = next(line for line in built.splitlines() if line.startswith("PROVMANAGER_VERSION = "))
    assert assignment.startswith("PROVMANAGER_VERSION = \"1.0.0+")
    assert "-dev." not in assignment
