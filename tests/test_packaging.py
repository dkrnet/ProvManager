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


def test_apache_example_uses_isolated_login_and_scoped_session_settings() -> None:
    example = (ROOT / "provmanager-form-auth.conf.example").read_text(encoding="utf-8")
    first_location = example.index("<Location ")
    assert '<Location "/provmanager-login">' in example
    assert '<Location "/login">' not in example
    assert "Session On" not in example[:first_location]
    assert example.count("SessionCookieName provmanager_session") == 3
    assert example.count("SessionMaxAge 28800") == 3


def test_selinux_example_grants_only_read_access_to_tftp_content() -> None:
    example = (ROOT / "provmanager-tftp-read.te.example").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "allow httpd_sys_script_t tftpdir_rw_t:dir" in example
    assert "allow httpd_sys_script_t tftpdir_rw_t:file" in example
    assert "allow httpd_sys_script_t tftpdir_rw_t:lnk_file" in example
    assert "module provmanager_tftp_read 1.0;" in example
    assert "checkmodule -M -m -o provmanager_tftp_read.mod provmanager_tftp_read.te" in readme
    assert "semodule_package -o provmanager_tftp_read.pp -m provmanager_tftp_read.mod" in readme
    assert "sudo semodule -i provmanager_tftp_read.pp" in readme
    for permission in ("create", "write", "append", "rename", "unlink"):
        assert permission not in example


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
    assert (tmp_path / "output" / "provmanager-form-auth.conf.example").is_file()
    assert (tmp_path / "output" / "provmanager-tftp-read.te.example").is_file()
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
