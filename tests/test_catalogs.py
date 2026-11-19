# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only safe catalog loading and presentation tests."""

from dataclasses import replace
from pathlib import Path

import pytest

from provmanager import CatalogError, Config, Identity, dispatch, load_catalog


VIEWER = Identity("viewer", "Viewer", frozenset({"provisioning_viewer"}), frozenset({"hosts_read", "catalogs_read"}))


def _identity(_username: str, _config: Config) -> Identity:
    return VIEWER


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_load_catalog_requires_versioned_mapping(tmp_path: Path) -> None:
    path = tmp_path / "hosts.yaml"
    _write(path, "- id: host-1\n")
    with pytest.raises(CatalogError, match="versioned mapping"):
        load_catalog(str(path))


def test_load_catalog_rejects_unsafe_yaml_tag(tmp_path: Path) -> None:
    path = tmp_path / "hosts.yaml"
    _write(path, "!!python/object/apply:os.system ['echo unsafe']\n")
    with pytest.raises(CatalogError, match="invalid YAML"):
        load_catalog(str(path))


def test_load_catalog_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = tmp_path / "hosts.yaml"
    _write(path, "schema_version: 1\nrecords:\n  - {id: duplicate}\n  - {id: duplicate}\n")
    with pytest.raises(CatalogError, match="duplicate record IDs"):
        load_catalog(str(path))


def test_host_list_is_sorted_and_escaped(tmp_path: Path) -> None:
    path = tmp_path / "hosts.yaml"
    _write(
        path,
        "schema_version: 1\nrecords:\n"
        "  - {id: h2, hostname: zeta.example, enabled: true}\n"
        "  - {id: h1, hostname: '<script>alert(1)</script>', enabled: false}\n",
    )
    config = replace(Config(), hosts_file=str(path))
    before = path.read_bytes()
    response = dispatch(
        {"QUERY_STRING": "action=hosts", "REMOTE_USER": "viewer"},
        config=config,
        identity_resolver=_identity,
    )
    assert response.status == "200 OK"
    assert b"&lt;script&gt;" in response.body
    assert b"<script>alert" not in response.body
    assert response.body.index(b"&lt;script&gt;") < response.body.index(b"zeta.example")
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "action,path_field,capability,title",
    [
        ("installers", "installers_file", "catalogs_read", b"Installers"),
        ("roles", "roles_file", "catalogs_read", b"Ansible Roles"),
        ("templates", "templates_file", "catalogs_read", b"Templates"),
    ],
)
def test_catalog_lists_read_isolated_files(tmp_path: Path, action: str, path_field: str, capability: str, title: bytes) -> None:
    path = tmp_path / (action + ".yaml")
    _write(path, "schema_version: 1\nrecords: []\n")
    config = replace(Config(), **{path_field: str(path)})
    identity = Identity("reader", "Reader", frozenset(), frozenset({capability}))
    response = dispatch(
        {"QUERY_STRING": "action=" + action, "REMOTE_USER": "reader"},
        config=config,
        identity_resolver=lambda username, active: identity,
    )
    assert response.status == "200 OK"
    assert title in response.body
    assert b"0 matching record(s)" in response.body


def test_missing_catalog_is_safe_error_not_empty_data(tmp_path: Path) -> None:
    config = replace(Config(), hosts_file=str(tmp_path / "missing.yaml"))
    response = dispatch(
        {"QUERY_STRING": "action=hosts", "REMOTE_USER": "viewer"},
        config=config,
        identity_resolver=_identity,
    )
    assert response.status == "500 Internal Server Error"
    assert b"not available" in response.body
    assert b"No hosts are configured" not in response.body
