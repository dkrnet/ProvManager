# SPDX-License-Identifier: AGPL-3.0-only
"""Validation summary, filtering, styling, and record-link tests."""

from dataclasses import replace
from pathlib import Path

from provmanager import Config, Identity, dispatch


VIEWER = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read", "preview"}))


def _config(tmp_path: Path) -> Config:
    paths = {}
    for field in ("hosts_file", "installers_file", "roles_file", "templates_file"):
        path = tmp_path / (field + ".yaml")
        path.write_text("schema_version: 1\nrecords: []\n", encoding="utf-8")
        paths[field] = str(path)
    return replace(Config(), **paths)


def _request(config: Config, query: str = ""):
    return dispatch(
        {"QUERY_STRING": "action=validate&" + query, "REMOTE_USER": "viewer"},
        config=config,
        identity_resolver=lambda username, active: VIEWER,
    )


def test_validation_navigation_is_visible_to_preview_role(tmp_path: Path) -> None:
    response = _request(_config(tmp_path))
    assert b'<a href="?action=validate">Validate</a>' in response.body


def test_validation_summary_and_severity_styles(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: host-1, hostname: bad_name, mac_addresses: []}\n",
        encoding="utf-8",
    )
    response = _request(config)
    assert b"severity severity-error" in response.body
    assert b"Errors</span>" in response.body
    assert b"severity severity-warning" in response.body
    assert b"severity severity-information" in response.body


def test_validation_resource_links_to_matching_record(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: host-1, hostname: bad_name, mac_addresses: []}\n",
        encoding="utf-8",
    )
    response = _request(config)
    assert b'?action=host_view&amp;id=host-1' in response.body
    assert b">bad_name</a>" in response.body


def test_validation_filters_by_severity_and_resource(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: host-1, hostname: bad_name, mac_addresses: []}\n",
        encoding="utf-8",
    )
    no_warnings = _request(config, "severity=warning")
    assert b"0 matching finding(s)" in no_warnings.body
    assert b"No validation findings match" in no_warnings.body
    matching = _request(config, "severity=error&resource=bad_name")
    assert b"matching finding(s)" in matching.body
    assert b"Hostname is not a valid DNS name" in matching.body


def test_validation_filters_are_escaped_and_read_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    tracked = [Path(config.hosts_file), Path(config.installers_file), Path(config.roles_file), Path(config.templates_file)]
    before = {path: path.read_bytes() for path in tracked}
    response = _request(config, "resource=%22%3E%3Cscript%3E")
    assert b'&quot;&gt;&lt;script&gt;' in response.body
    assert b'"><script>' not in response.body
    assert {path: path.read_bytes() for path in tracked} == before
