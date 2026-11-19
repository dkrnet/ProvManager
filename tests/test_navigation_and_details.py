# SPDX-License-Identifier: AGPL-3.0-only
"""Role-aware navigation and read-only record detail tests."""

from dataclasses import replace
from pathlib import Path

from provmanager import Config, Identity, dispatch


def _config(tmp_path: Path) -> Config:
    paths = {}
    for field in ("hosts_file", "installers_file", "roles_file", "templates_file"):
        path = tmp_path / (field + ".yaml")
        path.write_text("schema_version: 1\nrecords: []\n", encoding="utf-8")
        paths[field] = str(path)
    return replace(Config(), **paths)


def _dispatch(action: str, identity: Identity, config: Config):
    return dispatch(
        {"QUERY_STRING": action, "REMOTE_USER": identity.username},
        config=config,
        identity_resolver=lambda username, active: identity,
    )


def test_viewer_navigation_excludes_privileged_destinations(tmp_path: Path) -> None:
    config = _config(tmp_path)
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read", "preview"}))
    response = _dispatch("action=hosts", viewer, config)
    assert b">Hosts</a>" in response.body
    assert b">Installers</a>" in response.body
    assert b">Settings</a>" not in response.body
    assert b">Audit Log</a>" not in response.body


def test_auditor_navigation_includes_settings_and_audit(tmp_path: Path) -> None:
    config = _config(tmp_path)
    auditor = Identity("auditor", "Auditor", frozenset(), frozenset({"hosts_read", "catalogs_read", "settings_read", "audit_read"}))
    response = _dispatch("action=hosts", auditor, config)
    assert b">Settings</a>" in response.body
    assert b">Audit Log</a>" in response.body
    assert b">Operations</a>" not in response.body


def test_list_name_links_to_stable_record_id(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: host-001, hostname: example.test}\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read"}))
    response = _dispatch("action=hosts", viewer, config)
    assert b"?action=host_view&amp;id=host-001" in response.body


def test_detail_page_escapes_all_values_and_is_read_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    path = Path(config.hosts_file)
    path.write_text(
        "schema_version: 1\nrecords:\n  - id: host-001\n    hostname: example.test\n    description: '<img src=x onerror=alert(1)>'\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read"}))
    response = _dispatch("action=host_view&id=host-001", viewer, config)
    assert response.status == "200 OK"
    assert b"&lt;img src=x onerror=alert(1)&gt;" in response.body
    assert b"<img src=x" not in response.body
    assert path.read_bytes() == before


def test_missing_detail_id_is_bad_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read"}))
    assert _dispatch("action=host_view", viewer, config).status == "400 Bad Request"


def test_unknown_detail_id_is_not_found(tmp_path: Path) -> None:
    config = _config(tmp_path)
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read"}))
    assert _dispatch("action=host_view&id=missing", viewer, config).status == "404 Not Found"


def test_direct_catalog_detail_requires_catalog_permission(tmp_path: Path) -> None:
    config = _config(tmp_path)
    host_only = Identity("user", "User", frozenset(), frozenset({"hosts_read"}))
    response = _dispatch("action=installer_view&id=installer-1", host_only, config)
    assert response.status == "403 Forbidden"


def test_detail_page_redacts_sensitive_keys(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - id: host-001\n    hostname: example.test\n    api_token: do-not-display\n    variables:\n      admin_password: also-hidden\n      locale: en_US\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read"}))
    response = _dispatch("action=host_view&id=host-001", viewer, config)
    assert b"do-not-display" not in response.body
    assert b"also-hidden" not in response.body
    assert response.body.count(b"[redacted]") == 2
    assert b"locale=en_US" in response.body
