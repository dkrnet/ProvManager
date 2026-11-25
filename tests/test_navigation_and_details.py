# SPDX-License-Identifier: AGPL-3.0-only
"""Role-aware navigation and read-only record detail tests."""

from dataclasses import replace
from pathlib import Path

import pytest

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


def test_host_detail_shows_only_its_findings_to_validation_users(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n"
        "  - {id: first, hostname: shared.example, mac_addresses: ['02:00:00:00:00:01'], provisioning_state: unknown}\n"
        "  - {id: second, hostname: shared.example, mac_addresses: []}\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "preview"}))
    action = "action=host_view&id=first"
    response = _dispatch(action, viewer, config)
    assert b"Validation findings" in response.body
    assert b'action=validate&amp;host_id=first' in response.body
    assert b"Provisioning state must be one of" in response.body
    assert b"Hosts, line 3, column" in response.body
    assert b"At least one MAC address is required" not in response.body
    reader = replace(viewer, capabilities=frozenset({"hosts_read"}))
    assert b"Validation findings" not in _dispatch(action, reader, config).body
    scoped = _dispatch("action=validate&host_id=first&severity=error", viewer, config)
    assert b"Provisioning state must be one of" in scoped.body
    assert b"At least one MAC address is required" not in scoped.body
    assert b'name="host_id" value="first"' in scoped.body
    assert _dispatch("action=validate&host_id=missing", viewer, config).status.startswith("404")
    assert _dispatch("action=validate&host_id=first", reader, config).status.startswith("403")


@pytest.mark.parametrize("action, location", [
    ("installer_view", b"Installers"),
    ("role_view", b"Ansible Roles"),
    ("template_view", b"Templates"),
])
def test_catalog_detail_shows_findings_for_its_catalog(tmp_path: Path, action: str, location: bytes) -> None:
    config = _config(tmp_path)
    for path in (config.installers_file, config.roles_file, config.templates_file):
        Path(path).write_text("schema_version: 1\nrecords:\n  - {id: shared, name: Shared, enabled: 'false'}\n", encoding="utf-8")
    reader = Identity("viewer", "Viewer", frozenset(), frozenset({"catalogs_read"}))
    viewer = replace(reader, capabilities=reader.capabilities | {"preview"})
    query = f"action={action}&id=shared"
    body = _dispatch(query, viewer, config).body
    assert b"Validation findings" in body
    assert body.count(b"Enabled must be true or false.") == 1
    assert b"Enabled must be true or false. (" + location + b", line 3, column" in body
    assert b"Validation findings" not in _dispatch(query, reader, config).body


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
    assert b"<img src=x" not in response.body
    assert b"onerror" not in response.body
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


def test_host_detail_links_named_catalog_references_in_role_order(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.installers_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: installer-1, name: Example Linux}\n", encoding="utf-8",
    )
    Path(config.templates_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: template-1, name: Standard Build}\n", encoding="utf-8",
    )
    Path(config.roles_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: role-1, name: Base}\n  - {id: role-2, name: Monitoring}\n", encoding="utf-8",
    )
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - id: host-1\n    hostname: host.example\n    installer_id: installer-1\n    template_id: template-1\n    role_ids: [role-2, role-1]\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read"}))
    response = _dispatch("action=host_view&id=host-1", viewer, config)
    assert b"?action=installer_view&amp;id=installer-1" in response.body
    assert b">Example Linux</a>" in response.body
    assert b"?action=template_view&amp;id=template-1" in response.body
    assert response.body.index(b">Monitoring</a>") < response.body.index(b">Base</a>")


def test_catalog_detail_lists_inbound_dependencies(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.installers_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: installer-1, name: Example Linux}\n", encoding="utf-8",
    )
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: host-1, hostname: host.example, installer_id: installer-1}\n", encoding="utf-8",
    )
    Path(config.templates_file).write_text(
        "schema_version: 1\nrecords:\n  - {id: template-1, name: Standard Build, installer_id: installer-1}\n", encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"catalogs_read", "hosts_read"}))
    response = _dispatch("action=installer_view&id=installer-1", viewer, config)
    assert b"Referenced by" in response.body
    assert b"?action=host_view&amp;id=host-1" in response.body
    assert b"?action=template_view&amp;id=template-1" in response.body
