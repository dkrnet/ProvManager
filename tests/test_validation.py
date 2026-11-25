# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only record, relationship, and path validation tests."""

from dataclasses import replace
from pathlib import Path

from provmanager import Config, Identity, dispatch, validate_catalogs


def _catalog(path: Path, records: str) -> None:
    path.write_text("schema_version: 1\nrecords:\n" + records, encoding="utf-8")


def _config(tmp_path: Path) -> Config:
    ansible = tmp_path / "ansible"
    kickstart = tmp_path / "kickstart"
    tftp = tmp_path / "tftp"
    ansible.mkdir()
    kickstart.mkdir()
    tftp.mkdir()
    hosts = tmp_path / "hosts.yaml"
    installers = tmp_path / "installers.yaml"
    roles = tmp_path / "roles.yaml"
    templates = tmp_path / "templates.yaml"
    for path in (hosts, installers, roles, templates):
        _catalog(path, " []\n")
    return replace(
        Config(), hosts_file=str(hosts), installers_file=str(installers), roles_file=str(roles), templates_file=str(templates),
        ansible_root=str(ansible), kickstart_root=str(kickstart), tftp_root=str(tftp),
    )


def test_valid_empty_catalogs_produce_information_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = validate_catalogs(config)
    assert [(item.severity, item.message) for item in findings] == [("information", "No validation findings were reported.")]


def test_invalid_hosts_yaml_finding_reports_parser_location(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords: [private-value}\n", encoding="utf-8"
    )
    finding, = validate_catalogs(config)
    assert finding.resource == "Hosts"
    assert "line 2, column 24" in finding.message
    assert "private-value" not in finding.message


def test_common_catalog_field_validation(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), max_description_chars=5)
    _catalog(
        Path(config.roles_file),
        f"  - {{id: a, name: Invalid, role_path: '{config.ansible_root}', description: [], enabled: 'false'}}\n"
        f"  - {{id: b, name: Long, role_path: '{config.ansible_root}', description: longer, enabled: false}}\n"
        f"  - {{id: c, name: Legacy, role_path: '{config.ansible_root}', description: short}}\n",
    )
    assert [(item.resource, item.message) for item in validate_catalogs(config)] == [
        ("Invalid", "Description must be text."),
        ("Invalid", "Enabled must be true or false."),
        ("Long", "Description exceeds the configured character limit."),
    ]


def test_common_catalog_metadata_validation(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _catalog(
        Path(config.roles_file),
        f"  - {{id: a, name: Valid, role_path: '{config.ansible_root}', "
        "created_at: 2026-01-01T12:00:00Z, updated_at: '2026-01-01T13:00:00+00:00', created_by: admin}\n"
        f"  - {{id: b, name: Invalid, role_path: '{config.ansible_root}', "
        "created_at: 2026-01-01, updated_at: '2026-01-01T13:00:00+01:00', created_by: ' ', updated_by: []}\n",
    )
    assert [(item.resource, item.message.split()[0]) for item in validate_catalogs(config)] == [
        ("Invalid", field) for field in ("created_at", "updated_at", "created_by", "updated_by")
    ]


def test_host_validation_reports_invalid_fields_and_references(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _catalog(
        Path(config.hosts_file),
        "  - id: host-1\n    hostname: bad_name\n    mac_addresses: ['not-a-mac']\n    ipv4_address: 999.1.1.1\n    installer_id: missing\n    role_ids: [missing, missing]\n",
    )
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Hostname is not a valid DNS name." in messages
    assert "A MAC address is invalid." in messages
    assert "IPV4 ADDRESS is invalid." in messages
    assert "Referenced installer does not exist." in messages
    assert "Role references must be an ordered list without duplicates." in messages


def test_template_validation_reports_invalid_installer_and_role_references(tmp_path: Path) -> None:
    config = _config(tmp_path)
    content = Path(config.kickstart_root) / "missing-references.ks"
    content.write_text("# test template\n", encoding="utf-8")
    _catalog(
        Path(config.templates_file),
        "  - id: template-1\n"
        "    name: Missing references\n"
        "    template_type: kickstart\n"
        "    content_path: '" + str(content) + "'\n"
        "    installer_id: missing-installer\n"
        "    role_ids: [missing-role]\n",
    )
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Referenced installer does not exist." in messages
    assert "A referenced role does not exist." in messages


def test_template_validation_reports_duplicate_and_missing_role_references(tmp_path: Path) -> None:
    config = _config(tmp_path)
    content = Path(config.kickstart_root) / "duplicate-roles.ks"
    content.write_text("# test template\n", encoding="utf-8")
    _catalog(
        Path(config.templates_file),
        "  - id: template-1\n"
        "    name: Duplicate roles\n"
        "    template_type: kickstart\n"
        "    content_path: '" + str(content) + "'\n"
        "    role_ids: [missing-role, missing-role]\n",
    )
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Role references must be an ordered list without duplicates." in messages
    assert "A referenced role does not exist." in messages


def test_role_symlink_escape_is_rejected(tmp_path: Path) -> None:
    config = _config(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = Path(config.ansible_root) / "escaped"
    link.symlink_to(outside, target_is_directory=True)
    _catalog(Path(config.roles_file), "  - {id: role-1, name: escaped, role_path: '" + str(link) + "'}\n")
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Role path is outside the approved Ansible root." in messages


def test_validate_route_is_read_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    tracked = [Path(config.hosts_file), Path(config.installers_file), Path(config.roles_file), Path(config.templates_file)]
    before = {path: path.read_bytes() for path in tracked}
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"preview"}))
    response = dispatch(
        {"QUERY_STRING": "action=validate", "REMOTE_USER": "viewer"},
        config=config,
        identity_resolver=lambda username, active: viewer,
    )
    assert response.status == "200 OK"
    assert b"Read-only validation; no files were changed" in response.body
    assert {path: path.read_bytes() for path in tracked} == before


def test_validate_route_requires_preview_capability(tmp_path: Path) -> None:
    config = _config(tmp_path)
    reader = Identity("reader", "Reader", frozenset(), frozenset({"hosts_read"}))
    response = dispatch(
        {"QUERY_STRING": "action=validate", "REMOTE_USER": "reader"},
        config=config,
        identity_resolver=lambda username, active: reader,
    )
    assert response.status == "403 Forbidden"


def test_malformed_role_reference_type_is_reported_not_raised(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _catalog(
        Path(config.hosts_file),
        "  - id: host-1\n    hostname: host.example\n    mac_addresses: ['02:00:00:00:00:01']\n    role_ids: [{bad: value}]\n",
    )
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Role references must be an ordered list without duplicates." in messages


def test_disabled_host_does_not_reserve_network_identifiers(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _catalog(
        Path(config.hosts_file),
        "  - {id: old, hostname: old.example, mac_addresses: ['02:00:00:00:00:01'], ipv4_address: 192.0.2.1, enabled: false}\n"
        "  - {id: new, hostname: new.example, mac_addresses: ['02:00:00:00:00:01'], ipv4_address: 192.0.2.1, enabled: true}\n",
    )
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "A MAC address is already used by another enabled host." not in messages
    assert "An IP address is already used by another enabled host." not in messages


def test_installer_path_inside_configured_root_has_no_allowlist_finding(tmp_path: Path) -> None:
    config = _config(tmp_path)
    root = tmp_path / "installers"
    source = root / "rocky9"
    source.mkdir(parents=True)
    config = replace(config, installer_roots=(str(root),))
    _catalog(Path(config.installers_file), "  - {id: installer-1, name: Rocky 9, source_type: tree, source_path: '" + str(source) + "'}\n")
    messages = [finding.message for finding in validate_catalogs(config)]
    assert not any("installer-root allowlist" in message for message in messages)
    assert "Installer source path is outside the approved installer roots." not in messages


def test_installer_path_outside_configured_root_is_error(tmp_path: Path) -> None:
    config = _config(tmp_path)
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    config = replace(config, installer_roots=(str(root),))
    _catalog(Path(config.installers_file), "  - {id: installer-1, name: Outside, source_type: tree, source_path: '" + str(outside) + "'}\n")
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Installer source path is outside the approved installer roots." in messages


def test_installer_symlink_cannot_escape_configured_root(tmp_path: Path) -> None:
    config = _config(tmp_path)
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "escaped"
    link.symlink_to(outside, target_is_directory=True)
    config = replace(config, installer_roots=(str(root),))
    _catalog(Path(config.installers_file), "  - {id: installer-1, name: Escaped, source_type: tree, source_path: '" + str(link) + "'}\n")
    messages = [finding.message for finding in validate_catalogs(config)]
    assert "Installer source path is outside the approved installer roots." in messages
