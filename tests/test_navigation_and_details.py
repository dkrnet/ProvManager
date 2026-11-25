# SPDX-License-Identifier: AGPL-3.0-only
"""Role-aware navigation and read-only record detail tests."""

from dataclasses import replace
from pathlib import Path

import pytest

from provmanager import Config, Finding, Identity, dispatch, load_catalog


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
    assert b">Inventory preview</a>" not in response.body
    assert b">Settings</a>" not in response.body
    assert b">Audit Log</a>" not in response.body


def test_roles_list_offers_inventory_preview_to_authorized_users(tmp_path: Path) -> None:
    config = _config(tmp_path)
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read", "preview"}))
    link = b'<p><a href="?action=preview">Inventory preview</a></p>'
    body = _dispatch("action=roles", viewer, config).body
    assert body.index(link) < body.index(b"<table")
    reader = replace(viewer, capabilities=viewer.capabilities - {"hosts_read"})
    assert link not in _dispatch("action=roles", reader, config).body


def test_inventory_preview_filters_hosts_and_keeps_output_untouched(tmp_path: Path, monkeypatch) -> None:
    config = replace(_config(tmp_path), inventory_output_file=str(tmp_path / "inventory.yml"))
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords:\n"
        "  - {id: b, hostname: beta.example, provisioning_state: staged, inventory_groups: [web]}\n"
        "  - {id: a, hostname: alpha.example, provisioning_state: ready, ipv4_address: 192.0.2.10, inventory_groups: [web, linux], inventory_variables: {site: lab, api_token: hidden-value}, variables: {token: private-value}}\n"
        "  - {id: c, hostname: disabled.example, provisioning_state: ready, enabled: false, inventory_groups: [disabled_group]}\n"
        "  - {id: d, hostname: draft.example}\n"
        "  - {id: e, hostname: invalid.example, provisioning_state: ready}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("provmanager._validated_catalog_snapshot", lambda config: (
        {"hosts": load_catalog(config.hosts_file)},
        [
            Finding("error", "invalid.example", "Invalid host", catalog="hosts", record_id="e"),
            Finding("warning", "alpha.example", "Installer warning", catalog="hosts", record_id="a"),
        ],
    ))
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "preview"}))
    response = _dispatch("action=preview", viewer, config)
    assert response.status == "200 OK"
    assert b"2 included, 3 excluded" in response.body
    included_hosts = response.body.split(b"<h2>Included hosts</h2>", 1)[1].split(b"<h2>Excluded hosts</h2>", 1)[0]
    assert b'<a href="?action=host_view&amp;id=a">alpha.example</a>' in included_hosts
    assert b"linux, web" in included_hosts
    assert b'href="?action=validate&amp;host_id=a&amp;severity=warning">View validation warnings</a>' in included_hosts
    assert b"disabled.example" not in included_hosts
    inventory = response.body.split(b"<pre>", 1)[1].split(b"</pre>", 1)[0]
    assert inventory == (
        b"all:\n  hosts:\n    alpha.example:\n      ansible_host: 192.0.2.10\n"
        b"      api_token: &#x27;[redacted]&#x27;\n      site: lab\n    beta.example: {}\n"
        b"  children:\n    linux:\n      hosts:\n        alpha.example: {}\n"
        b"    web:\n      hosts:\n        alpha.example: {}\n        beta.example: {}\n"
    )
    assert b"Has validation errors" in response.body
    assert b'href="?action=validate&amp;host_id=e&amp;severity=error">View validation errors</a>' in response.body
    assert response.body.count(b">View validation errors</a>") == 1
    assert b"Provisioning state must be ready or staged" in response.body
    assert b"private-value" not in response.body
    assert b"hidden-value" not in response.body
    assert not Path(config.inventory_output_file).exists()
    filtered = _dispatch("action=preview&group=linux", viewer, config).body
    assert b'<option value="linux" selected>linux</option>' in filtered
    assert b"1 included, 0 excluded" in filtered
    assert b"alpha.example" in filtered and b"beta.example" not in filtered
    disabled = _dispatch("action=preview&group=disabled_group", viewer, config).body
    assert b"0 included, 1 excluded" in disabled
    assert b"disabled.example</a> " in disabled
    assert b"The requested inventory group was not found." in _dispatch("action=preview&group=unknown", viewer, config).body
    assert _dispatch("action=preview", replace(viewer, capabilities=frozenset({"preview"})), config).status.startswith("403")


@pytest.mark.parametrize("query", [
    "action=preview", "action=validate", "action=validate&host_id=only",
    "action=hosts", "action=host_view&id=only",
])
def test_catalog_views_with_validation_read_each_catalog_once(tmp_path: Path, monkeypatch, query: str) -> None:
    config = _config(tmp_path)
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords: [{id: only, hostname: only.example, mac_addresses: ['02:00:00:00:00:01']}]\n",
        encoding="utf-8",
    )
    reads = []

    def track_load(path, locations=None):
        reads.append(path)
        return load_catalog(path, locations)

    monkeypatch.setattr("provmanager.load_catalog", track_load)
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "preview"}))
    response = _dispatch(query, viewer, config)
    assert response.status == "200 OK"
    assert reads == [config.hosts_file, config.installers_file, config.roles_file, config.templates_file]


def test_template_detail_lists_variable_requirements_and_default_availability(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.templates_file).write_text(
        "schema_version: 1\nrecords:\n"
        "  - {id: setup, name: Setup, allowed_variables: [site, flag], "
        "required_variables: [site], variable_defaults: {flag: false}}\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"catalogs_read", "preview"}))
    body = _dispatch("action=template_view&id=setup", viewer, config).body
    assert b"<h2>Template variables</h2>" in body
    assert b"<code>site</code></th><td>Yes</td><td>No</td>" in body
    assert b"<code>flag</code></th><td>No</td><td>Yes</td>" in body


def test_rendered_template_preview_is_allowlisted_escaped_and_authorized(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), kickstart_root=str(tmp_path))
    source = tmp_path / "setup.ks"
    source.write_text("{{ site }} {{ count }} {{ api_token }}", encoding="utf-8")
    Path(config.hosts_file).write_text("schema_version: 1\nrecords: [{id: host, template_id: setup, variables: {site: '<lab>', api_token: private-value}}]\n", encoding="utf-8")
    Path(config.templates_file).write_text(
        f"schema_version: 1\nrecords: [{{id: setup, name: Setup, template_type: kickstart, content_path: '{source}', allowed_variables: [site, count, api_token], variable_defaults: {{site: default, count: 0}}}}]\n",
        encoding="utf-8",
    )
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read", "preview"}))
    query = "action=template_preview&host_id=host&template_id=setup"
    assert b"Preview selected template" in _dispatch("action=host_view&id=host", viewer, config).body
    response = _dispatch(query, viewer, config)
    assert response.status == "200 OK"
    assert b"<pre>&lt;lab&gt; 0 [redacted]</pre>" in response.body
    assert b"private-value" not in response.body
    assert _dispatch(query, replace(viewer, capabilities=frozenset({"preview"})), config).status.startswith("403")
    source.write_text("{{ site.upper() }}", encoding="utf-8")
    assert b"Unsupported template syntax" in _dispatch(query, viewer, config).body
    source.write_text("{{ missing }}", encoding="utf-8")
    assert b"is not allowlisted" in _dispatch(query, viewer, config).body
    scoped = "action=validate&catalog=templates&record_id=setup"
    source.write_text("# template\n{{ missing }}", encoding="utf-8")
    finding = b"Template variable missing is not allowlisted (source line 2, column 1)."
    assert finding in _dispatch(scoped, viewer, config).body
    assert finding in _dispatch("action=validate", viewer, config).body
    assert finding in _dispatch("action=template_view&id=setup", viewer, config).body
    source.write_text("# template\n{{ missing }}\n  {% unsupported %}", encoding="utf-8")
    body = _dispatch(scoped, viewer, config).body
    assert finding in body
    assert b"Unsupported template syntax at source line 3, column 3." in body
    assert body.count(b"Unsupported template syntax at") == 1
    source.write_text("{{ site }}", encoding="utf-8")
    assert b"No validation findings match" in _dispatch(scoped, viewer, config).body


def test_template_detail_offers_preview_for_associated_hosts(tmp_path: Path) -> None:
    config = _config(tmp_path)
    Path(config.templates_file).write_text(
        "schema_version: 1\nrecords: [{id: setup, name: Setup}]\n", encoding="utf-8",
    )
    Path(config.hosts_file).write_text(
        "schema_version: 1\nrecords: [{id: 'host&one', hostname: '<lab>', template_id: setup}, "
        "{id: unrelated, hostname: other.example}]\n", encoding="utf-8",
    )
    query = "action=template_view&id=setup"
    viewer = Identity("viewer", "Viewer", frozenset(), frozenset({"hosts_read", "catalogs_read", "preview"}))
    body = _dispatch(query, viewer, config).body
    selector = body.split(b'<select id="preview-host"', 1)[1].split(b"</select>", 1)[0]
    assert body.index(b"Validate this template") < body.index(b"<h2>Rendered preview</h2>")
    assert body.index(b"Validate this template") < body.index(b"<h2>Template source</h2>")
    assert b'<option value="host&amp;one">&lt;lab&gt;</option>' in selector
    assert b"unrelated" not in selector
    assert b'name="template_id" value="setup"' in body
    reader = replace(viewer, capabilities=viewer.capabilities - {"hosts_read"})
    assert b'id="preview-host"' not in _dispatch(query, reader, config).body


def test_template_detail_source_preview_is_bounded_escaped_and_authorized(tmp_path: Path) -> None:
    root = tmp_path / "kickstart"
    root.mkdir()
    source = root / "setup.ks"
    source.write_text("<script>sample</script>", encoding="utf-8")
    config = replace(_config(tmp_path), kickstart_root=str(root))
    Path(config.templates_file).write_text(
        f"schema_version: 1\nrecords:\n  - {{id: setup, name: Setup, template_type: kickstart, content_path: '{source}'}}\n",
        encoding="utf-8",
    )
    query = "action=template_view&id=setup"
    reader = Identity("reader", "Reader", frozenset(), frozenset({"catalogs_read"}))
    viewer = replace(reader, capabilities=reader.capabilities | {"preview"})
    assert b"Template source" not in _dispatch(query, reader, config).body
    assert b"<pre>&lt;script&gt;sample&lt;/script&gt;</pre>" in _dispatch(query, viewer, config).body
    assert b"Template source is unavailable" in _dispatch(query, viewer, replace(config, max_template_bytes=2)).body
    outside = tmp_path / "outside.ks"
    source.rename(outside)
    source.symlink_to(outside)
    body = _dispatch(query, viewer, config).body
    assert b"Template source is unavailable" in body
    assert b"sample" not in body


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
    assert b'<span class="severity severity-error">Error</span> Provisioning state' in response.body
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
    catalog = {"installer_view": "installers", "role_view": "roles", "template_view": "templates"}[action]
    scope = f"action=validate&catalog={catalog}&record_id=shared"
    href = scope.replace("&", "&amp;").encode()
    assert href in body
    assert href in _dispatch(f"action={catalog}", viewer, config).body
    scoped = _dispatch(scope + "&severity=error", viewer, config)
    assert scoped.status == "200 OK"
    assert scoped.body.count(b"Enabled must be true or false.") == 1
    assert href in scoped.body
    assert _dispatch(scope, replace(viewer, capabilities=frozenset({"preview"})), config).status.startswith("403")


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
