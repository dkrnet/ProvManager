# SPDX-License-Identifier: AGPL-3.0-only
"""Identity and backend capability regression tests."""

from dataclasses import replace
from types import SimpleNamespace

import provmanager
from provmanager import Config, Identity, dispatch, resolve_identity


def test_nss_identity_includes_primary_and_supplementary_roles(monkeypatch) -> None:
    account = SimpleNamespace(pw_gid=100, pw_gecos="Alice Example,Room")
    monkeypatch.setattr(provmanager.pwd, "getpwnam", lambda username: account)
    monkeypatch.setattr(provmanager.os, "getgrouplist", lambda username, gid: [100, 200])
    groups = {100: "pm_viewers", 200: "pm_prvusers"}
    monkeypatch.setattr(provmanager.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name=groups[gid]))

    identity = resolve_identity("alice", Config())

    assert identity is not None
    assert identity.full_name == "Alice Example"
    assert identity.roles == frozenset({"provisioning_viewer", "provisioning_user"})
    assert "hosts_write" in identity.capabilities
    assert "apply" not in identity.capabilities


def test_missing_or_unmapped_nss_user_is_denied(monkeypatch) -> None:
    monkeypatch.setattr(provmanager.pwd, "getpwnam", lambda username: (_ for _ in ()).throw(KeyError(username)))
    assert resolve_identity("missing", Config()) is None

    response = dispatch({"QUERY_STRING": "action=hosts", "REMOTE_USER": "missing"}, identity_resolver=lambda username, config: None)
    assert response.status == "403 Forbidden"


def test_direct_privileged_action_checks_backend_capability() -> None:
    viewer = Identity("viewer", "Viewer", frozenset({"provisioning_viewer"}), frozenset({"hosts_read", "catalogs_read", "preview"}))
    response = dispatch(
        {"QUERY_STRING": "action=apply", "REMOTE_USER": "viewer"},
        identity_resolver=lambda username, config: viewer,
    )
    assert response.status == "403 Forbidden"
    assert b"do not have permission" in response.body


def test_authorized_but_unimplemented_action_is_explicit() -> None:
    admin = Identity("admin", "Admin", frozenset({"application_admin"}), frozenset({"apply"}))
    response = dispatch(
        {"QUERY_STRING": "action=apply", "REMOTE_USER": "admin"},
        identity_resolver=lambda username, config: admin,
    )
    assert response.status == "501 Not Implemented"


def test_authenticated_page_escapes_nss_display_name() -> None:
    identity = Identity("alice", "<script>alert(1)</script>", frozenset({"provisioning_viewer"}), frozenset({"hosts_read"}))
    response = dispatch(
        {"QUERY_STRING": "action=hosts", "REMOTE_USER": "alice"},
        identity_resolver=lambda username, config: identity,
    )
    assert b"&lt;script&gt;" in response.body
    assert b"<script>alert" not in response.body


def test_feature_gates_cannot_enable_unimplemented_system_operations() -> None:
    config = replace(Config(), enable_service_reload=True, enable_provisioning_execution=True)
    admin = Identity("admin", "Admin", frozenset({"application_admin"}), frozenset({"apply", "execute"}))
    resolver = lambda username, active: admin
    apply_response = dispatch(
        {"QUERY_STRING": "action=apply_submit", "REMOTE_USER": "admin", "REQUEST_METHOD": "POST"},
        config=config, identity_resolver=resolver,
    )
    execute_response = dispatch(
        {"QUERY_STRING": "action=execute_submit", "REMOTE_USER": "admin", "REQUEST_METHOD": "POST"},
        config=config, identity_resolver=resolver,
    )
    assert apply_response.status == "501 Not Implemented"
    assert execute_response.status == "501 Not Implemented"
