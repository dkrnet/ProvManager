# SPDX-License-Identifier: AGPL-3.0-only
"""Regression coverage for the milestone-one CGI and configuration core."""

from pathlib import Path

from provmanager import Config, Identity, dispatch, load_config


VIEWER = Identity("alice", "Alice Example", frozenset({"provisioning_viewer"}), frozenset({"hosts_read", "catalogs_read", "preview"}))


def fixed_identity(_username: str, _config: Config) -> Identity:
    return VIEWER


def test_missing_configuration_uses_safe_defaults(tmp_path: Path) -> None:
    config, diagnostics = load_config(str(tmp_path / "missing.conf"))
    assert config.kickstart_root == "/data/provisioning/kickstart/"
    assert config.tftp_root == "/var/lib/tftpboot/efi/"
    assert config.enable_service_reload is False
    assert config.enable_provisioning_execution is False
    assert diagnostics == ()


def test_configuration_parses_supported_values_and_rejects_unsafe_ones(tmp_path: Path) -> None:
    path = tmp_path / "provmanager.conf"
    path.write_text(
        "LIST_PAGE_SIZE=25\nENABLE_SERVICE_RELOAD=yes\nINSTALLER_ROOTS=/mnt/installers, /srv/installers\nHOSTS_FILE=relative.yaml\nUNKNOWN_KEY=value\n",
        encoding="utf-8",
    )
    config, diagnostics = load_config(str(path))
    assert config.list_page_size == 25
    assert config.enable_service_reload is True
    assert config.installer_roots == ("/mnt/installers", "/srv/installers")
    assert config.hosts_file == Config().hosts_file
    assert diagnostics == ("Ignored invalid value for HOSTS_FILE.",)


def test_configuration_rejects_relative_installer_root(tmp_path: Path) -> None:
    path = tmp_path / "provmanager.conf"
    path.write_text("INSTALLER_ROOTS=/mnt/installers,relative/path\n", encoding="utf-8")
    config, diagnostics = load_config(str(path))
    assert config.installer_roots == ()
    assert diagnostics == ("Ignored invalid value for INSTALLER_ROOTS.",)


def test_default_request_without_user_shows_login() -> None:
    response = dispatch({"QUERY_STRING": ""})
    assert response.status == "200 OK"
    assert b"Sign in to continue" in response.body
    assert b'<form method="post" action="/provmanager-login">' in response.body
    assert b"ProvManager 1.0.0" not in response.body


def test_favicon_is_public_and_nonempty() -> None:
    response = dispatch({"QUERY_STRING": "action=favicon"})
    assert response.status == "200 OK"
    assert ("Content-Type", "image/x-icon") in response.headers
    assert response.body[:6] == b"\x00\x00\x01\x00\x06\x00"
    sizes = set()
    for index in range(6):
        width = response.body[6 + index * 16]
        height = response.body[7 + index * 16]
        sizes.add((256 if width == 0 else width, 256 if height == 0 else height))
    assert sizes == {(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)}


def test_login_failed_and_logged_out_link_back_to_login() -> None:
    for action in ("login_failed", "logged_out"):
        response = dispatch({"QUERY_STRING": "action=" + action})
        assert response.status == "200 OK"
        assert b'href="?action=login"' in response.body
        assert b"Return to login" in response.body


def test_protected_action_redirects_anonymous_request() -> None:
    response = dispatch({"QUERY_STRING": "action=hosts"})
    assert response.status == "303 See Other"
    assert ("Location", "?action=login") in response.headers


def test_authenticated_default_routes_to_hosts() -> None:
    response = dispatch({"QUERY_STRING": "", "REMOTE_USER": "alice"}, identity_resolver=fixed_identity)
    assert response.status == "500 Internal Server Error"
    assert b"ProvManager 1.0.0" in response.body


def test_unknown_authenticated_action_is_404() -> None:
    response = dispatch({"QUERY_STRING": "action=does_not_exist", "REMOTE_USER": "alice"}, identity_resolver=fixed_identity)
    assert response.status == "404 Not Found"


def test_cgi_serialization_places_headers_before_body() -> None:
    payload = dispatch({"QUERY_STRING": "action=login"}).to_cgi()
    header, body = payload.split(b"\r\n\r\n", 1)
    assert header.startswith(b"Status: 200 OK")
    assert b"Content-Type: text/html; charset=utf-8" in header
    assert body.startswith(b"<!doctype html>")
