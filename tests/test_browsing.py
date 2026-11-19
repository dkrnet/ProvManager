# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only filtering, sorting, and pagination tests."""

from dataclasses import replace
from pathlib import Path

from provmanager import Config, Identity, dispatch


READER = Identity("reader", "Reader", frozenset(), frozenset({"hosts_read", "catalogs_read"}))


def _config(tmp_path: Path, records: str, page_size: int = 50) -> Config:
    hosts = tmp_path / "hosts.yaml"
    hosts.write_text("schema_version: 1\nrecords:\n" + records, encoding="utf-8")
    return replace(Config(), hosts_file=str(hosts), list_page_size=page_size)


def _request(config: Config, query: str):
    return dispatch(
        {"QUERY_STRING": "action=hosts&" + query, "REMOTE_USER": "reader"},
        config=config,
        identity_resolver=lambda username, active: READER,
    )


def test_search_uses_documented_host_fields_and_escapes_query(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        "  - {id: a, hostname: alpha.example, description: web node, enabled: true}\n"
        "  - {id: b, hostname: beta.example, description: database, enabled: true}\n",
    )
    response = _request(config, "q=web")
    assert b"alpha.example" in response.body
    assert b"beta.example" not in response.body
    malicious = _request(config, "q=%22%3E%3Cscript%3E")
    assert b'&quot;&gt;&lt;script&gt;' in malicious.body
    assert b'"><script>' not in malicious.body


def test_search_does_not_match_sensitive_variables(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        "  - id: a\n    hostname: alpha.example\n    enabled: true\n    variables: {admin_password: hidden-needle}\n",
    )
    response = _request(config, "q=hidden-needle")
    assert b"alpha.example" not in response.body
    assert b"0 matching record(s)" in response.body


def test_enabled_filter_and_descending_sort(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        "  - {id: a, hostname: alpha.example, enabled: false}\n"
        "  - {id: b, hostname: beta.example, enabled: true}\n"
        "  - {id: c, hostname: charlie.example, enabled: true}\n",
    )
    response = _request(config, "enabled=true&sort=hostname&direction=desc")
    assert b"alpha.example" not in response.body
    assert response.body.index(b"charlie.example") < response.body.index(b"beta.example")


def test_pagination_clamps_page_and_preserves_filters(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        "  - {id: a, hostname: alpha.example, enabled: true}\n"
        "  - {id: b, hostname: beta.example, enabled: true}\n"
        "  - {id: c, hostname: charlie.example, enabled: true}\n",
        page_size=1,
    )
    first = _request(config, "q=example&enabled=true&page=-10")
    assert b"Page 1 of 3" in first.body
    assert b"page=2" in first.body and b"q=example" in first.body and b"enabled=true" in first.body
    last = _request(config, "page=999")
    assert b"Page 3 of 3" in last.body
    assert b"charlie.example" in last.body


def test_pagination_controls_appear_above_and_below_table_with_shared_style(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        "  - {id: a, hostname: alpha.example, enabled: true}\n"
        "  - {id: b, hostname: beta.example, enabled: true}\n",
        page_size=1,
    )
    response = _request(config, "page=1")
    marker = b'<p class="pagination">Page 1 of 2'
    assert response.body.count(marker) == 2
    table_start = response.body.index(b"<table>")
    table_end = response.body.index(b"</table>")
    positions = [index for index in range(len(response.body)) if response.body.startswith(marker, index)]
    assert positions[0] < table_start < table_end < positions[1]
    assert b".pagination{font-size:.82rem;text-align:right}" in response.body


def test_browsing_has_no_catalog_side_effect(tmp_path: Path) -> None:
    config = _config(tmp_path, "  - {id: a, hostname: alpha.example, enabled: true}\n")
    path = Path(config.hosts_file)
    before = path.read_bytes()
    _request(config, "q=alpha&sort=hostname")
    assert path.read_bytes() == before
