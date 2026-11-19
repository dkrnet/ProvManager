# SPDX-License-Identifier: AGPL-3.0-only
"""Safe Markdown rendering and authenticated help tests."""

import provmanager
from provmanager import Config, Identity, dispatch, render_markdown


def test_markdown_supports_documented_basic_syntax() -> None:
    rendered = render_markdown("# Heading\n\n**bold** *emphasis* ~~removed~~\n\n- item\n\n`code`")
    assert "<h1>Heading</h1>" in rendered
    assert "<strong>bold</strong>" in rendered
    assert "<em>emphasis</em>" in rendered
    assert "<del>removed</del>" in rendered
    assert "<li>item</li>" in rendered
    assert "<code>code</code>" in rendered


def test_markdown_strips_html_and_unsafe_links() -> None:
    rendered = render_markdown('<script>alert(1)</script> [bad](javascript:alert(2)) <img src=x onerror=alert(3)>')
    assert "<script" not in rendered
    assert "<img" not in rendered
    assert "javascript:" not in rendered
    assert "alert(1)" in rendered


def test_markdown_fallback_is_escaped_plaintext(monkeypatch) -> None:
    monkeypatch.setattr(provmanager, "markdown", None)
    assert render_markdown("<b>unsafe</b>") == "<pre>&lt;b&gt;unsafe&lt;/b&gt;</pre>"


def test_markdown_help_requires_authentication_and_capability() -> None:
    anonymous = dispatch({"QUERY_STRING": "action=markdown_help"})
    assert anonymous.status == "303 See Other"
    reader = Identity("reader", "Reader", frozenset(), frozenset({"hosts_read"}))
    response = dispatch(
        {"QUERY_STRING": "action=markdown_help", "REMOTE_USER": "reader"},
        identity_resolver=lambda username, config: reader,
    )
    assert response.status == "200 OK"
    assert b"Markdown Help" in response.body
