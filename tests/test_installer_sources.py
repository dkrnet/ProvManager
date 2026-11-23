# SPDX-License-Identifier: AGPL-3.0-only
"""Source-type-specific read-only installer validation tests."""

from dataclasses import replace
from pathlib import Path

import pytest

from provmanager import Config, _installer_source_findings


def _messages(record, config):
    return [finding.message for finding in _installer_source_findings(record, config)]


def test_tree_source_requires_readable_approved_directory(tmp_path: Path) -> None:
    root = tmp_path / "installers"
    tree = root / "rocky9"
    tree.mkdir(parents=True)
    config = replace(Config(), installer_roots=(str(root),))
    record = {"id": "installer-1", "name": "Rocky 9", "source_type": "tree", "source_path": str(tree)}
    assert _messages(record, config) == []

    regular_file = root / "not-a-tree"
    regular_file.write_text("not a directory", encoding="utf-8")
    record["source_path"] = str(regular_file)
    assert _messages(record, config) == ["Installer tree path is not a readable directory."]


def test_iso_source_requires_iso_path_regular_file_and_allowlist(tmp_path: Path) -> None:
    root = tmp_path / "installers"
    root.mkdir()
    image = root / "rocky9.ISO"
    image.write_bytes(b"placeholder")
    config = replace(Config(), installer_roots=(str(root),))
    record = {"id": "installer-1", "name": "Rocky ISO", "source_type": "iso", "iso_path": str(image)}
    assert _messages(record, config) == []

    record["iso_path"] = str(root / "missing.iso")
    assert _messages(record, config) == ["Installer ISO path must be a readable .iso file."]
    wrong_extension = root / "image.img"
    wrong_extension.write_bytes(b"placeholder")
    record["iso_path"] = str(wrong_extension)
    assert _messages(record, config) == ["Installer ISO path must be a readable .iso file."]


@pytest.mark.parametrize(
    "url",
    [
        "http://mirror.example.test/rocky/9/",
        "https://mirror.example.test:8443/rocky/9/",
    ],
)
def test_network_source_accepts_safe_http_urls_without_network_access(monkeypatch, url: str) -> None:
    def unexpected_network(*args, **kwargs):
        raise AssertionError("validation must not contact the network")

    monkeypatch.setattr("socket.create_connection", unexpected_network)
    record = {"id": "installer-1", "name": "Network", "source_type": "network", "source_path": url}
    assert _messages(record, Config()) == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://mirror.example.test/rocky/9/",
        "file:///srv/installers/rocky9",
        "https://user:password@mirror.example.test/rocky/9/",
        "https://mirror.example.test/rocky/9/#fragment",
        "https://mirror.example.test:99999/rocky/9/",
        "https://",
        "https://mirror.example.test/rocky/9/\nunsafe",
    ],
)
def test_network_source_rejects_unsafe_or_malformed_urls(url: str) -> None:
    record = {"id": "installer-1", "name": "Network", "source_type": "network", "source_path": url}
    messages = _messages(record, Config())
    assert len(messages) == 1
    assert "Network installer source" in messages[0]


def test_source_type_is_required_and_enumerated() -> None:
    record = {"id": "installer-1", "name": "Unknown", "source_type": "nfs", "source_path": "/srv/installers"}
    assert _messages(record, Config()) == ["Installer source type must be iso, tree, or network."]
