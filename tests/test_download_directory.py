import json
from pathlib import Path

import pytest

from siftfetch import downloader, egress_policy, saving, tools
from test_server import _link_dir


def test_download_root_precedence(tmp_path, monkeypatch):
    policy = tmp_path / "policy"
    policy.mkdir()
    monkeypatch.setenv("SIFTFETCH_HOME", str(policy))
    assert saving.download_dir() == saving.data_dir()
    configured = tmp_path / "configured"
    (policy / "config.json").write_text(json.dumps({"download_dir": str(configured)}))
    assert saving.download_dir() == configured
    override = tmp_path / "override"
    monkeypatch.setenv("SIFTFETCH_DOWNLOAD_DIR", str(override))
    monkeypatch.setattr(tools, "_download_to_staging", lambda url, target, *a, **kw: target)
    assert tools.download_sync("https://docs.example/a", "text", 100) == override
    assert tools.download_sync("https://docs.example/a", "text", 100, configured) == configured
    saved = saving.save("text", "https://docs.example/a", "a", {"risk": "none"})
    assert Path(saved["path"]).is_relative_to(saving.data_dir())
    assert (saving.data_dir() / "saved-ledger.jsonl").exists()


@pytest.mark.parametrize("component", ["root", "downloads", "ancestor"])
def test_download_links_refused_before_creation(tmp_path, component):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "target"
    if component == "downloads":
        root.mkdir()
        _link_dir(outside, root / "downloads")
    else:
        _link_dir(outside, root)
        if component == "ancestor":
            root /= "child"
    with pytest.raises(downloader.DownloadRejected, match="unsafe_staging"):
        downloader._safe_dir(root)
    assert not list(outside.iterdir())


@pytest.mark.parametrize("value", [None, 1, [], ""])
def test_bad_download_config(value):
    with pytest.raises(egress_policy.PolicyError):
        egress_policy.validate_policy("config.json", {"download_dir": value})
