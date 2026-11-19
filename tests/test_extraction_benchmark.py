import importlib.util
from pathlib import Path
import sys

import pytest

# The clean-install suite runs outside the checkout using the installed wheel.
script = Path(__file__).resolve().parents[1] / "tools" / "extraction_benchmark.py"
spec = importlib.util.spec_from_file_location("extraction_benchmark", script)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_extraction_baseline():
    # UTF-8 bytes including the envelope. Allow 5% growth per individual view.
    sizes = {
        "stations": (2850, 2850, 2850, 2850),
        "article": (1188, 1188, 1188, 1618),
        "table": (1426, 1426, 1426, 1565),
        "reference": (1682, 1307, 1479, 1618),
    }
    views = ("auto", "readability", "full", "raw")
    expected = {(page, view): size for page, row in sizes.items()
                for view, size in zip(views, row)}
    for page, view, _, size, truncated, missing in benchmark.measure():
        assert size <= expected.pop((page, view)) * 1.05, (page, view, size)
        assert not truncated, (page, view)
        allowed = {"reference reads 12 millimetres"} if (page, view) == (
            "reference", "readability") else set()
        assert set(missing) <= allowed, (page, view, missing)
    assert not expected


def test_reproducible_generated_timestamps():
    original = ("source=https://benchmark.example/ fetched=2026-03-18T13:17:10Z risk=none\n"
                "*Fetched: 2026-03-18*\n"
                "Field record: 2026-03-18T13:17:10Z\n*Fetched: 2026-03-18*")
    assert benchmark._fixed_timestamps(original) == (
        "source=https://benchmark.example/ fetched=2000-01-01T00:00:00Z risk=none\n"
        "*Fetched: 2000-01-01*\nField record: 2026-03-18T13:17:10Z\n*Fetched: 2026-03-18*"
    )


def test_tokenizer_requires_local_file_and_optional_package(monkeypatch, capsys):
    with pytest.raises(SystemExit) as missing_file:
        benchmark.main(["--tokenizer", "sample"])
    assert missing_file.value.code == 2
    assert "must be supplied together" in capsys.readouterr().err
    monkeypatch.setitem(sys.modules, "tokenizers", None)
    with pytest.raises(SystemExit) as missing_package:
        benchmark.main(["--tokenizer", "sample", "--tokenizer-file", "local.json"])
    assert missing_package.value.code == 2
    assert "optional dependency" in capsys.readouterr().err


def test_local_tokenizer_counts_without_padding_or_clipping(tmp_path, capsys, monkeypatch):
    tokenizers = pytest.importorskip("tokenizers")
    tokenizer = tokenizers.Tokenizer(tokenizers.models.WordLevel({"[UNK]": 0}, unk_token="[UNK]"))
    tokenizer.pre_tokenizer = tokenizers.pre_tokenizers.Whitespace()
    tokenizer.enable_truncation(max_length=1)
    tokenizer.enable_padding(length=8)
    path = tmp_path / "local.json"
    tokenizer.save(str(path))
    monkeypatch.setattr(benchmark, "_responses", lambda: [
        ("fixture", "raw", "one two three", "four", False, ["lost evidence"])])
    assert benchmark.main(["--tokenizer", "fixture-v1", "--tokenizer-file", str(path)]) == 1
    header, columns, row = capsys.readouterr().out.splitlines()
    assert header.startswith(f"Tokenizer fixture-v1 | tokenizers {tokenizers.__version__}")
    assert "SHA-256 " in header
    assert "HTML tokens" in columns
    assert row.split()[:9] == ["fixture", "raw", "13", "4", "69.2%", "3", "1", "66.7%", "False"]
    assert "lost evidence" in row
