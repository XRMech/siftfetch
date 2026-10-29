"""Offline release isolation and owner-portability contracts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cleanroom', ROOT / 'tools/cleanroom.py')
cleanroom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanroom)


def test_guard_accepts_clean_child(tmp_path):
    paths = cleanroom.guard(tmp_path, sys.executable, cleanroom.clean_env(tmp_path))
    assert Path(paths['home']) == tmp_path / 'profile'


def test_guard_refuses_real_home(tmp_path):
    # Only resolve home; never inspect its contents or policy/data directories.
    env = cleanroom.clean_env(tmp_path)
    env['HOME'] = env['USERPROFILE'] = str(Path.home())
    with pytest.raises(RuntimeError, match='unsafe home'):
        cleanroom.guard(tmp_path, sys.executable, env)


def test_guard_refuses_escape_and_missing_paths(tmp_path):
    with pytest.raises(RuntimeError):
        cleanroom.validate_paths(tmp_path, {'home': str(tmp_path / 'home')})
    with pytest.raises(RuntimeError, match='unsafe data'):
        cleanroom.validate_paths(tmp_path, dict(home=tmp_path / 'home', policy=tmp_path / 'policy',
                                               data=tmp_path / '../outside'))


def test_clean_environment_drops_inherited_tools_and_values(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_PRIVATE', 'sentinel')
    monkeypatch.setenv('PYTHONPATH', 'sentinel')
    monkeypatch.setenv('SIFTFETCH_DATA', 'sentinel')
    env = cleanroom.clean_env(tmp_path, tmp_path / 'venv/bin')
    assert not any(key.startswith(('AGENT_', 'PYTHON', 'SIFTFETCH_')) for key in env)
    assert env['PATH'].split(os.pathsep)[0] == str(tmp_path / 'venv/bin')


def test_tracked_files_have_no_owner_strings():
    manifest = ROOT / '.cleanroom-tracked.json'
    names = (json.loads(manifest.read_text()) if manifest.exists() else
             subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0'))
    hits = []
    for name in names:
        if not name:
            continue
        path = ROOT / name
        # Protected inputs must never be opened, even if accidentally tracked.
        if any(part == '.secrets' or part.startswith('.env') for part in path.relative_to(ROOT).parts):
            pytest.fail('protected input in tracked release files')
        if path.is_file():
            hits.extend(cleanroom.owner_hits(name, path.read_bytes()))
    assert not hits, hits


def test_owner_scan_casefold_and_attribution():
    for value in cleanroom.OWNER_STRINGS:
        assert cleanroom.owner_hits('sample.txt', value.upper().encode())
    assert not cleanroom.owner_hits('pyproject.toml', ('authors = [{ name = "Cli' + 'nton Campbell" }]').encode())
    assert cleanroom.owner_hits('other.txt', ('Cli' + 'nton Campbell').encode())
    assert not cleanroom.owner_hits('NOTICE', ('Copyright 2026 Cli' + 'nton Campbell (XRMech Solutions)').encode())


def test_packaged_benchmark_matches_reviewed_corpus():
    from siftfetch import benchmark
    for path in (ROOT / 'tests/fixtures/benchmark').iterdir():
        if path.is_file():
            assert (benchmark._DEFAULT_CORPUS / path.name).read_bytes() == path.read_bytes()
