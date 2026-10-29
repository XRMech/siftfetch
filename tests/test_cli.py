import json
from pathlib import Path
import sys
import tomllib

import pytest
from siftfetch import cli, egress_policy as ep


@pytest.fixture
def setup(tmp_path, monkeypatch):
    folder = tmp_path / 'policy'
    monkeypatch.setenv('SIFTFETCH_HOME', str(folder))
    monkeypatch.delenv('SIFTFETCH_CONTACT_ALIAS', raising=False)
    monkeypatch.delenv('SIFTFETCH_ENABLED', raising=False)
    monkeypatch.setattr(ep, '_cached', None)
    return tmp_path


def test_init_never_reads_or_overwrites_existing_policy(setup, monkeypatch):
    assert cli.initialize() == 0
    folder = setup / 'policy'
    assert json.loads((folder / 'identifiers.json').read_text())['values'] == []
    original = Path.read_text
    def read(path, *args, **kwargs):
        assert not path.is_relative_to(folder)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    assert cli.initialize() == 0


def test_init_respects_toml_and_does_not_follow_links(setup):
    folder = setup / 'policy'
    folder.mkdir()
    (folder / 'identifiers.toml').write_text('values = []')
    cli.initialize()
    assert not (folder / 'identifiers.json').exists()


@pytest.mark.parametrize('client', ['claude', 'codex'])
@pytest.mark.parametrize('scope', ['user', 'project'])
def test_install_dry_run_apply_preserve_backup_idempotent(setup, capsys, client, scope):
    paths = cli._targets(client, scope, setup / 'home', setup / 'project')
    first = paths[0]
    first.parent.mkdir(parents=True)
    original = {'custom': 'keep', 'hooks': {'SessionStart': [{'matcher': '*', 'hooks': []}]}}
    text = ('custom = "keep"\n[hooks]\nSessionStart = [{matcher = "*", hooks = []}]\n'
            if client == 'codex' else json.dumps(original))
    first.write_text(text, encoding='utf-8')
    before = first.read_bytes()
    kwargs = dict(home=setup / 'home', project=setup / 'project')
    assert cli.install(client, scope, **kwargs) == 0
    assert first.read_bytes() == before
    assert not list(first.parent.glob('*.siftfetch-backup-*'))
    assert 'keep' not in capsys.readouterr().out
    assert cli.install(client, scope, True, **kwargs) == 0
    result = cli._read_settings(first)
    assert result['custom'] == 'keep'
    assert result['hooks']['SessionStart'] == original['hooks']['SessionStart']
    backups = list(first.parent.glob('*.siftfetch-backup-*'))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    after = first.read_bytes()
    cli.install(client, scope, True, **kwargs)
    assert first.read_bytes() == after
    assert len(list(first.parent.glob('*.siftfetch-backup-*'))) == 1


def test_install_conflict_is_no_write(setup):
    target = setup / '.codex/config.toml'
    target.parent.mkdir()
    text = '[mcp_servers.siftfetch]\ncommand = "custom"\n'
    target.write_text(text)
    with pytest.raises(ValueError):
        cli.install('codex', 'project', True, project=setup)
    assert target.read_text() == text
    assert not list(target.parent.glob('*.siftfetch-backup-*'))


def test_doctor_counts_no_values_and_disabled(setup, capsys):
    cli.initialize()
    folder = setup / 'policy'
    (folder / 'identifiers.json').write_text(json.dumps({'values': [
        {'label': 'email', 'value': 'jane.doe@mail.example', 'kind': 'email', 'class': 'exact'}]}))
    (folder / 'config.json').write_text('{"enabled": false, "substitute": {"name": "Alex Example"}}')
    cli.install('claude', 'project', True, project=setup)
    capsys.readouterr()
    assert cli.doctor('claude', 'project', project=setup) == 0
    out = capsys.readouterr().out
    assert 'DISABLED' in out and 'identifiers=1' in out
    assert 'jane.doe' not in out and 'Alex Example' not in out
    (folder / 'config.toml').write_text('enabled = true')
    assert cli.doctor('claude', 'project', project=setup) == 1
    assert 'conflicting' in capsys.readouterr().out


def test_doctor_reports_shadowed_json(setup, capsys):
    cli.initialize()
    (setup / 'policy/exceptions.toml').write_text('exceptions = []')
    cli.doctor('claude', 'project', project=setup)
    assert 'exceptions.json is shadowed' in capsys.readouterr().out


def test_install_never_reads_policy_values(setup, monkeypatch):
    monkeypatch.setattr(ep, '_read_policy', lambda *a, **k: pytest.fail('installer read protected policy'))
    assert cli.install('claude', 'project', True, project=setup) == 0


def test_install_rejects_link_before_writing(setup, monkeypatch):
    monkeypatch.setattr(cli.saving, 'is_link', lambda path: path.name == '.codex')
    with pytest.raises(ValueError):
        cli.install('codex', 'project', True, project=setup)
    assert not (setup / '.codex').exists()


def test_cli_error_exit_and_no_values(setup, monkeypatch, capsys):
    monkeypatch.chdir(setup)
    folder = setup / '.codex'
    folder.mkdir()
    (folder / 'config.toml').write_text('private = "unclosed-synthetic-value')
    assert cli.main(['install', '--client', 'codex', '--scope', 'project', '--apply']) == 2
    output = capsys.readouterr()
    assert 'unclosed-synthetic-value' not in output.out + output.err
    assert not list(folder.glob('*.siftfetch-backup-*'))


@pytest.mark.parametrize('quoted_headers', [False, True])
def test_codex_preserves_bytes_and_merges_hooks(setup, quoted_headers):
    target, hookfile = cli._targets('codex', 'project', project=setup)
    target.parent.mkdir()
    server = cli._entries('codex')[1]
    original = ('# owner comment\r\nweb_search  = "live" # keep\r\n\r\n'
                '[unrelated]\r\nvalue = "keep"\r\n\r\n'
                '[mcp_servers.siftfetch]\r\ncommand = ' + json.dumps(server['command']) +
                '\r\nargs = ["-I", "-m", "siftfetch.server"]\r\n\r\n'
                '[shell_environment_policy]\r\n# environment comment\r\ninherit = "core"\r\n')
    if quoted_headers:
        original = original.replace('[shell_environment_policy]', '[ "shell_environment_policy" ]')
        original = original.replace('[mcp_servers.siftfetch]', '[ mcp_servers . "siftfetch" ]')
    target.write_bytes(original.encode())
    hookfile.write_text('{"custom": 1, "hooks": {"SessionStart": []}}')
    assert cli.install('codex', 'project', True, project=setup) == 0
    expected = original.replace('"live"', '"disabled"') + 'ignore_default_excludes = false\r\n'
    assert target.read_bytes() == expected.encode()
    hooks = json.loads(hookfile.read_text())
    assert hooks['custom'] == 1 and hooks['hooks']['SessionStart'] == []
    assert hooks['hooks']['PreToolUse'] == cli._entries('codex')[0]['PreToolUse']


@pytest.mark.parametrize('text', [
    'shell_environment_policy.ignore_default_excludes = true\n',
    'shell_environment_policy = {ignore_default_excludes = true}\n',
    'mcp_servers.siftfetch.command = "custom"\n',
])
def test_codex_unsafe_forms_refuse_without_writes(setup, text):
    target, hookfile = cli._targets('codex', 'project', project=setup)
    target.parent.mkdir()
    target.write_bytes(text.encode())
    with pytest.raises(ValueError, match='reconcile'):
        cli.install('codex', 'project', True, project=setup)
    assert target.read_bytes() == text.encode()
    assert not hookfile.exists()
    assert not list(target.parent.glob('*.siftfetch-backup-*'))


@pytest.mark.parametrize('client', ['claude', 'codex'])
@pytest.mark.parametrize('command', ['python -I -m siftfetch.hook', '"C:/Other Python/python.exe" "-m" "siftfetch.hook" "--deny"'])
def test_different_hook_refused(setup, client, command):
    paths = cli._targets(client, 'project', project=setup)
    target = paths[0 if client == 'claude' else 1]
    target.parent.mkdir()
    hooks = cli._entries(client)[0]
    hooks['PreToolUse'][0]['hooks'][0]['command'] = command
    target.write_text(json.dumps({'hooks': hooks}))
    before = target.read_bytes()
    with pytest.raises(ValueError, match='existing siftfetch hook differs; owner must reconcile it manually'):
        cli.install(client, 'project', True, project=setup)
    assert target.read_bytes() == before


@pytest.mark.parametrize('location', ['json', 'toml'])
def test_codex_doctor_hook_locations(setup, location):
    cli.initialize()
    cli.install('codex', 'project', True, project=setup)
    target, hookfile = cli._targets('codex', 'project', project=setup)
    if location == 'toml':
        hooks = json.loads(hookfile.read_text())['hooks']
        with target.open('a', encoding='utf-8') as stream:
            stream.write('\n[hooks]\nPreToolUse = ' + cli._toml_value(hooks['PreToolUse']) + '\n')
        hookfile.unlink()
    assert cli.doctor('codex', 'project', project=setup) == 0


def test_hook_command_quoting():
    python = cli.sys.executable.replace('\\', '/')
    assert cli._entries('codex')[0]['PreToolUse'][0]['hooks'][0]['command'] == (
        f'"{python}" "-I" "-m" "siftfetch.hook" "--deny"')
    assert cli._entries('claude')[0]['PreToolUse'][0]['hooks'][0]['command'] == f'"{python}" -I -m siftfetch.hook'


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_codex_only_web_search_line_changes(setup, newline):
    cli.install('codex', 'project', True, project=setup)
    target = cli._targets('codex', 'project', project=setup)[0]
    text = target.read_text().replace('"disabled"', "'live' # keep")
    text = ('# custom\n\n' + text + '\n[unrelated]\nvalue = "keep"\n').replace('\n', newline)
    target.write_bytes(text.encode())
    cli.install('codex', 'project', True, project=setup)
    assert target.read_bytes() == text.replace("'live'", '"disabled"').encode()


def test_codex_semantic_mismatch_refuses_all_writes(setup, monkeypatch):
    target, hookfile = cli._targets('codex', 'project', project=setup)
    target.parent.mkdir()
    before = b'# custom\n'
    target.write_bytes(before)
    monkeypatch.setattr(cli, '_toml_value', lambda value: '"wrong"')
    with pytest.raises(ValueError, match='reconcile'):
        cli.install('codex', 'project', True, project=setup)
    assert target.read_bytes() == before
    assert not hookfile.exists()
    assert not list(target.parent.glob('*.siftfetch-backup-*'))


def test_codex_legacy_hook_conflict_cli_message(setup, monkeypatch, capsys):
    target, hookfile = cli._targets('codex', 'project', project=setup)
    target.parent.mkdir()
    hooks = cli._entries('codex')[0]
    hooks['PreToolUse'][0]['hooks'][0]['command'] = 'python -m siftfetch.hook'
    target.write_text('[hooks]\nPreToolUse = ' + cli._toml_value(hooks['PreToolUse']))
    before = target.read_bytes()
    monkeypatch.chdir(setup)
    assert cli.main(['install', '--client', 'codex', '--scope', 'project', '--apply']) == 2
    assert 'existing siftfetch hook differs; owner must reconcile it manually' in capsys.readouterr().err
    assert target.read_bytes() == before and not hookfile.exists()


def test_claude_concurrent_writer_keeps_backup(setup, monkeypatch, capsys):
    target = setup / '.claude.json'
    before = b'{"custom": "before"}'
    concurrent = b'{"custom": "concurrent"}'
    target.write_bytes(before)
    cli.install('claude', home=setup)
    assert 'Close Claude Code before --apply: it rewrites ~/.claude.json while running.' in capsys.readouterr().out
    write = cli.saving._write_new
    def race(path, text):
        result = write(path, text)
        if path.name.startswith('.claude.json.siftfetch-'):
            target.write_bytes(concurrent)
        return result
    monkeypatch.setattr(cli.saving, '_write_new', race)
    monkeypatch.setattr(Path, 'home', lambda: setup)
    assert cli.main(['install', '--client', 'claude', '--apply']) == 2
    assert 'settings changed during install; close the client and retry' in capsys.readouterr().err
    assert target.read_bytes() == concurrent
    backups = list(setup.glob('.claude.json.siftfetch-backup-*'))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    assert list(setup.glob('.claude.json.siftfetch-*')) == backups


def test_hook_coverage_uses_each_clients_tool_names():
    command = '"' + sys.executable.replace(chr(92), '/') + '" -I -m siftfetch.hook'
    def source(matcher):
        return {'hooks': {'PreToolUse': [{'matcher': matcher, 'hooks': [{'type': 'command', 'command': command}]}]}}
    claude = ['Edit', 'MultiEdit', 'mcp__example__tool']
    missing, _ = cli._hook_checks([source('Edit|Write|mcp__.*')], 'PreToolUse', claude)
    assert missing == ['MultiEdit']  # "Edit" must not cover "MultiEdit"
    codex = ['Bash', 'apply_patch', 'mcp__example__tool']
    missing, _ = cli._hook_checks([source('^Bash$'), source('Edit|Write')], 'PreToolUse', codex)
    assert missing == ['mcp__example__tool']
