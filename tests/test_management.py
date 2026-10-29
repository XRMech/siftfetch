"""Management contracts use synthetic homes; editors and process launches are mocked."""
import copy
import json
from pathlib import Path
import sys
import tomllib

import pytest

from siftfetch import cli, egress_policy as ep, hook, management as m, receipt, tools


@pytest.mark.parametrize('client', ['claude', 'codex'])
@pytest.mark.parametrize('executable', [False, True])
def test_adopt_legacy_roundtrip(home, client, executable):
    paths = cli._targets(client, 'user', home)
    hooks, server, deny = cli._entries(client)
    for event, groups in hooks.items():
        groups[0]['matcher'] = '*'
        command = ('"C:/Legacy/sf/siftfetch-hook.exe"' if executable else
                   '"C:/Legacy/sf/python.exe" "-I" "-m" "siftfetch.hook"')
        if client == 'codex':
            command += ' "--deny"'
        groups[0]['hooks'] = [{'type': 'command', 'command': command}]
        if client == 'codex':
            # Hand-written Codex entries carry a limit and a status line.
            groups[0]['hooks'][0].update(timeout=30, statusMessage='SiftFetch privacy guard')
    server = ({'command': 'C:/Legacy/sf/siftfetch-server.exe', 'args': []} if executable else
              {'command': 'C:/Legacy/sf/python.exe', 'args': ['-I', '-m', 'siftfetch.server']})
    if client == 'claude':
        server.update(type='stdio', env={})  # The shape `claude mcp add` writes.
    if client == 'claude':
        documents = [{'hooks': hooks, 'permissions': {'deny': [deny[0], 'Read(private-example/**)']}},
                     {'mcpServers': {'siftfetch': server, 'other': {'command': 'other'}}}]
    else:
        # Codex keeps hook-trust records under hooks.state once a hook is trusted.
        trust = {'state': {'C:/x/config.toml:pre_tool_use:0:0': {'trusted_hash': 'sha256:00'}}}
        documents = [{'hooks': {**hooks, **trust},
                      'mcp_servers': {'siftfetch': server, 'other': {'command': 'other'}}}, {}]
    for path, document in zip(paths, documents):
        path.parent.mkdir(exist_ok=True)
        text = m.edit_toml('# retained\n', document) if path.suffix == '.toml' else json.dumps(document)
        path.write_text(text)
    before = [p.read_bytes() for p in paths]
    assert cli.install(client, home=home, adopt=True) == 0
    assert [p.read_bytes() for p in paths] == before
    assert cli.install(client, home=home, adopt=True, apply=True) == 0
    assert cli.doctor(client, home=home) == 0
    installed = [p.read_bytes() for p in paths]
    manifest = (home / 'policy/install-manifest.json').read_bytes()
    assert cli.install(client, home=home, adopt=True, apply=True) == 0
    assert [p.read_bytes() for p in paths] == installed
    assert (home / 'policy/install-manifest.json').read_bytes() == manifest
    journal = receipt.load()
    assert any(item['backup'] for tx in journal['transactions'] for item in tx['files'])
    answers = iter(['uninstall', ''])
    assert cli.uninstall(client, apply=True, home=home, prompt=lambda _: next(answers)) == 0
    for path in paths:
        document = cli._read_settings(path)
        # Codex trust records are the owner's, not SiftFetch's; they stay.
        assert all(not groups for event, groups in document.get('hooks', {}).items() if event != 'state')
        assert 'siftfetch' not in document.get('mcpServers', document.get('mcp_servers', {}))
        if path.suffix == '.toml':
            assert '# retained' in path.read_text()
    if client == 'claude':
        assert cli._read_settings(paths[0])['permissions']['deny'] == ['Read(private-example/**)']


@pytest.mark.parametrize('change', ['args', 'event', 'mixed', 'options', 'server'])
def test_adopt_refuses_unknown_without_writes(home, change):
    hooks, server, _ = cli._entries('claude')
    hooks['PreToolUse'][0]['hooks'][0]['command'] = '"C:/Legacy/python.exe" -I -m siftfetch.hook'
    if change == 'args':
        hooks['PreToolUse'][0]['hooks'][0]['command'] += ' --unknown'
    elif change == 'event':
        hooks['UnknownEvent'] = hooks.pop('PreToolUse')
    elif change == 'mixed':
        hooks['PreToolUse'][0]['hooks'].append({'type': 'command', 'command': 'other'})
    elif change == 'options':
        hooks['PreToolUse'][0]['hooks'][0]['async'] = True
    else:
        server['args'] += ['--unknown']
    paths = cli._targets('claude', 'user', home)
    for path, value in zip(paths, [{'hooks': hooks}, {'mcpServers': {'siftfetch': server}}]):
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value))
    before = [p.read_bytes() for p in paths]
    with pytest.raises(ValueError, match='Cannot adopt:'):
        cli.install('claude', home=home, adopt=True, apply=True)
    assert [p.read_bytes() for p in paths] == before
    assert not (home / 'policy/install-manifest.json').exists()


@pytest.mark.parametrize('args,accepted', [
    (['-m', 'siftfetch.hook'], True), (['-I', '-m', 'siftfetch.hook'], True),
    (['-m', 'siftfetch.hook', '--deny'], True), (['-m', 'siftfetch.hook', '--unknown'], False),
    (['-X', 'dev', '-m', 'siftfetch.hook'], False), (['-c', 'siftfetch.hook'], False),
])
def test_legacy_exact_grammar(args, accepted):
    assert m._legacy_command(['C:/Legacy/runtime.exe', *args], 'siftfetch.hook') is accepted


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setenv('SIFTFETCH_HOME', str(tmp_path / 'policy'))
    monkeypatch.setattr(m, 'temporary_interpreter', lambda: False)
    cli.initialize()
    return tmp_path


@pytest.mark.parametrize('before,after,allowed', [
    ({'enabled': False}, {'enabled': True}, True),
    ({'enabled': True}, {'enabled': False}, False),
    ({'guard_lock': False}, {'guard_lock': True}, True),
    ({'guard_lock': True}, {'guard_lock': False}, False),
    ({'guard_lock': {'enabled': True, 'paths': ['a']}}, {'guard_lock': {'enabled': True, 'paths': ['a', 'b']}}, True),
    ({'guard_lock': {'enabled': True, 'paths': ['a']}}, {'guard_lock': True}, False),
    ({'secret_file_mode': 'off'}, {'secret_file_mode': 'standard'}, True),
    ({'secret_file_mode': 'standard'}, {'secret_file_mode': 'strict'}, True),
    ({'secret_file_mode': 'strict'}, {'secret_file_mode': 'standard'}, False),
    ({'browser_fetch': {'mode': 'on-wall'}}, {'browser_fetch': {'mode': 'off'}}, True),
    ({'browser_fetch': {'mode': 'off'}}, {'browser_fetch': {'mode': 'on-wall'}}, False),
    ({'blocked_domains': ['a.example']}, {'blocked_domains': ['a.example', 'b.example']}, True),
    ({'blocked_domains': ['a.example']}, {'blocked_domains': []}, False),
    ({}, {'contact_alias': 'alias@example.invalid'}, False),
    ({'enabled': 'bad'}, {'enabled': True}, False),
    ({'unknown': True}, {'unknown': True, 'enabled': True}, False),
    ({'enabled': False, 'guard_lock': True}, {'enabled': True, 'guard_lock': False}, False),
])
def test_classifier(before, after, allowed):
    assert m.classify(before, after) is allowed


@pytest.mark.parametrize('before,after,allowed', [
    ({'web_search': 'live'}, {'web_search': 'disabled'}, True),
    ({'web_search': 'disabled'}, {'web_search': 'live'}, False),
    ({'ignore_default_excludes': True}, {'ignore_default_excludes': False}, True),
    ({'ignore_default_excludes': False}, {'ignore_default_excludes': True}, False),
    ({'deny': ['a']}, {'deny': ['a', 'b']}, True),
    ({'deny': ['a']}, {'deny': []}, False),
])
def test_client_classifier(before, after, allowed):
    assert m.classify(before, after, client=True) is allowed


@pytest.mark.parametrize('format', ['json', 'toml'])
def test_policy_atomic_preserves_other_keys(home, monkeypatch, format):
    base = home / 'policy'
    (base / 'config.json').unlink()
    path = base / ('config.' + format)
    original = {'enabled': False, '_note': 'keep', 'browser_fetch': {'mode': 'on-wall', 'window': 'visible'}}
    text = json.dumps(original) if format == 'json' else '# keep comment\nenabled = false # switch\n_note = "keep"\n[browser_fetch]\nmode = "on-wall" # mode\nwindow = "visible"\n'
    path.write_text(text)
    calls = []
    replace = m.os.replace
    def atomic(source, target):
        assert source.parent == target.parent
        assert target.read_text() == text
        calls.append(target)
        replace(source, target)
    monkeypatch.setattr(m.os, 'replace', atomic)
    assert tools.tighten({'enabled': True, 'browser_fetch': {'mode': 'off'}})['ok']
    current = tomllib.loads(path.read_text()) if format == 'toml' else json.loads(path.read_text())
    assert current == {**original, 'enabled': True, 'browser_fetch': {'mode': 'off', 'window': 'visible'}}
    assert calls == [path]
    assert len(list(base.glob('config.*.siftfetch-backup-*'))) == 1
    if format == 'toml':
        assert '# keep comment' in path.read_text() and '# switch' in path.read_text() and '# mode' in path.read_text()


@pytest.mark.parametrize('bad', ['unknown', 'malformed', 'coexistence', 'env'])
def test_refuse_bad_effective_baseline(home, monkeypatch, bad):
    path = home / 'policy/config.json'
    if bad == 'unknown':
        path.write_text('{"mystery": true}')
    elif bad == 'malformed':
        path.write_text('{')
    elif bad == 'coexistence':
        (home / 'policy/config.toml').write_text('enabled = false')
    else:
        monkeypatch.setenv('SIFTFETCH_ENABLED', '0')
    raw = path.read_bytes()
    assert not tools.tighten({'enabled': True})['ok']
    assert path.read_bytes() == raw


@pytest.mark.parametrize('preset', ['standard', 'lockdown', 'strict', 'custom paths,chrome'])
def test_wizard_five_prompts(home, monkeypatch, preset):
    answers = iter(['claude,codex', 'user', preset, 'n', 'y'])
    prompts = []
    def ask(text):
        prompts.append(text)
        return next(answers)
    assert cli.setup(prompt=ask, home=home) == 0
    assert len(prompts) == 5
    config = ep._config()
    assert bool(config['guard_lock']) == (preset != 'standard')
    assert 'PostToolUse' in cli._read_settings(home / '.claude/settings.json')['hooks']
    codex = cli._read_settings(home / '.codex/config.toml')
    assert codex['web_search'] == 'disabled'
    assert codex['shell_environment_policy']['ignore_default_excludes'] is False
    if preset != 'standard':
        assert str(Path(cli.__file__).resolve().parent) in config['guard_lock']['paths']
        assert str(Path(sys.prefix).resolve()) in config['guard_lock']['paths']


def test_wizard_cancel_dry_run_and_temp(home, monkeypatch):
    answers = iter(['claude', 'user', 'standard', 'n', 'n'])
    assert cli.setup(prompt=lambda _: next(answers), home=home) == 0
    assert not (home / '.claude').exists()
    monkeypatch.setattr(m, 'temporary_interpreter', lambda: True)
    assert cli.setup(['claude'], 'user', 'standard', True, home=home) == 2
    assert not (home / '.claude').exists()


@pytest.mark.parametrize('client', ['claude', 'codex'])
@pytest.mark.parametrize('scope', ['user', 'project'])
def test_receipt_three_way_round_trip(home, client, scope):
    kwargs = {'home': home, 'project': home}
    targets = cli._targets(client, scope, **kwargs)
    cli.install(client, scope, True, **kwargs)
    path = targets[0]
    current = cli._read_settings(path)
    current['unrelated'] = 'keep'
    if client == 'claude':
        current['permissions']['deny'].append('user-added')
        current['hooks']['PreToolUse'][0]['matcher'] = 'user-edit'
        path.write_text(json.dumps(current))
    else:
        with path.open('a') as stream:
            stream.write('\n[unrelated]\nvalue = "keep"\n')
    _, _, changes, conflicts, _ = receipt.uninstall_plan(client, scope, **kwargs)
    result = {p: (tomllib.loads(text) if p.suffix == '.toml' else json.loads(text)) for p, _, text in changes}
    assert result[path]['unrelated']
    if client == 'claude':
        assert result[path]['permissions']['deny'] == ['user-added']
        assert result[path]['hooks']['PreToolUse'][0]['matcher'] == 'user-edit'
        assert 'hooks.PreToolUse' in conflicts
    else:
        assert 'web_search' not in result[path]
        assert 'mcp_servers' not in result[path]
        assert not conflicts


@pytest.mark.parametrize('prior', ['live', 'cached', 'disabled', None])
def test_receipt_prior_scalar(home, prior):
    target = home / '.codex/config.toml'
    target.parent.mkdir()
    target.write_text('web_search = ' + json.dumps(prior) if prior else '# comment\n')
    cli.install('codex', apply=True, home=home)
    _, _, changes, conflicts, _ = receipt.uninstall_plan('codex', home=home)
    result = [tomllib.loads(text) for path, _, text in changes if path == target][-1]
    assert result.get('web_search') == prior
    assert not conflicts


def test_interrupted_journal_not_replayed(home, monkeypatch, capsys):
    real = m.atomic_write
    def fail(path, *args, **kwargs):
        if path.name == 'hooks.json':
            raise OSError('synthetic interruption')
        return real(path, *args, **kwargs)
    monkeypatch.setattr(m, 'atomic_write', fail)
    with pytest.raises(OSError):
        cli.install('codex', apply=True, home=home)
    assert receipt.load()['transactions'][-1]['state'] == 'pending'
    with pytest.raises(ValueError, match='interrupted'):
        receipt.uninstall_plan('codex', home=home)
    assert cli.doctor('codex', home=home) == 1
    assert 'install journal' in capsys.readouterr().out


@pytest.mark.parametrize('client', ['claude', 'codex'])
def test_replace_interpreter(home, monkeypatch, client):
    cli.install(client, apply=True, home=home)
    monkeypatch.setattr(cli.sys, 'executable', 'C:/Stable Python/python.exe')
    with pytest.raises(ValueError):
        cli.install(client, apply=True, home=home)
    assert cli.install(client, apply=True, home=home, replace=True) == 0
    settings = [cli._read_settings(p) for p in cli._targets(client, 'user', home=home)]
    assert 'Stable Python' in json.dumps(settings)


def test_editor_handoff_never_values(home, monkeypatch, capsys):
    path = home / 'policy/config.json'
    path.write_text('{"_note": "sentinel-private", "guard_lock": true}')
    calls = []
    monkeypatch.setenv('EDITOR', '"C:/Owner Editor/editor.exe" --wait')
    monkeypatch.setattr(m.subprocess, 'Popen', lambda args, **kwargs: calls.append((args, kwargs)))
    before = path.read_bytes()
    assert cli.configure('guard-lock', loosen=True, editor=True) == 0
    assert path.read_bytes() == before
    assert calls[0][0] == ['C:/Owner Editor/editor.exe', '--wait', str(path)]
    assert 'sentinel-private' not in capsys.readouterr().out


@pytest.mark.parametrize('command,denied', [
    ('python -m siftfetch doctor', False), ('siftfetch status --json', False),
    ('py -3 -I -m siftfetch setup --preset strict --client codex --scope user', False),
    ('siftfetch uninstall --client codex', False), ('siftfetch install --replace --client claude', False),
    ('siftfetch tighten guard-lock', False), ('siftfetch --help', False),
    ('python -m siftfetch uninstall --apply', True), ('siftfetch configure', True),
    ('siftfetch uninstall --client claude --scope project --apply', True),
    ('py -3 -I -m siftfetch.cli uninstall --apply --client codex', True),
    ('powershell -Command "siftfetch uninstall --apply"', True),
    ('siftfetch uninstall --apply --yes', True),
    ('siftfetch setup --preset lockdown --client codex --scope user', False),
    ('siftfetch setup', True), ('siftfetch setup --preset standard', True),
    ('"C:/Any Interpreter/runtime.exe" -m siftfetch install --replace --apply', True),
    ('py -3 -m siftfetch.cli unknown', True), ('siftfetch doctor --apply', True),
    ('cmd /c "siftfetch uninstall --apply"', True),
    ('powershell -Command "siftfetch configure"', True),
    ('bash -c \'cmd /c "siftfetch configure"\'', True),
    ('echo "python -m siftfetch uninstall --apply"', False),
    ('cat <<\'EOF\'\npython -m siftfetch uninstall --apply\nEOF', False),
    ('tee notes <<\'EOF\'\nsiftfetch configure\nEOF', False),
    ('git commit -m "siftfetch configure"', False),
])
def test_management_command_table(command, denied):
    assert hook._management_command_denied(command) is denied


@pytest.mark.parametrize('name', ['.codex/hooks.json', '.claude.json'])
@pytest.mark.parametrize('operation', ['edit', 'redirect', 'delete', 'rename'])
def test_new_guard_paths(home, name, operation):
    (home / 'policy/config.json').write_text('{"guard_lock": true}')
    if operation == 'edit':
        result, _ = hook._locked_target('Edit', {'file_path': str(home / name)}, str(home))
    else:
        commands = {'redirect': f'echo x > {name}', 'delete': f'rm {name}', 'rename': f'mv {name} other'}
        result = hook._shell_locked(commands[operation], str(home), list(ep.GUARD_LOCK_PATHS))
    assert result


def test_legacy_plan_retains_uncertain_settings(home):
    cli.install('claude', apply=True, home=home)
    (home / 'policy/install-manifest.json').unlink()
    _, records, changes, conflicts, _ = receipt.uninstall_plan('claude', home=home)
    assert not records and conflicts
    settings = [json.loads(text) for p, _, text in changes if p.name == 'settings.json'][-1]
    assert settings['permissions']['deny'] == cli._entries('claude')[2]
    assert settings['hooks']['PreToolUse'] == []


def test_manifest_ignored_and_unknown_keys_rejected(home):
    before = ep.policy_fingerprint()
    cli.install('codex', apply=True, home=home)
    assert ep.policy_fingerprint() == before
    assert ep.policy_status()['loaded']
    path = home / 'policy/install-manifest.json'
    data = json.loads(path.read_text())
    data['unknown'] = True
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        receipt.load()


def test_duplicate_owned_entry_is_conflict(home):
    cli.install('claude', apply=True, home=home)
    target = home / '.claude/settings.json'
    settings = cli._read_settings(target)
    settings['hooks']['PreToolUse'] *= 2
    target.write_text(json.dumps(settings))
    _, _, changes, conflicts, _ = receipt.uninstall_plan('claude', home=home)
    assert 'hooks.PreToolUse' in conflicts
    result = [json.loads(text) for p, _, text in changes if p == target][-1]
    assert len(result['hooks']['PreToolUse']) == 2


@pytest.mark.parametrize('client', ['claude', 'codex'])
def test_replace_transfers_ownership(home, monkeypatch, client):
    cli.install(client, apply=True, home=home)
    monkeypatch.setattr(cli.sys, 'executable', 'C:/Stable New/python.exe')
    cli.install(client, apply=True, home=home, replace=True)
    _, _, changes, conflicts, _ = receipt.uninstall_plan(client, home=home)
    assert not conflicts
    final = {path: text for path, _, text in changes}
    for text in final.values():
        assert 'Stable New' not in text


def test_sentinel_new_output_surfaces(home, capsys):
    path = home / 'policy/config.json'
    path.write_text(json.dumps({'contact_alias': 'sentinel-contact@mail.example.com',
                               'substitute': {'name': 'sentinel-substitute'},
                               'guard_lock': {'enabled': True, 'paths': ['sentinel-path']},
                               'blocked_domains': ['sentinel-domain.example']}))
    (home / 'policy/identifiers.json').write_text(json.dumps({'values': [
        {'label': 'sentinel-label', 'value': 'sentinel-identity', 'kind': 'text', 'class': 'exact'}]}))
    cli.setup(['claude'], 'user', 'standard', True, home=home)
    cli.configure()
    cli.uninstall('claude', home=home)
    result = tools.tighten({'secret_file_mode': 'strict'})
    output = capsys.readouterr()
    assert 'sentinel-' not in output.out + output.err + json.dumps(result)
    assert 'sentinel-' not in (home / 'policy/install-manifest.json').read_text()


def test_coexisting_formats_both_tighten(home):
    path = home / 'policy/config.json'
    path.write_text('{"guard_lock": false}')
    other = path.with_suffix('.toml')
    other.write_text('# owner\nguard_lock = false # keep\n')
    assert tools.tighten({'guard_lock': True}) == {'ok': True, 'changed_files': 2, 'message': 'Tightening applied.'}
    assert ep.policy_status()['loaded']
    assert '# owner' in other.read_text() and '# keep' in other.read_text()


def test_failed_replace_preserves_policy(home, monkeypatch):
    path = home / 'policy/config.json'
    original = path.read_bytes()
    def fail(*args):
        raise OSError('synthetic-private-error')
    monkeypatch.setattr(m.os, 'replace', fail)
    result = tools.tighten({'guard_lock': True})
    assert not result['ok'] and result['changed_files'] == 0
    assert path.read_bytes() == original
    assert list(path.parent.glob('config.json.siftfetch-backup-*'))  # backup retained
    assert 'synthetic-private-error' not in json.dumps(result)


def test_policy_change_between_baseline_and_plan_refuses(home, monkeypatch):
    path = home / 'policy/config.json'
    path.write_text('{"guard_lock": false}')
    original = m.baseline
    def race(**kwargs):
        result = original(**kwargs)
        path.write_text('{"guard_lock": {"enabled": true, "paths": ["keep"]}}')
        return result
    monkeypatch.setattr(m, 'baseline', race)
    assert not tools.tighten({'guard_lock': True})['ok']
    assert json.loads(path.read_text())['guard_lock']['paths'] == ['keep']


def test_client_classifier_preserves_coverage_and_unrelated_entries():
    hooks, server, _ = cli._entries('claude')
    before = {'hooks': {'PreToolUse': []}, 'custom': 'keep'}
    after = {'hooks': hooks, 'custom': 'keep', 'mcpServers': {'siftfetch': server}}
    assert m.client_transition(before, after)
    assert not m.client_transition(after, before)
    assert not m.client_transition(before, {**after, 'custom': 'changed'})


def test_replace_preserves_isolation_flags(home, monkeypatch):
    cli.install('claude', apply=True, home=home)
    settings = home / '.claude/settings.json'
    data = cli._read_settings(settings)
    data['hooks']['PreToolUse'][0]['hooks'][0]['command'] = '"C:/Old/python.exe" -I -m siftfetch.hook --deny'
    settings.write_text(json.dumps(data))
    monkeypatch.setattr(cli.sys, 'executable', 'C:/New/python.exe')
    cli.install('claude', apply=True, home=home, replace=True)
    commands = [entry['hooks'][0]['command'] for entry in cli._read_settings(settings)['hooks']['PreToolUse']]
    assert any('"-I"' in command and '"--deny"' in command and 'C:/New/' in command for command in commands)


@pytest.mark.parametrize('prior', [None, 'disabled', 'live'])
@pytest.mark.parametrize('scope', ['user', 'project'])
def test_uninstall_apply_round_trip(home, prior, scope):
    kwargs = {'home': home, 'project': home}
    codex = cli._targets('codex', scope, **kwargs)[0]
    codex.parent.mkdir()
    codex.write_text('# owner comment\n' + ('web_search = ' + json.dumps(prior) + '\n' if prior else ''))
    claude = cli._targets('claude', scope, **kwargs)[0]
    claude.parent.mkdir()
    existing = ['WebFetch', 'Read(**/.env)', 'owner-deny']
    claude.write_text(json.dumps({'permissions': {'deny': existing}, 'owner': 'keep'}))
    policies = {p: p.read_bytes() for p in (home / 'policy').glob('*.json')}
    assert cli.setup(['claude', 'codex'], scope, 'standard', True, **kwargs) == 0
    assert cli._read_settings(codex)['web_search'] == 'disabled'
    backups = receipt.uninstall_plan(scope=scope, **kwargs)[4]
    assert backups
    prompts = []
    def ask(text):
        prompts.append(text)
        return 'uninstall' if len(prompts) == 1 else ''
    assert cli.uninstall(scope=scope, apply=True, prompt=ask, **kwargs) == 0
    assert len(prompts) == 2 and 'client tokens' in prompts[1] and '[y/N]' in prompts[1]
    assert cli._read_settings(codex) == ({'web_search': prior} if prior else {})
    assert '# owner comment' in codex.read_text()
    assert cli._read_settings(claude) == {'permissions': {'deny': existing}, 'owner': 'keep'}
    assert all(Path(name).is_file() for name in backups)
    assert all(p.read_bytes() == raw for p, raw in policies.items())
    assert (home / 'policy').is_dir()
    assert all(tx['state'] == 'removed' for tx in receipt.load()['transactions'])


@pytest.mark.parametrize('answer', ['', 'yes', 'UNINSTALL', 'uninstall '])
def test_uninstall_wrong_confirmation_changes_nothing(home, answer):
    cli.install('codex', apply=True, home=home)
    paths = [*cli._targets('codex', 'user', home), home / 'policy/install-manifest.json']
    before = {p: p.read_bytes() for p in paths}
    assert cli.uninstall('codex', apply=True, home=home, prompt=lambda _: answer) == 2
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_uninstall_apply_preserves_conflicts(home):
    cli.install('claude', apply=True, home=home)
    target = home / '.claude/settings.json'
    current = cli._read_settings(target)
    current['hooks']['PreToolUse'][0]['matcher'] = 'owner-edit'
    current['permissions']['deny'].append('owner-added')
    target.write_text(json.dumps(current))
    assert cli.uninstall('claude', apply=True, home=home, prompt=lambda _: 'uninstall') == 0
    result = cli._read_settings(target)
    assert result['hooks']['PreToolUse'] == current['hooks']['PreToolUse']
    assert result['permissions']['deny'] == ['owner-added']


@pytest.mark.parametrize('client', ['claude', 'codex'])
def test_legacy_uninstall_apply(home, client):
    cli.install(client, apply=True, home=home)
    (home / 'policy/install-manifest.json').unlink()
    target = cli._targets(client, 'user', home)[0]
    before = cli._read_settings(target)
    assert cli.uninstall(client, apply=True, home=home, prompt=lambda _: 'uninstall') == 0
    after = cli._read_settings(target)
    if client == 'claude':
        assert after['permissions'] == before['permissions']
        assert all(not groups for groups in after['hooks'].values())
    else:
        assert after['web_search'] == before['web_search']
        assert after['shell_environment_policy'] == before['shell_environment_policy']
    assert 'siftfetch' not in after.get('mcp_servers', {})
    assert not (home / 'policy/install-manifest.json').exists()


def test_uninstall_deletes_only_listed_backups(home):
    target = home / '.codex/config.toml'
    target.parent.mkdir()
    target.write_text('# owner\n')
    cli.install('codex', apply=True, home=home)
    backups = receipt.uninstall_plan('codex', home=home)[4]
    unlisted = target.with_name(target.name + '.siftfetch-backup-' + 'f' * 32)
    unlisted.write_text('unowned')
    answers = iter(['uninstall', 'y'])
    assert cli.uninstall('codex', apply=True, home=home, prompt=lambda _: next(answers)) == 0
    assert all(not Path(name).exists() for name in backups)
    assert unlisted.read_text() == 'unowned'


def test_uninstall_requires_terminal_and_has_no_yes(home, monkeypatch):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    assert cli.uninstall('codex', apply=True, home=home) == 2
    with pytest.raises(SystemExit):
        cli.main(['uninstall', '--apply', '--yes'])


@pytest.mark.parametrize('preset', ['standard', 'custom', 'custom guard-lock', 'lockdown'])
def test_presets_keep_or_tighten(home, preset):
    path = home / 'policy/config.json'
    path.write_text(json.dumps({'guard_lock': False, 'secret_file_mode': 'standard',
                                'browser_fetch': {'mode': 'on-wall'}}))
    assert cli.setup(['claude'], 'user', preset, True, home=home) == 0
    config = json.loads(path.read_text())
    assert bool(config['guard_lock']) == (preset in ('custom guard-lock', 'lockdown'))
    assert config['secret_file_mode'] == ('strict' if preset == 'lockdown' else 'standard')
    assert config['browser_fetch']['mode'] == ('off' if preset == 'lockdown' else 'on-wall')
    assert 'PostToolUse' in cli._read_settings(home / '.claude/settings.json')['hooks']


def test_standard_preserves_existing_lock(home):
    path = home / 'policy/config.json'
    path.write_text('{"guard_lock": {"enabled": true, "paths": ["owner-path"]}}')
    before = path.read_bytes()
    assert cli.setup(['codex'], 'user', 'standard', True, home=home) == 0
    assert path.read_bytes() == before


def test_repeated_uninstall_preserves_preexisting_registration(home):
    hooks, server, deny = cli._entries('claude')
    target, mcp = cli._targets('claude', 'user', home)
    target.parent.mkdir()
    original = {'hooks': hooks, 'permissions': {'deny': deny}}
    target.write_text(json.dumps(original))
    mcp.write_text(json.dumps({'mcpServers': {'siftfetch': server}}))
    cli.install('claude', apply=True, home=home)
    for _ in range(2):
        assert cli.uninstall('claude', apply=True, home=home, prompt=lambda _: 'uninstall') == 0
        assert cli._read_settings(target) == original
        assert cli._read_settings(mcp) == {'mcpServers': {'siftfetch': server}}


def test_uninstall_confirmation_race_refuses_before_mutation(home):
    cli.install('codex', apply=True, home=home)
    target, hooks = cli._targets('codex', 'user', home)
    original_hooks = hooks.read_bytes()
    def ask(_):
        target.write_text('# owner replaced settings\n')
        return 'uninstall'
    with pytest.raises(ValueError, match='changed during uninstall'):
        cli.uninstall('codex', apply=True, home=home, prompt=ask)
    assert hooks.read_bytes() == original_hooks
    assert receipt.load()['transactions'][0]['state'] == 'complete'


def test_uninstall_failure_keeps_backups_and_journal_pending(home, monkeypatch):
    target = home / '.codex/config.toml'
    target.parent.mkdir()
    target.write_text('# keep\n')
    cli.install('codex', apply=True, home=home)
    backups = receipt.uninstall_plan('codex', home=home)[4]
    calls = []
    def fail(*args, **kwargs):
        raise OSError('synthetic failure')
    monkeypatch.setattr(m, 'atomic_write', fail)
    def ask(text):
        calls.append(text)
        return 'uninstall'
    with pytest.raises(OSError):
        cli.uninstall('codex', apply=True, home=home, prompt=ask)
    assert len(calls) == 1
    assert all(Path(name).is_file() for name in backups)
    assert receipt.load()['transactions'][0]['state'] == 'pending'


@pytest.mark.parametrize('scope', ['user', 'project'])
def test_uninstall_removes_files_and_servers_setup_created(home, scope):
    kwargs = {'home': home, 'project': home}
    claude_settings, claude_mcp = cli._targets('claude', scope, **kwargs)
    codex_config, codex_hooks = cli._targets('codex', scope, **kwargs)
    claude_mcp.parent.mkdir(parents=True, exist_ok=True)
    claude_mcp.write_text(json.dumps({'mcpServers': {'other': {'command': 'x'}}}))
    assert not codex_hooks.exists()
    assert cli.setup(['claude', 'codex'], scope, 'standard', True, **kwargs) == 0
    assert codex_hooks.exists() and 'siftfetch' in cli._read_settings(claude_mcp)['mcpServers']
    answers = iter(['uninstall', ''])
    assert cli.uninstall(scope=scope, apply=True, prompt=lambda _: next(answers), **kwargs) == 0
    assert cli._read_settings(claude_mcp) == {'mcpServers': {'other': {'command': 'x'}}}
    hooks_left = cli._read_settings(codex_hooks) if codex_hooks.exists() else {}
    assert not any(hooks_left.get('hooks', {}).values())
    assert 'mcp_servers' not in cli._read_settings(codex_config)
    assert 'hooks' not in cli._read_settings(claude_settings)


def test_statement_starts_tracks_multiline_values():
    text = ('a = """x\n[not.a.table]\n"""\n'
            "b = '''y\n[still.text]'''\n"
            'c = [\n  [1, 2],\n  "]",\n]\n'
            'd = { e = "[" } # [comment\n'
            '[real]\n')
    starts = m.statement_starts(text.splitlines(keepends=True))
    assert starts == [True, False, False, True, False, True, False, False, False, True, True]


def test_large_codex_config_edits_quickly():
    import time
    # Owner configs gain a [projects.'...'] table per trusted folder.
    text = '# owner\nmodel = "x"\n' + ''.join(
        f"[projects.'c:\\work\\p{i}']\ntrust_level = \"trusted\"\n\n" for i in range(3000))
    intended = tomllib.loads(text) | {'web_search': 'disabled'}
    started = time.monotonic()
    edited = m.edit_toml(text, intended)
    assert tomllib.loads(edited) == intended and '# owner' in edited
    assert time.monotonic() - started < 10


CODEX_TOML_HOOKS = '''# owner settings
model = "example"

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "other-guard"

[mcp_servers.siftfetch]
command = "C:/Legacy/sf/python.exe"
args = ["-I", "-m", "siftfetch.server"]

# SiftFetch privacy guard (hand-written)
[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch|Edit|Write|mcp__.*)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '"C:/Legacy/sf/python.exe" "-I" "-m" "siftfetch.hook" "--deny"'
timeout = 30
statusMessage = "SiftFetch privacy guard"

[hooks.state]

[hooks.state.'C:/x/config.toml:pre_tool_use:0:0']
trusted_hash = "sha256:00"
'''


def test_adopt_codex_hooks_written_as_toml_arrays(home):
    # The layout Codex documents, as hand-wired installs have it.
    config, hookfile = cli._targets('codex', 'user', home)
    config.parent.mkdir(exist_ok=True)
    config.write_text(CODEX_TOML_HOOKS)
    assert cli.install('codex', home=home, adopt=True, apply=True) == 0
    adopted = tomllib.loads(config.read_text())
    entries = adopted['hooks']['PreToolUse']
    assert entries[0]['hooks'][0]['command'] == 'other-guard'
    command = entries[1]['hooks'][0]['command']
    assert '"-I"' in command and '"--deny"' in command and 'Legacy' not in command
    assert entries[1]['matcher'] == '^(Bash|apply_patch|Edit|Write|mcp__.*)$'
    assert adopted['hooks']['state'] and adopted['mcp_servers']['siftfetch']['args'][0] == '-I'
    assert '# owner settings' in config.read_text()
    assert cli.doctor('codex', home=home) == 0
    # A later plain install uses the other TOML editor; it must find what adopt wrote.
    adopted_text = config.read_bytes()
    assert cli.install('codex', home=home, apply=True) == 0
    assert config.read_bytes() == adopted_text
    answers = iter(['uninstall', ''])
    assert cli.uninstall('codex', apply=True, home=home, prompt=lambda _: next(answers)) == 0
    left = tomllib.loads(config.read_text())
    assert [e['hooks'][0]['command'] for e in left['hooks']['PreToolUse']] == ['other-guard']
    assert 'siftfetch' not in left.get('mcp_servers', {}) and left['hooks']['state']
