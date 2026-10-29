"""Redacted diagnostics and client checks, using synthetic homes only."""
import asyncio
import json
from pathlib import Path
import sys

import pytest

from siftfetch import cli, egress_policy as ep, server, tools


@pytest.fixture
def policy(tmp_path, monkeypatch):
    folder = tmp_path / '.siftfetch'
    folder.mkdir()
    monkeypatch.setenv('SIFTFETCH_HOME', str(folder))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    (folder / 'identifiers.json').write_text('{"values": []}')
    return folder


def write(folder, name, data):
    (folder / (name + '.json')).write_text(json.dumps(data), encoding='utf-8')


def test_sentinel_leaks_across_all_surfaces(policy, tmp_path, monkeypatch, capsys):
    sentinels = []
    def sentinel(name):
        value = 'sentinel-' + name + '-unique'
        sentinels.append(value)
        return value
    write(policy, 'identifiers', {'values': [
        {'label': sentinel('label'), 'value': sentinel('identifier'), 'kind': 'text', 'class': 'exact'},
        {'label': sentinel('softlabel'), 'value': sentinel('softvalue'), 'kind': 'text', 'class': 'soft', 'public_search': True}]})
    alias = sentinel('alias') + '@mail.example.com'
    config = {'contact_alias': alias, 'substitute': {k: sentinel(k) for k in ('name', 'phone', 'organization', 'postal_address')},
              'blocked_domains': [sentinel('blocked') + '.example'],
              'cookie_origins': ['https://' + sentinel('cookie') + '.example'],
              'local_endpoints': [{'scheme': 'http', 'host': sentinel('host') + '.example', 'port': 1234}],
              'mcp_local_tools': [sentinel('mcp')],
              'guard_lock': {'enabled': True, 'paths': [sentinel('guard')]},
              'download_dir': str(tmp_path / sentinel('download')),
              'browser_fetch': {'mode': 'on-wall', 'sites': [sentinel('site')]}}
    write(policy, 'config', config)
    grants = [{'label': sentinel('grantlabel'), 'op': 'fetch', 'origin': 'https://' + sentinel('origin') + '.example',
               'location': 'query', 'path_prefix': '/' + sentinel('prefix'), 'expires': '2099-01-01T00:00:00Z'},
              {'label': sentinel('shelllabel'), 'op': 'shell', 'command_prefix': 'echo ' + sentinel('command'),
               'expires': '2000-01-01T00:00:00Z'}, {'op': sentinel('invalidop')}]
    write(policy, 'exceptions', {'exceptions': grants})
    monkeypatch.setenv('SIFTFETCH_DATA', str(tmp_path / sentinel('data')))
    result = ep.policy_status()
    assert result['loaded'] and result['error'] is None
    assert result['identifiers']['total'] == 2
    assert result['identifiers']['public_search'] == 1
    assert result['exceptions'] == {'fetch': {'active': 1, 'expired': 0, 'invalid': 0},
        'shell': {'active': 0, 'expired': 1, 'invalid': 0}, 'other': {'active': 0, 'expired': 0, 'invalid': 1}}
    assert result['config']['contact_alias'] == {'status': 'set', 'source': 'config'}
    assert set(result['config']) == ep.CONFIG_KEYS
    assert tools.policy_status() == result
    assert asyncio.run(server.policy_status()) == result
    # Exercise the registered MCP serialization boundary too.
    mcp_result = asyncio.run(server.mcp.call_tool('policy_status', {}))
    outputs = [json.dumps(result), str(mcp_result)]
    for as_json in (False, True):
        cli.doctor(home=tmp_path, json_output=as_json)
        output = capsys.readouterr().out
        if as_json:
            assert json.loads(output)['policy_status'] == result
        outputs.append(output)
    for output in outputs:
        assert all(value not in output for value in sentinels)
    assert not (tmp_path / 'sentinel-download-unique').exists()


@pytest.mark.parametrize('as_json', [False, True])
def test_malformed_never_raises(policy, tmp_path, capsys, as_json):
    write(policy, 'config', {'enabled': 'sentinel-bad-value'})
    for result in (ep.policy_status(), tools.policy_status(), asyncio.run(server.policy_status())):
        assert not result['loaded']
        assert result['error'] == 'config.json: enabled is invalid'
        assert result['protection']['enabled'] is True
    assert cli.doctor(home=tmp_path, json_output=as_json) == 1
    assert 'sentinel-bad-value' not in capsys.readouterr().out


def test_unexpected_error_redacted(policy, monkeypatch):
    def fail():
        raise OSError('sentinel-private-path')
    monkeypatch.setattr(ep, '_load_policy', fail)
    result = tools.policy_status()
    assert not result['loaded'] and 'sentinel' not in json.dumps(result)


@pytest.mark.parametrize('alias,expected', [('alias@example.invalid', None), ('alias@mail.example.com', 'config'), ('', 'unset')])
def test_alias_validity(policy, alias, expected):
    write(policy, 'config', {'contact_alias': alias})
    config = ep.policy_status()['config']
    if expected is None:
        assert 'contact_alias' not in config
    elif expected == 'unset':
        assert config['contact_alias']['status'] == 'unset'
    else:
        assert config['contact_alias']['source'] == expected


def test_environment_and_formats(policy, monkeypatch):
    (policy / 'identifiers.toml').write_text('values = []')
    monkeypatch.setenv('SIFTFETCH_CONTACT_ALIAS', 'synthetic@mail.example.com')
    monkeypatch.setenv('SIFTFETCH_ENABLED', '0')
    result = ep.policy_status()
    assert result['files']['identifiers']['format'] == 'toml'
    assert result['files']['identifiers']['warning']
    assert result['config']['contact_alias']['source'] == 'env'
    assert result['env']['SIFTFETCH_ENABLED'] == '0'
    assert result['protection'] == {'enabled': False, 'config_disabled': False, 'env_disabled': True}
    monkeypatch.setenv('SIFTFETCH_ENABLED', 'sentinel-invalid-switch')
    assert ep.policy_status()['env']['SIFTFETCH_ENABLED'] == 'set'


def installed(tmp_path, client):
    cli.install(client, home=tmp_path, apply=True)
    return cli._targets(client, 'user', home=tmp_path)


def checks(tmp_path, capsys, client):
    capsys.readouterr()
    cli.doctor(client, home=tmp_path, json_output=True)
    return json.loads(capsys.readouterr().out)['checks']


@pytest.mark.parametrize('client', ['claude', 'codex'])
def test_other_interpreter_isolation_flags_and_mcp(policy, tmp_path, capsys, client):
    paths = installed(tmp_path, client)
    interpreter = tmp_path / 'Other Python' / 'python.exe'
    interpreter.parent.mkdir()
    interpreter.touch()  # Existence only; doctor must never execute it.
    target = paths[0 if client == 'claude' else 1]
    data = json.loads(target.read_text())
    for entries in data['hooks'].values():
        for entry in entries:
            entry['hooks'][0]['command'] = f'"{interpreter}" -I -m siftfetch.hook --deny'
    target.write_text(json.dumps(data))
    target = paths[1 if client == 'claude' else 0]
    if client == 'claude':
        data = json.loads(target.read_text())
        data['mcpServers']['siftfetch'] = {'command': str(interpreter), 'args': ['-I', '-m', 'siftfetch.server']}
        target.write_text(json.dumps(data))
    else:
        text = target.read_text().replace(json.dumps(sys.executable.replace('\\', '/')), json.dumps(str(interpreter)))
        target.write_text(text.replace('["-m", "siftfetch.server"]', '["-I", "-m", "siftfetch.server"]'))
    results = checks(tmp_path, capsys, client)
    assert all(r['status'] != 'FAIL' for r in results)
    assert any('registered with a different interpreter' in r['detail'] for r in results)
    interpreter.unlink()
    assert any(r['status'] == 'FAIL' and 'MCP server' in r['check'] for r in checks(tmp_path, capsys, client))


def test_matcher_union_missing_tool_and_post_hook(policy, tmp_path, capsys):
    target, _ = installed(tmp_path, 'claude')
    data = json.loads(target.read_text())
    entry = data['hooks']['PreToolUse'][0]
    entry['matcher'] = 'WebSearch|Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|apply_patch|mcp__.*'
    target.write_text(json.dumps(data))
    results = checks(tmp_path, capsys, 'claude')
    assert any(r['status'] == 'FAIL' and r['detail'] == 'uncovered tool names: WebFetch' for r in results)
    data['hooks']['PreToolUse'].append({**entry, 'matcher': 'WebFetch'})
    target.write_text(json.dumps(data))
    assert all(r['status'] != 'FAIL' for r in checks(tmp_path, capsys, 'claude'))
    data['hooks']['PostToolUse'][0]['matcher'] = 'mcp__claude-in-chrome__get_page_text'
    target.write_text(json.dumps(data))
    assert any(r['status'] == 'FAIL' and 'read_page' in r['detail'] for r in checks(tmp_path, capsys, 'claude'))


def test_claude_hooks_json(policy, tmp_path, capsys):
    target, _ = installed(tmp_path, 'claude')
    data = json.loads(target.read_text())
    target.with_name('hooks.json').write_text(json.dumps({'hooks': data.pop('hooks')}))
    target.write_text(json.dumps(data))
    # Claude Code reads hooks only from settings files; ~/.claude/hooks.json is
    # a plugin-only name, so a hook parked there is not registered.
    failed = [r['check'] for r in checks(tmp_path, capsys, 'claude') if r['status'] == 'FAIL']
    assert 'claude hook entry PreToolUse' in failed


@pytest.mark.parametrize('prefix', ['~/.siftfetch', '//ABSOLUTE'])
def test_equivalent_deny_rules(policy, tmp_path, capsys, prefix):
    target, _ = installed(tmp_path, 'claude')
    data = json.loads(target.read_text())
    replacement = '//' + policy.as_posix() if prefix == '//ABSOLUTE' else prefix
    data['permissions']['deny'] = [rule.replace(policy.as_posix(), replacement) for rule in data['permissions']['deny']]
    target.write_text(json.dumps(data))
    assert all(r['status'] != 'FAIL' for r in checks(tmp_path, capsys, 'claude'))


@pytest.mark.parametrize('client', ['claude', 'codex'])
def test_builtin_web_pass_fail(policy, tmp_path, capsys, client):
    paths = installed(tmp_path, client)
    assert all(r['status'] == 'PASS' for r in checks(tmp_path, capsys, client) if 'built-in web' in r['check'])
    target = paths[0]
    if client == 'claude':
        data = json.loads(target.read_text())
        data['permissions']['deny'].remove('WebFetch')
        target.write_text(json.dumps(data))
    else:
        target.write_text(target.read_text().replace('"disabled"', '"live"'))
    assert any(r['status'] == 'FAIL' for r in checks(tmp_path, capsys, client) if 'built-in web' in r['check'])


def test_doctor_json_cli(policy, tmp_path, monkeypatch, capsys):
    installed(tmp_path, 'claude')
    capsys.readouterr()
    assert cli.main(['doctor', '--client', 'claude', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['policy_status']['loaded']



@pytest.mark.parametrize('args,valid', [
    (['-I', '-X', 'utf8', '-W', 'ignore', '-m', 'siftfetch.hook', '--deny'], True),
    (['-c', 'print(1)', '-m', 'siftfetch.hook'], False),
    (['script.py', '-m', 'siftfetch.hook'], False),
    (['--version', '-m', 'siftfetch.hook'], False),
])
def test_module_command_recognition(args, valid):
    assert (cli._module_interpreter(['python', *args], 'siftfetch.hook') is not None) == valid
