"""Owner setup commands. No network, models, credential discovery or CLI spawning."""
from __future__ import annotations

import argparse
import copy
from datetime import date, datetime, time
import importlib
from importlib import metadata
from importlib import resources
import json
import os
import re
import shlex
import shutil
from pathlib import Path
import sys
import tomllib
import uuid

from siftfetch import egress_policy as policy, saving
from siftfetch import management, receipt


def _safe_path(path):
    for part in (path, *path.absolute().parents):
        if saving.is_link(part):
            raise ValueError('refusing a link or junction; choose a regular local path')


def initialize():
    """Copy packaged examples, exclusively; never read an existing policy file."""
    base = policy.policy_dir()
    _safe_path(base)
    base.mkdir(parents=True, exist_ok=True)
    for stem in ('identifiers', 'exceptions', 'config'):
        if any((base / (stem + ext)).exists() for ext in ('.json', '.toml')):
            print(f'SKIP {stem}: already present; unchanged')
            continue
        text = resources.files('siftfetch').joinpath('templates', stem + '.json').read_text(encoding='utf-8')
        if saving._write_new(base / (stem + '.json'), text):
            print(f'CREATED {stem}.json: example only; owner must configure it')
    print('Owner: edit identifiers in your own editor; never paste protected values into chat.')
    return 0


def _targets(client, scope, home=None, project=None):
    base = Path(home) if home is not None else Path.home()
    if scope == 'project':
        base = Path(project) if project is not None else Path.cwd()
    if client == 'claude':
        return base / '.claude/settings.json', base / ('.claude.json' if scope == 'user' else '.mcp.json')
    return base / '.codex/config.toml', base / '.codex/hooks.json'


def _entries(client):
    # -I keeps the working folder off sys.path: a repo holding its own
    # siftfetch package must not be able to replace the guard or server.
    command = '"' + sys.executable.replace('\\', '/') + '" -I -m siftfetch.hook'
    if client == 'codex':
        command = '"' + sys.executable.replace('\\', '/') + '" "-I" "-m" "siftfetch.hook" "--deny"'
    hook = {'type': 'command', 'command': command}
    if client == 'claude':
        hook['onFailure'] = 'block'
    matcher = '^(WebFetch|WebSearch|Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|apply_patch|mcp__.*)$'
    hooks = {'PreToolUse': [{'matcher': matcher, 'hooks': [hook]}]}
    if client == 'claude':
        hooks['PostToolUse'] = [{'matcher': 'mcp__claude-in-chrome__(get_page_text|read_page|find|javascript_tool)',
                                 'hooks': [dict(hook)]}]
    server = {'command': sys.executable.replace('\\', '/'), 'args': ['-I', '-m', 'siftfetch.server']}
    folder = policy.policy_dir().as_posix()
    deny = [f'Read({folder}/**)', f'Edit({folder}/**)', 'Read(**/.env)', 'Read(**/.env.*)',
            'Read(//**/.env)', 'Read(//**/.env.*)', 'WebFetch', 'WebSearch']
    return hooks, server, deny


def _read_settings(path, *, raw=None):
    _safe_path(path)
    if not path.exists():
        return {}
    try:
        text = (path.read_bytes() if raw is None else raw).decode('utf-8')
        value = tomllib.loads(text) if path.suffix == '.toml' else json.loads(text)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, OSError):
        raise ValueError('client config is unreadable or malformed; repair it before installation') from None


def _merge_hooks(data, wanted, replace=False):
    hooks = data.setdefault('hooks', {})
    if not isinstance(hooks, dict):
        raise ValueError('hooks must be a table/object; repair client config')
    for event, entries in wanted.items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            raise ValueError('hook event must be an array; repair client config')
        if replace and entries:
            for old in existing:
                if not isinstance(old, dict):
                    continue
                for handler in old.get('hooks', []):
                    if not isinstance(handler, dict) or handler.get('type') != 'command':
                        continue
                    tokens = [t.strip('"\'') for t in shlex.split(handler.get('command', ''), posix=False)]
                    if _module_interpreter(tokens, 'siftfetch.hook'):
                        standard = [t.strip('"\'') for t in shlex.split(entries[0]['hooks'][0]['command'], posix=False)]
                        if tokens[1:] == standard[1:]:
                            handler['command'] = entries[0]['hooks'][0]['command']
                        elif tokens[0] != standard[0]:
                            # Keep isolation and deny flags from the old invocation.
                            handler['command'] = ' '.join('"' + t.replace('"', '\\"') + '"' for t in [standard[0], *tokens[1:]])
        for entry in entries:
            for old in existing:
                if isinstance(old, dict) and any(
                    isinstance(handler, dict) and 'siftfetch.hook' in str(handler.get('command', ''))
                    for handler in old.get('hooks', [])
                ) and old != entry and not replace and not (
                    set(old) <= {'matcher', 'hooks'} and old.get('hooks') == entry['hooks']):
                    raise ValueError('existing siftfetch hook differs; owner must reconcile it manually')
            if entry not in existing:
                existing.append(copy.deepcopy(entry))


def _merge_server(data, key, server, replace=False):
    entries = data.setdefault(key, {})
    if not isinstance(entries, dict):
        raise ValueError('MCP server settings must be a table/object')
    if 'siftfetch' in entries and entries['siftfetch'] != server:
        old = entries['siftfetch']
        if (not replace or not isinstance(old, dict) or set(old) - {'command', 'args'} or
                not _module_interpreter([old.get('command'), *old.get('args', [])], 'siftfetch.server')):
            raise ValueError('existing siftfetch server differs; owner must reconcile it manually')
        server = {**server, 'args': old['args']}
    entries['siftfetch'] = server


def _toml_value(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is bool:
        return str(value).lower()
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if type(value) in (int, float):
        return str(value).lower()
    if isinstance(value, list):
        return '[' + ', '.join(_toml_value(v) for v in value) + ']'
    if isinstance(value, dict):
        return '{' + ', '.join(json.dumps(k) + ' = ' + _toml_value(v) for k, v in value.items()) + '}'
    raise ValueError('unsupported TOML value; owner must edit client config manually')


def _serialize(path, value, original_text=''):
    if path.suffix == '.toml':
        return _edit_codex_toml(original_text, value)
    return json.dumps(value, ensure_ascii=False, indent=2) + '\n'


def _edit_codex_toml(text, intended):
    """Edit only simple assignments/tables; validate the complete semantic merge."""
    reconcile = 'existing siftfetch settings differ; owner must reconcile it manually'
    original = tomllib.loads(text)
    newline = '\r\n' if '\r\n' in text else '\n'
    lines = text.splitlines(keepends=True)
    # Headers only count outside multiline values; the result is fully re-parsed below.
    starts = management.statement_starts(lines)
    headers = [index for index, line in enumerate(lines) if starts[index] and line.lstrip().startswith('[')]

    def table(name):
        expected = {}
        for key in reversed(name.split('.')):
            expected = {key: expected}
        return next((i for i in headers if tomllib.loads(lines[i]) == expected), None)

    def set_key(key, value, start, end, present):
        pattern = re.compile(r'([ \t]*(?:' + key + r'|"' + key + r'"|\'' + key +
                             r'\')[ \t]*=[ \t]*)("(?:[^"\\]|\\.)*"|\'[^\']*\'|true|false)([ \t]*(?:#[^\r\n]*)?)(\r?\n)?$')
        if present:
            for i in range(start, end):
                match = pattern.fullmatch(lines[i])
                if match:
                    try:
                        tomllib.loads(''.join(lines[:i]))
                    except ValueError:
                        continue
                    lines[i] = match[1] + _toml_value(value) + match[3] + (match[4] or '')
                    return
            raise ValueError(reconcile)
        insertion = key + ' = ' + _toml_value(value) + newline
        if end and not lines[end - 1].endswith('\n'):
            insertion = newline + insertion
        lines.insert(end, insertion)

    # Work backwards so earlier table offsets remain valid.
    env = table('shell_environment_policy')
    if 'shell_environment_policy' in original and env is None:
        raise ValueError(reconcile)
    if 'siftfetch' in original.get('mcp_servers', {}) and table('mcp_servers.siftfetch') is None:
        raise ValueError(reconcile)
    if env is not None:
        end = next((i for i in headers if i > env), len(lines))
        set_key('ignore_default_excludes', False, env + 1, end,
                'ignore_default_excludes' in original['shell_environment_policy'])
    set_key('web_search', 'disabled', 0, headers[0] if headers else len(lines), 'web_search' in original)
    result = ''.join(lines)
    def append_table(name, values):
        nonlocal result
        if result and not result.endswith('\n'):
            result += newline
        result += '[' + name + ']' + newline
        result += ''.join(k + ' = ' + _toml_value(v) + newline for k, v in values.items())
    if 'siftfetch' not in original.get('mcp_servers', {}):
        append_table('mcp_servers.siftfetch', intended['mcp_servers']['siftfetch'])
    if env is None:
        append_table('shell_environment_policy', {'ignore_default_excludes': False})
    try:
        if tomllib.loads(result) != intended:
            raise ValueError
    except ValueError:
        raise ValueError(reconcile) from None
    return result


def install(client, scope='user', apply=False, *, home=None, project=None, replace=False,
            preset=None, _plan_only=False, adopt=False):
    management.baseline(required=False)
    paths = _targets(client, scope, home, project)
    for path in paths:
        if path.absolute().is_relative_to(policy.policy_dir().absolute()):
            raise ValueError('client settings cannot be inside the protected policy folder')
    for path in paths:
        _safe_path(path)
    snapshots = [path.read_bytes() if path.exists() else None for path in paths]
    original = [_read_settings(path, raw=raw) for path, raw in zip(paths, snapshots)]
    updated = copy.deepcopy(original)
    hooks, server, deny = _entries(client)
    ownership = original
    transition = original
    if adopt:
        updated, ownership = management.adopt_legacy(original, client, hooks, server, deny)
        transition = copy.deepcopy(updated)
        # An adopted entry that already covers an event's tool names needs no
        # standard entry beside it; that would run the guard twice per call.
        sources = updated if client == 'codex' else [updated[0]]
        hooks = {event: entries for event, entries in hooks.items()
                 if _hook_checks(sources, event, _required_tools(client)[event])[0]}
        replace = True
    if client == 'claude':
        _merge_hooks(updated[0], hooks, replace)
        permissions = updated[0].setdefault('permissions', {})
        if not isinstance(permissions, dict) or not isinstance(permissions.setdefault('deny', []), list):
            raise ValueError('permissions.deny must be an array')
        permissions['deny'] += [item for item in deny if item not in permissions['deny']]
        if not all(isinstance(item, str) for item in permissions['deny']):
            raise ValueError(management.HANDOFF)
        _merge_server(updated[1], 'mcpServers', server, replace)
        changes = {'hooks': hooks, 'permissions': {'deny': deny}, 'mcpServers': {'siftfetch': server}}
    else:
        legacy = copy.deepcopy(updated[0])
        _merge_hooks(legacy, hooks, replace)  # Validate legacy entries without duplicating them.
        if replace and 'hooks' in updated[0]:
            updated[0]['hooks'] = legacy['hooks']
        _merge_hooks(updated[1], {event: [entry for entry in entries
                     if entry not in original[0].get('hooks', {}).get(event, [])]
                     for event, entries in hooks.items()}, replace)
        # Validate JSON conflicts even when an identical TOML entry exists.
        _merge_hooks(copy.deepcopy(updated[1]), hooks, replace)
        _merge_server(updated[0], 'mcp_servers', server, replace)
        if not management.classify({'web_search': original[0].get('web_search')}, {'web_search': 'disabled'}, client=True):
            raise ValueError(management.HANDOFF)
        updated[0]['web_search'] = 'disabled'
        environment = updated[0].setdefault('shell_environment_policy', {})
        if not isinstance(environment, dict):
            raise ValueError('shell_environment_policy must be a table')
        if not management.classify({'ignore_default_excludes': environment.get('ignore_default_excludes')},
                                   {'ignore_default_excludes': False}, client=True):
            raise ValueError(management.HANDOFF)
        environment['ignore_default_excludes'] = False
        changes = {'hooks': hooks, 'mcp_servers': {'siftfetch': server}, 'web_search': 'disabled',
                   'shell_environment_policy': {'ignore_default_excludes': False}}
    if not all(management.client_transition(before, after, replace=replace) for before, after in zip(transition, updated)):
        raise ValueError(management.HANDOFF)
    encoded = [(management.edit_toml((raw or b'').decode('utf-8'), value) if replace and path.suffix == '.toml'
                else _serialize(path, value, (raw or b'').decode('utf-8')))
               for path, value, raw in zip(paths, updated, snapshots)]
    if _plan_only:
        return changes
    print('APPLY' if apply else 'DRY RUN: no files written; use --apply to write')
    print(json.dumps(changes, ensure_ascii=True, indent=2))
    if client == 'codex':
        print('Codex: trust the exact hook in /hooks. Native Read deny rules have no equivalent here; '
              'verify sandbox read restrictions and run the owner live checks.')
    if not apply:
        if client == 'claude' and scope == 'user':
            print('Close Claude Code before --apply: it rewrites ~/.claude.json while running.')
        return 0
    # Journal intent before the first client write; never replay an interrupted run.
    journal, transaction = receipt.begin(client, scope, paths, ownership, updated, replace=replace and not adopt)
    for index, (path, before, after, text, raw) in enumerate(zip(paths, original, updated, encoded, snapshots)):
        if before == after:
            transaction['files'][index]['state'] = 'complete'
            continue
        try:
            backup = management.atomic_write(path, text, raw)
        except ValueError as exc:
            if str(exc) == 'settings changed during install; close the client and retry':
                print('ERROR: settings changed during install; close the client and retry', file=sys.stderr)
                return 2
            raise
        transaction['files'][index].update(state='complete', backup=backup)
        receipt.save(journal)
    transaction['state'] = 'complete'
    receipt.save(journal)
    print('Settings merged; existing entries retained and changed files backed up. Restart the client.')
    print('Configured; verification pending. Restart the clients, re-trust the hook in Codex /hooks, then run doctor.')
    return 0


def _module_interpreter(tokens, module):
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        return None
    if len(tokens) < 3:
        return None
    # Python options may precede -m; a script or -c must not masquerade as one.
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "-m":
            return tokens[0] if i + 1 < len(tokens) and tokens[i + 1] == module else None
        if token in ("-c", "--", "-h", "-V", "--help", "--version") or not token.startswith("-"):
            return None
        i += 2 if token in ("-W", "-X", "--check-hash-based-pycs") else 1
    return None


def _interpreter_exists(command):
    return Path(command).is_file() or shutil.which(command) is not None


def _required_tools(client):
    """Tool names each hook event must cover. Each client's own names: Codex
    has no WebFetch/PowerShell tools, and Claude has no apply_patch."""
    if client == 'claude':
        return {'PreToolUse': ['WebFetch', 'WebSearch', 'Bash', 'PowerShell', 'Edit', 'Write',
                               'MultiEdit', 'NotebookEdit', 'mcp__example__tool'],
                'PostToolUse': ['mcp__claude-in-chrome__' + name for name in
                                ('get_page_text', 'read_page', 'find', 'javascript_tool')]}
    return {'PreToolUse': ['Bash', 'apply_patch', 'mcp__example__tool']}


def _hook_checks(sources, event, names):
    matches, interpreters = [], []
    for source in sources:
        for entry in source.get('hooks', {}).get(event, []):
            if not isinstance(entry, dict):
                continue
            for handler in entry.get('hooks', []):
                if not isinstance(handler, dict) or handler.get('type') != 'command':
                    continue
                try:
                    tokens = [t.strip('"\'') for t in shlex.split(handler.get('command', ''), posix=False)]
                    interpreter = _module_interpreter(tokens, 'siftfetch.hook')
                    if interpreter is None:
                        continue
                    exists = _interpreter_exists(interpreter)
                    interpreters.append((interpreter, exists))
                    matcher = entry.get('matcher', '*')
                    pattern = re.compile('.*' if matcher == '*' else matcher)
                    if exists:
                        matches.append(pattern)
                except (ValueError, TypeError, re.error):
                    continue
    # A name is covered when any of its spellings fully matches a matcher:
    # Codex reports apply_patch to hooks as apply_patch, Edit and Write.
    spellings = {'apply_patch': ('apply_patch', 'Edit', 'Write')}
    missing = [name for name in names
               if not any(p.fullmatch(alias) for p in matches for alias in spellings.get(name, (name,)))]
    return missing, interpreters


def _deny_equivalent(rule, wanted, home):
    if rule == wanted:
        return True
    def normalized(value):
        match = re.fullmatch(r'(Read|Edit)\((.*)/\*\*\)', value)
        if not match:
            return value
        path = match[2].replace('\\', '/')
        if path.startswith('~/'):
            path = Path(home).as_posix() + path[1:]
        return match[1] + '(' + policy.normalize_path_text(path).lstrip('/') + '/**)'
    return isinstance(rule, str) and normalized(rule) == normalized(wanted)


def doctor(client=None, scope='user', *, home=None, project=None, json_output=False):
    checks = []
    def report(ok, check, detail=''):
        checks.append({'status': 'PASS' if ok else 'FAIL', 'check': check, 'detail': detail})
    def info(check, detail):
        checks.append({'status': 'INFO', 'check': check, 'detail': detail})
    status = policy.policy_status()
    info('verification', 'configured; verification pending. Restart clients, re-trust the hook in Codex /hooks, then run doctor.')
    info('gaps by design', 'Same-user programs, TTY emulation, launch environment overrides, Codex fail-open errors/timeouts, '
         'code-mode exec and hosted tools remain outside complete enforcement. See docs/threat-model.md')
    try:
        journal = receipt.load()
        report(not any(tx['state'] == 'pending' for tx in journal['transactions']), 'install journal',
               'Interrupted intent is never replayed; inspect locally if pending.')
        targets = [path for selected in ([client] if client else ['claude', 'codex'])
                   for path in _targets(selected, scope, home, project)]
        info('install drift', f'Changed or missing owned edits: {receipt.drift(journal, targets)}')
    except (ValueError, OSError, TypeError, KeyError):
        report(False, 'install journal', 'Malformed manifest; owner review required.')
    try:
        metadata.version('siftfetch')
        report(True, 'package installed')
    except metadata.PackageNotFoundError:
        report(False, 'package installed', 'install this repository into the active Python environment')
    for module in ('siftfetch', 'siftfetch.tools', 'siftfetch.hook', 'siftfetch.server'):
        try:
            importlib.import_module(module)
            report(True, module + ' importable')
        except Exception:
            report(False, module + ' importable', 'install this package and its dependencies')
    report(status['loaded'], 'policy parse and substitute sanity', status['error'] or '')
    for key in ('data', 'download'):
        report(status['paths'].get(key, {}).get('writable', False), key + ' directory',
               'writable local directory required; absent directories use nearest existing parent')
    lock = status['config'].get('guard_lock')
    info('guard lock', ('on' if lock['enabled'] else 'off') if lock else 'unknown; built-in guards fail closed')
    for selected in ([client] if client else ['claude', 'codex']):
        try:
            paths = _targets(selected, scope, home, project)
            settings = [_read_settings(p) for p in paths]
            _, _, deny = _entries(selected)
            sources = settings if selected == 'codex' else [settings[0]]
            events = _required_tools(selected)
            if selected == 'claude' and not settings[0].get('hooks', {}).get('PostToolUse'):
                del events['PostToolUse']
                report(False, 'Claude Chrome labeling', 'Standard PostToolUse hook is absent.')
            for event, names in events.items():
                missing, interpreters = _hook_checks(sources, event, names)
                report(not missing, selected + ' hook entry ' + event,
                       'uncovered tool names: ' + ', '.join(missing) if missing else 'all required tool names covered')
                for interpreter, exists in sorted(set(interpreters)):
                    detail = interpreter + (' exists' if exists else ' missing')
                    if os.path.normcase(os.path.abspath(interpreter)) != os.path.normcase(os.path.abspath(sys.executable)):
                        detail += '; registered with a different interpreter'
                    info(selected + ' hook interpreter', detail)
            servers = settings[1 if selected == 'claude' else 0].get('mcpServers' if selected == 'claude' else 'mcp_servers', {})
            server = servers.get('siftfetch', {})
            interpreter = _module_interpreter([server.get('command'), *server.get('args', [])], 'siftfetch.server')
            ok = interpreter is not None and _interpreter_exists(interpreter)
            report(ok, selected + ' MCP server entry',
                   (interpreter + (' exists' if ok else ' missing')) if interpreter else 'register siftfetch.server with -m')
            if selected == 'claude':
                configured = settings[0].get('permissions', {}).get('deny', [])
                missing = [item for item in deny if item not in ('WebFetch', 'WebSearch') and
                           not any(_deny_equivalent(rule, item, home or Path.home()) for rule in configured)]
                # Only canonical rule names, never the configured policy path.
                names = [re.sub(r'\(.*?/\*\*\)', '(~/.siftfetch/**)', item) for item in missing]
                report(not missing, 'Claude deny rules', 'missing: ' + ', '.join(names) if names else '')
                missing = [name for name in ('WebFetch', 'WebSearch') if name not in configured]
                report(not missing, 'claude built-in web tools', 'missing deny rules: ' + ', '.join(missing) if missing else '')
            else:
                report(settings[0].get('web_search') == 'disabled', 'codex built-in web tools',
                       'web_search must be disabled')
                report(settings[0].get('shell_environment_policy', {}).get('ignore_default_excludes') is False,
                       'Codex hosted search and environment guards', 'environment default excludes required')
                info('Codex trust', 'File deny rules and hook trust require owner live verification')
        except Exception:
            report(False, selected + ' client configuration', 'repair settings syntax and structure; rerun install dry run')
    if json_output:
        print(json.dumps({'policy_status': status, 'checks': checks}, indent=2))
    else:
        print('EGRESS PROTECTION: ' + ('ENABLED' if status['protection']['enabled'] else 'DISABLED'))
        print('POLICY STATUS (redacted):')
        print(json.dumps(status, indent=2))
        if status['loaded']:
            print(f"COUNTS identifiers={status['identifiers']['total']}")
        for item in checks:
            print(item['status'] + ' ' + item['check'] + (': ' + item['detail'] if item['detail'] else ''))
        print('Doctor never prints policy values. Live client trust/execution checks remain owner-run.')
    return 1 if any(item['status'] == 'FAIL' for item in checks) else 0


_TIGHTEN = {'enabled': {'enabled': True}, 'guard-lock': {'guard_lock': True},
            'secret-files': {'secret_file_mode': 'strict'}, 'browser-off': {'browser_fetch': {'mode': 'off'}}}
_COSTS = {'enabled': ('enabled', False, 'disables outbound value checks'),
          'guard-lock': ('guard_lock', False, 'permits changes to guard settings'),
          'secret-files': ('secret_file_mode', 'off', 'permits shell dotenv reads'),
          'browser-off': ('browser_fetch.mode', 'on-wall', 'enables browser network access'),
          'blocked-domain': ('blocked_domains', [], 'removes destination blocks'),
          'contact-alias': ('contact_alias', '<enter alias locally>', 'changes approved contact identity'),
          'substitute': ('substitute', '<enter fields locally>', 'changes approved substitute identities')}


def _tightening_change(setting, value=None):
    if setting == 'blocked-domain':
        before = management.baseline()
        return {'blocked_domains': list(dict.fromkeys([*before.get('blocked_domains', []), value]))}
    change = copy.deepcopy(_TIGHTEN[setting])
    if setting == 'guard-lock':
        lock = management.baseline().get('guard_lock')
        if isinstance(lock, dict):
            change['guard_lock'] = {**lock, 'enabled': True}
    return change


def configure(setting=None, *, loosen=False, editor=False):
    print(json.dumps(policy.policy_status(), indent=2))
    for name, (key, replacement, cost) in _COSTS.items():
        print(f'{name}: loosening {cost}; owner editor only.')
    if setting is None:
        return 0
    path = policy.policy_dir() / ('config.toml' if (policy.policy_dir() / 'config.toml').exists() else 'config.json')
    if loosen or setting in ('contact-alias', 'substitute', 'blocked-domain'):
        key, replacement, _ = _COSTS[setting]
        print(f'Owner edit: {path}; key {key}; replacement text: {_toml_value(replacement)}')
        if editor:
            management.open_editor(path)
        else:
            print('Use --open-editor to open this file in EDITOR or the platform editor.')
        return 0
    result = management.tighten(_tightening_change(setting))
    print(json.dumps(result))
    return 0 if result['ok'] else 2


def setup(clients=None, scope=None, preset=None, apply=False, *, prompt=input, home=None, project=None):
    if management.temporary_interpreter():
        print('Refused temporary interpreter. Install with pipx or uv tool install in a stable environment.')
        return 2
    interactive = clients is None or scope is None or preset is None
    editor = False
    if interactive:
        detected = [name for name in ('claude', 'codex') if
                    (Path(home or Path.home()) / ('.' + name)).is_dir() or shutil.which(name)]
        chosen = prompt('Clients (claude,codex); detected: ' + ','.join(detected) + ': ')
        clients = [s.strip() for s in chosen.split(',') if s.strip()] or detected
        scope = prompt('Scope (user/project) [user]: ').strip() or 'user'
        preset = prompt('Preset standard/lockdown/custom [standard]; Standard routes all web content through '
                        "SiftFetch's cleaner and checks outbound data; Lockdown optional: also stops agents editing "
                        'their own settings. Custom: append tightened items '
                        '(guard-lock,paths,secret-files,browser-off), e.g. custom paths: ').strip() or 'standard'
        editor = prompt('Open identifiers and config in the owner editor after apply? [y/N]: ').lower() == 'y'
    if isinstance(clients, str):
        clients = [clients]
    if preset == 'strict':
        print('Deprecated preset strict: use lockdown.')
        preset = 'lockdown'
    custom = preset.startswith('custom')
    items = set(preset.removeprefix('custom').strip().split(',')) - {''} if custom else set()
    if (not clients or any(c not in ('claude', 'codex') for c in clients) or scope not in ('user', 'project') or
            (not custom and preset not in ('standard', 'lockdown')) or items - {'guard-lock', 'paths', 'secret-files', 'browser-off', 'chrome'}):
        raise ValueError('invalid setup selection')
    config = management.baseline(required=False)
    lock = config.get('guard_lock', False)
    change = {}
    if 'guard-lock' in items:
        change['guard_lock'] = {**lock, 'enabled': True} if isinstance(lock, dict) else True
    if preset == 'lockdown' or 'paths' in items:
        paths = lock.get('paths', []) if isinstance(lock, dict) else []
        change['guard_lock'] = {'enabled': True, 'paths': list(dict.fromkeys([
            *paths, str(Path(__file__).resolve().parent), str(Path(sys.prefix).resolve())]))}
    if preset == 'lockdown' or 'secret-files' in items:
        change['secret_file_mode'] = 'strict'
    if preset == 'lockdown' or 'browser-off' in items:
        change['browser_fetch'] = {'mode': 'off'}
    if custom:
        print('Custom keeps Standard; omitted items are kept. Loosening requires configure --loosen and an owner editor.')
    management.policy_plan(change, required=False)
    selected_preset = 'standard'
    for client in dict.fromkeys(clients):
        plan = install(client, scope, home=home, project=project, preset=selected_preset, _plan_only=True)
        print(json.dumps(plan, indent=2))
    print('Policy tightening: ' + ', '.join(change) + ' (values redacted).')
    if interactive:
        apply = prompt('Apply this plan? [y/N]: ').lower() == 'y'
    if not apply:
        print('DRY RUN: no files written; use --apply to write')
        return 0
    initialize()
    # Validate every target before the first client mutation.
    for client in dict.fromkeys(clients):
        install(client, scope, home=home, project=project, preset=selected_preset, _plan_only=True)
    result = management.tighten(change)
    if not result['ok']:
        print(result['message'])
        return 2
    for client in dict.fromkeys(clients):
        if install(client, scope, True, home=home, project=project, preset=selected_preset):
            return 2
    if editor:
        for stem in ('identifiers', 'config'):
            base = policy.policy_dir() / stem
            management.open_editor(base.with_suffix('.toml' if base.with_suffix('.toml').exists() else '.json'))
    print('Configured; verification pending. Restart the clients, re-trust the hook in Codex /hooks, then run doctor.')
    return 0


def uninstall(client=None, scope='user', apply=False, *, prompt=input, home=None, project=None):
    data, records, changes, conflicts, backups = receipt.uninstall_plan(client, scope, home=home, project=project)
    print('UNINSTALL APPLY' if apply else 'UNINSTALL DRY RUN: no files written')
    print(json.dumps({'files': len({str(p) for p, _, _ in changes}), 'conflicts': conflicts,
                      'backups': backups}, indent=2))
    print('Policy files and policy/data folders are kept. Backups may contain client tokens.')
    if not records:
        print('No active manifest ownership: only unrecorded legacy registrations are eligible; '
              'uncertain denies and scalars remain.')
    if apply:
        if prompt is input and not sys.stdin.isatty():
            print('Uninstall requires an interactive owner confirmation; no --yes option.')
            return 2
        try:
            confirmed = prompt('Type uninstall to restore owned client settings: ') == 'uninstall'
        except EOFError:
            confirmed = False
        if not confirmed:
            print('Uninstall confirmation refused; no files written.')
            return 2
        # Revalidate all original snapshots before any mutation. Later entries
        # for the same file are sequential stages, with hooks removed last.
        checked = set()
        for path, raw, _ in changes:
            _safe_path(path)
            if path not in checked and (path.read_bytes() if path.exists() else None) != raw:
                raise ValueError('settings changed during uninstall')
            checked.add(path)
        for tx, _ in records:
            tx['state'] = 'pending'
        if records:
            receipt.save(data)
        for path, raw, text in changes:
            management.atomic_write(path, text, raw, backup=False)
        for tx, _ in records:
            tx['state'] = 'removed'
        if records:
            receipt.save(data)
        print('Owned settings restored; conflicts left untouched.')
        if backups:
            try:
                delete = prompt('Backups may contain client tokens. Delete only the manifest-listed '
                                'SiftFetch backup files? [y/N]: ').lower() == 'y'
            except EOFError:
                delete = False
            if delete:
                for name in backups:
                    path = Path(name)
                    _safe_path(path)
                    if path.is_file():
                        path.unlink()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'get':
        from siftfetch.shell_fetch import main as get
        return get(argv[1:])
    parser = argparse.ArgumentParser(description='SiftFetch owner setup and diagnostics')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('get', help='fetch and label web content; curl-like safe subset')
    benchmark = sub.add_parser('benchmark', help='measure the offline cleaning corpus')
    benchmark.add_argument('--json', action='store_true')
    benchmark.add_argument('--corpus', type=Path)
    sub.add_parser('init', help='create absent example policy files')
    check = sub.add_parser('doctor', help='read-only structural diagnostics; never prints values')
    check.add_argument('--json', action='store_true', help='redacted report and check results as JSON')
    check.add_argument('--client', choices=('claude', 'codex'))
    check.add_argument('--scope', choices=('user', 'project'), default='user')
    status = sub.add_parser('status', help='read-only doctor alias')
    status.add_argument('--json', action='store_true')
    status.add_argument('--client', choices=('claude', 'codex'))
    status.add_argument('--scope', choices=('user', 'project'), default='user')
    setup = sub.add_parser('install', help='preview client configuration, or apply with backups')
    setup.add_argument('--client', choices=('claude', 'codex'), required=True)
    setup.add_argument('--scope', choices=('user', 'project'), default='user')
    setup.add_argument('--apply', action='store_true')
    setup.add_argument('--replace', action='store_true')
    setup.add_argument('--adopt', action='store_true', help='adopt recognized legacy registrations')
    wizard = sub.add_parser('setup', help='guided tightening-only setup')
    wizard.add_argument('--client', choices=('claude', 'codex'), action='append')
    wizard.add_argument('--scope', choices=('user', 'project'))
    wizard.add_argument('--preset', choices=('standard', 'lockdown', 'strict', 'custom'))
    wizard.add_argument('--apply', action='store_true')
    config = sub.add_parser('configure', help='tighten or hand off to the owner editor')
    config.add_argument('--setting', choices=tuple(_COSTS))
    config.add_argument('--loosen', action='store_true')
    config.add_argument('--open-editor', action='store_true')
    tight = sub.add_parser('tighten', help='apply an allowlisted tightening')
    tight.add_argument('setting', choices=(*_TIGHTEN, 'blocked-domain'))
    tight.add_argument('domain', nargs='?')
    remove = sub.add_parser('uninstall', help='preview owned removals and conflicts')
    remove.add_argument('--client', choices=('claude', 'codex'))
    remove.add_argument('--scope', choices=('user', 'project'), default='user')
    remove.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'benchmark':
        from siftfetch.benchmark import run, _report
        try:
            result = run(args.corpus)
        except (ValueError, OSError, KeyError, TypeError):
            print('ERROR: corpus missing or malformed; provide --corpus DIR.', file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=True) if args.json else _report(result))
        return 0
    try:
        if args.action == 'init':
            return initialize()
        if args.action in ('doctor', 'status'):
            return doctor(args.client, args.scope, json_output=args.json)
        if args.action == 'setup':
            supplied = (args.client is not None, args.scope is not None, args.preset is not None)
            if (any(supplied) or args.apply) and not all(supplied):
                raise ValueError('noninteractive setup requires client, scope and preset')
            return globals()['setup'](args.client, args.scope, args.preset, args.apply)
        if args.action == 'configure':
            return configure(args.setting, loosen=args.loosen, editor=args.open_editor)
        if args.action == 'tighten':
            if (args.setting == 'blocked-domain') != (args.domain is not None):
                raise ValueError('domain argument required only for blocked-domain')
            result = management.tighten(_tightening_change(args.setting, args.domain))
            print(json.dumps(result))
            return 0 if result['ok'] else 2
        if args.action == 'uninstall':
            return uninstall(args.client, args.scope, args.apply)
        return install(args.client, args.scope, args.apply, replace=args.replace, adopt=args.adopt)
    except (ValueError, OSError) as exc:
        # No raw OS/parser messages: these can include private paths or values.
        if str(exc).startswith('Cannot adopt:') or str(exc) in {
            'existing siftfetch hook differs; owner must reconcile it manually',
            'existing siftfetch server differs; owner must reconcile it manually',
            'existing siftfetch settings differ; owner must reconcile it manually',
        }:
            print('ERROR: ' + str(exc), file=sys.stderr)
            return 2
        print('ERROR: unsafe path, conflicting or malformed settings, or write failure. '
              'Owner: inspect settings locally, retain backups, repair structure and retry.', file=sys.stderr)
        return 2
