"""Constrained, value-free management results and tightening-only policy writes."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
import uuid

from siftfetch import egress_policy as policy, saving

HANDOFF = 'Refused: change is not provably tightening. Owner: edit the file by hand in your editor.'


def _lock(value):
    return value if isinstance(value, dict) else {'enabled': value, 'paths': []}


def classify(before, after, *, client=False):
    """Allow only known monotone transitions; callers validate complete baselines."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if not client:
        try:
            policy.validate_policy('config.json', before)
            policy.validate_policy('config.json', after)
        except (ValueError, TypeError):
            return False
    for key in before.keys() | after.keys():
        old, new = before.get(key), after.get(key)
        if key in before and key in after and old == new and type(old) is type(new):
            continue
        if key not in after:
            return False
        if key == 'enabled':
            ok = type(new) is bool and new is True and (old is None or type(old) is bool)
        elif key == 'guard_lock':
            a, b = _lock(False if old is None else old), _lock(new)
            ok = (b.get('enabled', True) is True and
                  set(a.get('paths', [])) <= set(b.get('paths', [])))
        elif key == 'secret_file_mode':
            order = {'off': 0, 'standard': 1, 'strict': 2}
            ok = new in order and order.get(old or 'strict', 99) <= order[new]
        elif key == 'browser_fetch':
            a = old or {}
            ok = (isinstance(new, dict) and new.get('mode') == 'off' and
                  {k: v for k, v in a.items() if k != 'mode'} ==
                  {k: v for k, v in new.items() if k != 'mode'})
        elif key in ('blocked_domains', 'deny') and (key != 'deny' or client):
            ok = isinstance(new, list) and isinstance(old or [], list) and set(old or []) <= set(new)
            if ok and key == 'blocked_domains':
                policy.validate_policy('config.json', {key: new})
        elif client and key == 'web_search':
            ok = old in (None, 'disabled', 'cached', 'indexed', 'live') and new == 'disabled'
        elif client and key == 'ignore_default_excludes':
            ok = (old is None or type(old) is bool) and new is False
        else:
            ok = False
        if not ok:
            return False
    return True


def merge(before, changes):
    result = copy.deepcopy(before)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def client_transition(before, after, *, replace=False):
    """Prove client edits are registrations, added coverage/denies, or known scalars."""
    from siftfetch.cli import _module_interpreter
    def command(value, module):
        if module == 'siftfetch.hook':
            if not isinstance(value, dict) or value.get('type') != 'command':
                return None
            try:
                tokens = [t.strip('"\'') for t in shlex.split(value.get('command', ''), posix=False)]
            except ValueError:
                return None
        else:
            if not isinstance(value, dict) or set(value) - {'command', 'args'}:
                return None
            tokens = [value.get('command'), *value.get('args', [])]
        return tokens[1:] if _module_interpreter(tokens, module) else None

    for key in before.keys() | after.keys():
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if key == 'web_search':
            if not classify({key: old}, {key: new}, client=True):
                return False
        elif key == 'shell_environment_policy':
            if not isinstance(new, dict) or not classify(old or {}, new, client=True):
                return False
        elif key == 'permissions':
            if not isinstance(new, dict) or not classify(old or {}, new, client=True):
                return False
        elif key in ('mcpServers', 'mcp_servers'):
            if not isinstance(new, dict) or {k: v for k, v in (old or {}).items() if k != 'siftfetch'} != {
                    k: v for k, v in new.items() if k != 'siftfetch'}:
                return False
            args = command(new.get('siftfetch'), 'siftfetch.server')
            previous = (old or {}).get('siftfetch')
            if args is None or previous is not None and (not replace or command(previous, 'siftfetch.server') != args):
                return False
        elif key == 'hooks':
            if not isinstance(new, dict):
                return False
            for event in (old or {}).keys() | new.keys():
                a, b = (old or {}).get(event, []), new.get(event, [])
                if a == b:
                    continue  # Untouched, e.g. Codex's hooks.state trust records.
                if not isinstance(a, list) or not isinstance(b, list):
                    return False
                def signature(group):
                    group = copy.deepcopy(group)
                    if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                        return group
                    for handler in group['hooks']:
                        args = command(handler, 'siftfetch.hook')
                        if args is not None:
                            handler['command'] = args
                    return group
                for entry in a:
                    if entry not in b and not (replace and signature(entry) in [signature(g) for g in b]):
                        return False
                for entry in b:
                    if entry in a or replace and signature(entry) in [signature(g) for g in a]:
                        continue
                    if not isinstance(entry, dict) or not entry.get('hooks'):
                        return False
                    try:
                        re.compile('.*' if entry.get('matcher', '*') == '*' else entry['matcher'])
                    except (ValueError, TypeError, re.error):
                        return False
                    if any(command(handler, 'siftfetch.hook') is None for handler in entry['hooks']):
                        return False
        else:
            return False
    return True


def _legacy_command(tokens, module):
    if not isinstance(tokens, list) or not tokens or not all(isinstance(t, str) for t in tokens):
        return False
    executable = tokens[0].replace('\\', '/').rsplit('/', 1)[-1].lower()
    args = tokens[1:]
    if executable in (module.replace('.', '-'), module.replace('.', '-') + '.exe'):
        return args in ([], ['--deny']) if module == 'siftfetch.hook' else not args
    if args[:1] == ['-I']:
        args = args[1:]
    return args in ([['-m', module], ['-m', module, '--deny']] if module == 'siftfetch.hook'
                    else [['-m', module]])


def adopt_legacy(documents, client, hooks, server, deny):
    """Normalize exact legacy invocations, retaining every event and matcher."""
    normalized, unowned = copy.deepcopy(documents), copy.deepcopy(documents)
    for document, baseline in zip(normalized, unowned):
        if not isinstance(document.get('hooks', {}), dict):
            raise ValueError('Cannot adopt: unsupported hook shape')
        for event, groups in document.get('hooks', {}).items():
            if event == 'state' and isinstance(groups, dict):
                continue  # Codex's hook-trust records, not an event; left as is.
            if not isinstance(groups, list):
                raise ValueError('Cannot adopt: unsupported hook shape')
            retained = []
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                    raise ValueError('Cannot adopt: unsupported hook shape')
                handlers = group['hooks']
                candidates = [h for h in handlers if isinstance(h, dict) and
                              any(s in str(h.get('command', '')).lower() for s in ('siftfetch.hook', 'siftfetch-hook'))]
                if not candidates:
                    retained.append(copy.deepcopy(group))
                    continue
                if (event not in hooks or set(group) - {'matcher', 'hooks'} or
                        not isinstance(group.get('matcher', '*'), str) or len(candidates) != len(handlers)):
                    raise ValueError('Cannot adopt: unsupported event or mixed hook shape')
                try:
                    re.compile('.*' if group.get('matcher', '*') == '*' else group['matcher'])
                except re.error:
                    raise ValueError('Cannot adopt: invalid matcher') from None
                for handler in handlers:
                    # timeout and statusMessage are display/limit fields; the
                    # canonical handler replaces them along with the command.
                    if (set(handler) - {'type', 'command', 'onFailure', 'timeout', 'statusMessage'} or
                            handler.get('type') != 'command' or
                            not isinstance(handler.get('command'), str) or handler.get('onFailure', 'block') != 'block'):
                        raise ValueError('Cannot adopt: unsupported hook options')
                    try:
                        tokens = [t.strip('"\'') for t in shlex.split(handler['command'], posix=False)]
                    except ValueError:
                        raise ValueError('Cannot adopt: unknown hook arguments') from None
                    if not _legacy_command(tokens, 'siftfetch.hook'):
                        raise ValueError('Cannot adopt: unknown hook arguments')
                    canonical = copy.deepcopy(hooks[event][0]['hooks'][0])
                    # A legacy deny flag remains a deny flag for either client.
                    if '--deny' in tokens and '--deny' not in canonical['command']:
                        canonical['command'] += ' --deny'
                    handler.clear()
                    handler.update(canonical)
            baseline['hooks'][event] = retained
        for key in ('mcpServers', 'mcp_servers'):
            if not isinstance(document.get(key, {}), dict):
                raise ValueError('Cannot adopt: unsupported server shape')
            entry = document.get(key, {}).get('siftfetch')
            if entry is None:
                continue
            # `claude mcp add` writes type "stdio" and an empty env; any real
            # env value could change policy or data folders, so it refuses.
            if (not isinstance(entry, dict) or set(entry) - {'command', 'args', 'type', 'env'} or
                    entry.get('type', 'stdio') != 'stdio' or entry.get('env', {}) != {} or
                    not isinstance(entry.get('args', []), list) or not _legacy_command(
                        [entry.get('command'), *entry.get('args', [])], 'siftfetch.server')):
                raise ValueError('Cannot adopt: unknown server arguments or shape')
            document[key]['siftfetch'] = copy.deepcopy(server)
            del baseline[key]['siftfetch']
        permissions = baseline.get('permissions', {})
        if not isinstance(permissions, dict):
            raise ValueError('Cannot adopt: unsupported deny rules')
        if 'deny' in permissions:
            if not isinstance(permissions['deny'], list):
                raise ValueError('Cannot adopt: unsupported deny rules')
            permissions['deny'] = [rule for rule in permissions['deny'] if rule not in deny]
            if permissions['deny']:
                print('Legacy noncanonical deny rules retained; ownership unchanged.')
    return normalized, unowned


def baseline(*, required=True):
    """Reject malformed effective state, including shadowed formats and env switches."""
    if required:
        config = policy._config()
    else:
        # Registration never reads identifiers or grants. Validate only config state.
        from siftfetch.cli import _safe_path
        configs = []
        for ext in ('json', 'toml'):
            path = policy.policy_dir() / ('config.' + ext)
            _safe_path(path)
            if path.exists():
                text = path.read_bytes().decode('utf-8')
                configs.append(policy.validate_policy(path.name, tomllib.loads(text) if ext == 'toml' else json.loads(text)))
        if len(configs) == 2 and any(configs[0].get(k) != configs[1].get(k) for k in policy._SECURITY_KEYS):
            raise ValueError(HANDOFF)
        config = configs[-1] if configs else {}
    browser = config.get('browser_fetch', {})
    if (browser.get('mode', 'off') not in policy.BROWSER_FETCH_MODES or
            browser.get('window', 'offscreen') not in policy.BROWSER_WINDOWS or
            browser.get('browser', 'msedge') not in ('msedge', 'chrome') or
            type(browser.get('max_per_minute', 6)) is not int or
            not 1 <= browser.get('max_per_minute', 6) <= 60 or
            not isinstance(browser.get('sites', []), list) or
            not all(isinstance(site, str) and site.strip() for site in browser.get('sites', []))):
        raise ValueError(HANDOFF)
    if os.environ.get('SIFTFETCH_ENABLED') not in (None, '0', '1'):
        raise ValueError(HANDOFF)
    if required:
        if not policy.policy_status()['loaded']:
            raise ValueError(HANDOFF)
    return config


def atomic_write(path, text, raw, *, backup=True):
    from siftfetch.cli import _safe_path
    _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if (path.read_bytes() if path.exists() else None) != raw:
        raise ValueError('settings changed during install; close the client and retry')
    backup_path = None
    if backup and raw is not None:
        backup_path = path.with_name(path.name + '.siftfetch-backup-' + uuid.uuid4().hex)
        # Exclusive, restrictive creation; do not decode/re-encode the snapshot.
        fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    temporary = path.with_name(path.name + '.siftfetch-' + uuid.uuid4().hex)
    try:
        if not saving._write_new(temporary, text):
            raise ValueError('temporary file collision')
        _safe_path(path)
        if (path.read_bytes() if path.exists() else None) != raw:
            raise ValueError('settings changed during install; close the client and retry')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return str(backup_path) if backup_path else None


def _toml_key(part):
    return part if re.fullmatch(r'[A-Za-z0-9_-]+', part) else json.dumps(part)


def _without_empty_tables(value):
    """An empty table holds no setting; `[x]` with nothing in it equals no `x`."""
    if not isinstance(value, dict):
        return value
    pruned = {key: _without_empty_tables(item) for key, item in value.items()}
    return {key: item for key, item in pruned.items() if item != {}}


def statement_starts(lines):
    """True for each line that begins outside any multiline value.

    One linear pass over strings, comments and brackets; re-parsing every
    prefix instead is quadratic and takes minutes on a large Codex config.
    Callers still verify the edited text with a full parse.
    """
    starts, mode, depth = [], None, 0
    for line in lines:
        starts.append(mode is None and depth == 0)
        i, n = 0, len(line)
        while i < n:
            if mode is not None:
                if mode == '"""' and line[i] == '\\':
                    i += 2
                elif line.startswith(mode, i):
                    i += 3
                    while i < n and line[i] == mode[0]:
                        i += 1  # Up to two quotes before the delimiter are content.
                    mode = None
                else:
                    i += 1
                continue
            char = line[i]
            if char == '#':
                break
            if line.startswith(('"""', "'''"), i):
                mode, i = line[i:i + 3], i + 3
                continue
            if char in '"\'':
                i += 1
                while i < n and line[i] != char:
                    i += 2 if char == '"' and line[i] == '\\' else 1
            elif char in '[{':
                depth += 1
            elif char in ']}':
                depth = max(0, depth - 1)
            i += 1
    return starts


def edit_toml(text, intended):
    """Surgical simple assignments; refuse unsupported syntax rather than rewrite it."""
    from siftfetch.cli import _toml_value
    original = tomllib.loads(text)
    newline = '\r\n' if '\r\n' in text else '\n'
    lines = text.splitlines(keepends=True)
    missing = object()

    def locations():
        """Assignments, table headers and array-of-tables counts, by resolved path.

        An element of an array of tables resolves to an integer index, so
        `[[hooks.PreToolUse.hooks]]` under the second `[[hooks.PreToolUse]]`
        is ('hooks', 'PreToolUse', 1, 'hooks', 0).
        """
        table, found, headers, arrays = (), {}, {}, {}
        starts = statement_starts(lines)
        for i, line in enumerate(lines):
            if not starts[i]:
                continue  # inside multiline value
            if line.lstrip().startswith('['):
                try:
                    data = tomllib.loads(line)
                    names = []
                    while isinstance(data, dict) and len(data) == 1:
                        key, data = next(iter(data.items()))
                        names.append(key)
                    array = isinstance(data, list)
                    if data != ([{}] if array else {}):
                        raise ValueError
                except (ValueError, TypeError):
                    raise ValueError(HANDOFF) from None
                resolved = []
                for depth, name in enumerate(names):
                    resolved.append(name)
                    if array and depth == len(names) - 1:
                        arrays[tuple(resolved)] = arrays.get(tuple(resolved), 0) + 1
                    if tuple(resolved) in arrays:
                        resolved.append(arrays[tuple(resolved)] - 1)
                table = tuple(resolved)
                headers[table] = i
                continue
            match = re.match(r'([ \t]*(?:[\w-]+|"[^"\n]+"|\'[^\'\n]+\')(?:[ \t]*\.[ \t]*(?:[\w-]+|"[^"\n]+"|\'[^\'\n]+\'))*[ \t]*=[ \t]*)(.*)', line)
            if match:
                parsed = tomllib.loads(match[1] + '0')
                keys = []
                while isinstance(parsed, dict) and len(parsed) == 1:
                    key, parsed = next(iter(parsed.items()))
                    keys.append(key)
                end = next((j for j in range(i + 1, len(lines)) if starts[j]), len(lines))
                found[table + tuple(keys)] = (i, end, match[1])
        return found, headers, arrays

    def get(data, path):
        for part in path:
            if isinstance(data, dict) and part in data:
                data = data[part]
            elif isinstance(data, list) and isinstance(part, int) and part < len(data):
                data = data[part]
            else:
                return missing
        return data

    def leaves(data, tables, prefix=()):
        for key, value in data.items():
            path = prefix + (key,)
            if isinstance(value, dict):
                yield from leaves(value, tables, path)
            elif path in tables and isinstance(value, list):
                for index, item in enumerate(value):
                    yield from leaves(item, tables, path + (index,))
            else:
                yield path, value

    # Whole array-of-tables elements removed (an uninstalled hook entry):
    # delete the element's header and everything below it up to the next
    # header outside that element. Deepest arrays first, one element each.
    while True:
        _, headers, arrays = locations()
        current = tomllib.loads(''.join(lines))
        removal = None
        for name in sorted(arrays, key=len, reverse=True):
            old, new = get(current, name), get(intended, name)
            new = [] if new is missing else new
            if isinstance(old, list) and isinstance(new, list) and len(new) == len(old) - 1:
                removal = next(((name, k) for k in range(len(old)) if old[:k] + old[k + 1:] == new), None)
                if removal:
                    break
        if removal is None:
            break
        element = removal[0] + (removal[1],)
        first = headers[element]
        last = min((i for path, i in headers.items() if i > first and path[:len(element)] != element),
                   default=len(lines))
        del lines[first:last]

    _, _, arrays = locations()
    current = tomllib.loads(''.join(lines))
    before, after = dict(leaves(current, arrays)), dict(leaves(intended, arrays))
    for path in before.keys() | after.keys():
        old, new = before.get(path, missing), after.get(path, missing)
        if old == new:
            continue
        found, headers, _ = locations()
        if path in found:
            start, end, prefix = found[path]
            # Retain inline comments on single-line assignments.
            comment = ''
            if end == start + 1:
                quote = None
                escaped = False
                for index, char in enumerate(lines[start][len(prefix):]):
                    if char == '#' and quote is None:
                        comment = ' ' + lines[start][len(prefix) + index:].rstrip('\r\n')
                        break
                    if char in ('"', "'") and not escaped:
                        quote = None if quote == char else char if quote is None else quote
                    escaped = char == '\\' and not escaped
            lines[start:end] = ([prefix + _toml_value(new) + comment + newline] if new is not missing else
                                [comment.lstrip() + newline] if comment else [])
        elif old is not missing:
            raise ValueError(HANDOFF)
        elif path[:-1] in headers:
            # Prefer an existing explicit table; dotted root declarations cannot
            # redefine a table which the owner already declared below.
            lines.insert(headers[path[:-1]] + 1, _toml_key(path[-1]) + ' = ' + _toml_value(new) + newline)
        elif any(isinstance(part, int) for part in path):
            raise ValueError(HANDOFF)  # A new array element; never synthesized.
        elif len(path) > 1 and get(tomllib.loads(''.join(lines)), path[:-1]) is missing:
            # A brand-new table gets a header, as install writes it, so either
            # editor can find it on a later run.
            if lines and not lines[-1].endswith('\n'):
                lines[-1] += newline
            lines += ['[' + '.'.join(_toml_key(part) for part in path[:-1]) + ']' + newline,
                      _toml_key(path[-1]) + ' = ' + _toml_value(new) + newline]
        else:
            key = '.'.join(_toml_key(part) for part in path)
            lines.insert(0, key + ' = ' + _toml_value(new) + newline)
    result = ''.join(lines)
    # Empty leftover tables are harmless but remove those absent from intended.
    # Only a header with no statements before the next header can be redundant.
    starts = statement_starts(lines)
    body = [starts[i] and lines[i].strip() and not lines[i].lstrip().startswith('#')
            for i in range(len(lines))]
    for i in range(len(lines) - 1, -1, -1):
        following = next((j for j in range(i + 1, len(lines)) if body[j]), None)
        empty = following is None or lines[following].lstrip().startswith('[')
        if starts[i] and empty and lines[i].lstrip().startswith('[') and not lines[i].lstrip().startswith('[['):
            try:
                header = tomllib.loads(lines[i])
                cursor = intended
                absent = False
                while header:
                    key, header = next(iter(header.items()))
                    if key not in cursor:
                        absent = True
                        break
                    cursor = cursor[key]
                if absent:
                    for column in (lines, starts, body):
                        column.pop(i)
                    continue
                trial = ''.join(lines[:i] + lines[i + 1:])
                if tomllib.loads(trial) == intended:
                    for column in (lines, starts, body):
                        column.pop(i)
            except ValueError:
                pass
    result = ''.join(lines)
    if _without_empty_tables(tomllib.loads(result)) != _without_empty_tables(intended):
        raise ValueError(HANDOFF)
    return result


def policy_plan(changes, *, required=True):
    if not isinstance(changes, dict):
        raise ValueError(HANDOFF)
    config = baseline(required=required)
    updated = merge(config, changes)
    policy.validate_policy('config.json', updated)
    if not classify(config, updated):
        raise ValueError(HANDOFF)
    if 'enabled' in changes and os.environ.get('SIFTFETCH_ENABLED') == '0':
        raise ValueError(HANDOFF)
    base = policy.policy_dir()
    paths = [base / ('config.' + ext) for ext in ('json', 'toml') if (base / ('config.' + ext)).exists()]
    paths = paths or [base / 'config.json']
    plan = []
    for path in paths:
        from siftfetch.cli import _safe_path
        _safe_path(path)
        raw = path.read_bytes() if path.exists() else None
        text = (raw if raw is not None else b'{}').decode('utf-8')
        before = tomllib.loads(text) if path.suffix == '.toml' else json.loads(text)
        after = merge(before, changes)
        policy.validate_policy(path.name, after)
        if not classify(before, after):
            raise ValueError(HANDOFF)
        encoded = edit_toml(text, after) if path.suffix == '.toml' else json.dumps(after, indent=2) + '\n'
        if before != after:
            plan.append((path, raw, encoded))
    return plan


def tighten(changes):
    written = 0
    try:
        plan = policy_plan(changes)
        for path, raw, text in plan:
            atomic_write(path, text, raw)
            written += 1
        policy._cached = None
        return {'ok': True, 'changed_files': len(plan), 'message': 'Tightening applied.'}
    except (ValueError, OSError, TypeError):
        return {'ok': False, 'changed_files': written, 'message': HANDOFF +
                (' Partial write; retain backups and inspect locally.' if written else '')}


def open_editor(path):
    """Detached editor handoff; never read contents, use a shell, or accept values."""
    editor = os.environ.get('EDITOR')
    args = shlex.split(editor, posix=os.name != 'nt') if editor else (
        ['notepad'] if os.name == 'nt' else ['open'] if sys.platform == 'darwin' else ['xdg-open'])
    args = [arg.strip('"') for arg in args] + [str(path)]
    kwargs = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    subprocess.Popen(args, **kwargs)


def temporary_interpreter():
    executable = Path(sys.executable).resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    normalized = executable.as_posix().lower()
    return (executable.is_relative_to(temporary) or '/uv/cache/' in normalized or '/uv/archive-v' in normalized or any(
        re.fullmatch(r'\.?(?:tmp|temp|temporary)(?:[-_].*)?', part, re.I)
        for part in executable.parts))


def management_argv_allowed(args):
    """Small exact grammar for the shell guard, independent of TTY or markers."""
    if args and args[0] == 'get':
        return True  # Data fetch; the get parser and transport enforce its scope.
    if args in (['--help'], ['-h']):
        return True
    if not args or args[0] not in ('doctor', 'status', 'install', 'setup', 'uninstall', 'tighten'):
        return False
    action, rest = args[0], list(args[1:])
    if rest in (['--help'], ['-h']):
        return True
    options = {'--client': ('claude', 'codex'), '--scope': ('user', 'project')}
    if action == 'setup':
        options['--preset'] = ('standard', 'lockdown', 'strict', 'custom')
    if action == 'tighten':
        return len(rest) == 1 and rest[0] in ('enabled', 'guard-lock', 'secret-files', 'browser-off') or (
            len(rest) == 2 and rest[0] == 'blocked-domain')
    seen = set()
    while rest:
        token = rest.pop(0)
        if token in seen:
            return False
        seen.add(token)
        if token == '--json' and action in ('doctor', 'status'):
            continue
        if token in ('--replace', '--adopt') and action == 'install':
            continue
        if token not in options or not rest or rest.pop(0) not in options[token]:
            return False
    # An incomplete setup invocation enters the wizard and can confirm writes.
    return action != 'setup' or {'--client', '--scope', '--preset'} <= seen
