"""Versioned ownership receipts. Never store whole client documents or policy values."""
import copy
import hashlib
import json
from pathlib import Path
import shlex
import re

from siftfetch import egress_policy as policy
from siftfetch.management import atomic_write, edit_toml


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load():
    from siftfetch.cli import _safe_path
    path = policy.policy_dir() / 'install-manifest.json'
    _safe_path(path)
    if not path.exists():
        return {'version': 1, 'transactions': []}
    data = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(data, dict) or set(data) != {'version', 'transactions'} or data['version'] != 1
            or not isinstance(data['transactions'], list)):
        raise ValueError('invalid install manifest')
    for tx in data['transactions']:
        if (not isinstance(tx, dict) or set(tx) != {'state', 'client', 'scope', 'files'} or
                tx['state'] not in ('pending', 'complete', 'removed') or
                tx['client'] not in ('claude', 'codex') or tx['scope'] not in ('user', 'project') or
                not isinstance(tx['files'], list)):
            raise ValueError('invalid install manifest')
        for item in tx['files']:
            if (not isinstance(item, dict) or set(item) != {'file', 'state', 'edits', 'containers', 'backup'} or
                    item['state'] not in ('pending', 'complete') or not isinstance(item['edits'], list) or
                    not isinstance(item['containers'], list) or not isinstance(item['file'], str) or
                    not Path(item['file']).is_absolute()):
                raise ValueError('invalid install manifest')
            permitted = {('hooks', 'PreToolUse'): 'item', ('hooks', 'PostToolUse'): 'item',
                         ('permissions', 'deny'): 'item', ('mcpServers', 'siftfetch'): 'object',
                         ('mcp_servers', 'siftfetch'): 'object', ('web_search',): 'scalar',
                         ('shell_environment_policy', 'ignore_default_excludes'): 'scalar'}
            containers = {p[:i] for p in permitted for i in range(1, len(p))} | {
                ('hooks', 'PreToolUse'), ('hooks', 'PostToolUse'), ('permissions', 'deny')}
            if any(not isinstance(p, list) or not all(isinstance(k, str) for k in p) or tuple(p) not in containers
                   for p in item['containers']):
                raise ValueError('invalid install manifest')
            if item['backup'] is not None and (not isinstance(item['backup'], str) or not re.fullmatch(
                    re.escape(item['file']) + r'\.siftfetch-backup-[0-9a-f]{32}', item['backup'])):
                raise ValueError('invalid install manifest')
            for edit in item['edits']:
                if (not isinstance(edit, dict) or set(edit) != {'path', 'kind', 'installed', 'owned', 'prior'} or
                        edit['kind'] not in ('item', 'scalar', 'object') or type(edit['owned']) is not bool or
                        not isinstance(edit['path'], list) or not edit['path'] or
                        not all(isinstance(k, str) for k in edit['path']) or
                        not isinstance(edit['installed'], str) or not re.fullmatch('[0-9a-f]{64}', edit['installed'])):
                    raise ValueError('invalid install manifest')
                path_key = tuple(edit['path'])
                if permitted.get(path_key) != edit['kind']:
                    raise ValueError('invalid install manifest')
                if edit['prior'] is not None:
                    allowed = ('disabled', 'cached', 'indexed', 'live') if path_key == ('web_search',) else (True, False)
                    if (edit['kind'] != 'scalar' or edit['prior'] not in allowed or
                            path_key != ('web_search',) and type(edit['prior']) is not bool):
                        raise ValueError('invalid install manifest')
    return data


def save(data):
    path = policy.policy_dir() / 'install-manifest.json'
    raw = path.read_bytes() if path.exists() else None
    atomic_write(path, json.dumps(data, indent=2) + '\n', raw, backup=False)


def edits(before, after, prefix=()):
    result, containers = [], []
    for key, new in after.items():
        path = prefix + (key,)
        if not prefix and key not in ('hooks', 'permissions', 'mcpServers', 'mcp_servers', 'web_search', 'shell_environment_policy'):
            continue
        if prefix == ('permissions',) and key != 'deny':
            continue
        if prefix == ('hooks',) and key not in ('PreToolUse', 'PostToolUse'):
            continue
        if prefix == ('shell_environment_policy',) and key != 'ignore_default_excludes':
            continue
        if prefix in (('mcpServers',), ('mcp_servers',)) and key != 'siftfetch':
            continue
        old = before.get(key)
        if isinstance(new, dict) and key != 'siftfetch':
            child, created = edits(old or {}, new, path)
            result.extend(child)
            containers.extend(created)
            if key not in before:
                containers.append(list(path))
        elif isinstance(new, list):
            for value in new:
                result.append({'path': list(path), 'kind': 'item', 'installed': digest(value),
                               'owned': value not in (old or []), 'prior': None})
            if key not in before:
                containers.append(list(path))
        elif key == 'siftfetch' or path in (('web_search',), ('shell_environment_policy', 'ignore_default_excludes')):
            result.append({'path': list(path), 'kind': 'object' if isinstance(new, dict) else 'scalar',
                           'installed': digest(new), 'owned': old != new,
                           'prior': old if not isinstance(new, dict) else None})
    return result, containers


def begin(client, scope, paths, before, after, *, replace=False):
    data = load()
    if any(tx['state'] == 'pending' for tx in data['transactions']):
        raise ValueError('interrupted journal; owner review required')
    tx = {'state': 'pending', 'client': client, 'scope': scope, 'files': []}
    for path, original, installed in zip(paths, before, after):
        changes, containers = edits(original, installed)
        for edit in changes:
            if any(previous['state'] == 'complete' and item['file'] == str(path.absolute()) and
                   owned['owned'] and owned['path'] == edit['path'] and owned['installed'] == edit['installed']
                   for previous in data['transactions'] for item in previous['files'] for owned in item['edits']):
                edit['owned'] = False
        if replace:
            # Transfer existing ownership to the new interpreter without owning
            # entries which predated installation or creating duplicate receipts.
            old_edits, _ = edits({}, original)
            for edit in changes:
                candidates = [old for old in old_edits if old['path'] == edit['path'] and old['kind'] == edit['kind']]
                if len(candidates) != 1 or candidates[0]['installed'] == edit['installed']:
                    continue
                for previous in data['transactions']:
                    for item in previous['files']:
                        if item['file'] != str(path.absolute()):
                            continue
                        for owned in item['edits']:
                            if owned['owned'] and owned['path'] == edit['path'] and owned['installed'] == candidates[0]['installed']:
                                owned['installed'] = edit['installed']
                                edit['owned'] = False
        # Retain first ownership across idempotent installs. New transactions own only new changes.
        tx['files'].append({'file': str(path.absolute()), 'state': 'pending', 'edits': changes,
                            'containers': containers, 'backup': None})
    if not any(edit['owned'] for item in tx['files'] for edit in item['edits']):
        for previous in reversed(data['transactions']):
            if (previous['state'] == 'complete' and previous['client'] == client and previous['scope'] == scope and
                    [item['file'] for item in previous['files']] == [item['file'] for item in tx['files']] and
                    not drift(data, paths)):
                return data, previous
    data['transactions'].append(tx)
    save(data)
    return data, tx


def _parent(document, path):
    for key in path[:-1]:
        if not isinstance(document, dict) or key not in document:
            return None
        document = document[key]
    return document if isinstance(document, dict) else None


def revert(document, record, *, hooks):
    result = copy.deepcopy(document)
    conflicts = []
    for edit in reversed(record['edits']):
        if not edit['owned'] or (edit['path'][0] == 'hooks') != hooks:
            continue
        parent = _parent(result, edit['path'])
        key = edit['path'][-1]
        current = parent.get(key) if parent is not None else None
        if edit['kind'] == 'item':
            matches = [i for i, value in enumerate(current or []) if digest(value) == edit['installed']] if isinstance(current, list) else []
            if len(matches) != 1:
                conflicts.append('.'.join(edit['path']))
                continue
            current.pop(matches[0])
        elif parent is None or key not in parent or digest(current) != edit['installed']:
            conflicts.append('.'.join(edit['path']))
        elif edit['prior'] is None:
            del parent[key]
        else:
            parent[key] = edit['prior']
    for path in sorted(record['containers'], key=len, reverse=True):
        parent = _parent(result, path)
        if parent is not None and parent.get(path[-1]) in ({}, []):
            del parent[path[-1]]
    return result, conflicts


def uninstall_plan(client=None, scope='user', *, home=None, project=None):
    from siftfetch.cli import _targets, _read_settings
    data = load()
    if any(tx['state'] == 'pending' for tx in data['transactions']):
        raise ValueError('interrupted journal; no replay; owner review required')
    targets = {str(path.absolute()) for selected in ([client] if client else ['claude', 'codex'])
               for path in _targets(selected, scope, home, project)}
    if any(Path(path).is_relative_to(policy.policy_dir().absolute()) for path in targets):
        raise ValueError('client settings cannot be inside the protected policy folder')
    documents, raw, changes, conflicts, backups = {}, {}, [], [], []
    records = [(tx, item) for tx in reversed(data['transactions']) if tx['state'] == 'complete'
               and tx['scope'] == scope and (client is None or client == tx['client'])
               for item in tx['files'] if item['file'] in targets]
    for _, record in records:
        path = Path(record['file'])
        if path not in documents:
            documents[path] = _read_settings(path)
            raw[path] = path.read_bytes() if path.exists() else None
        if record['backup']:
            backups.append(record['backup'])
    for hooks in (False, True):
        for _, record in records:
            path = Path(record['file'])
            before = documents[path]
            after, problems = revert(before, record, hooks=hooks)
            conflicts.extend(problems)
            if after != before:
                text = ((raw[path] or b'').decode('utf-8'))
                encoded = edit_toml(text, after) if path.suffix == '.toml' else json.dumps(after, indent=2) + '\n'
                changes.append((path, raw[path], encoded))
                documents[path], raw[path] = after, encoded.encode('utf-8')
    # A completed uninstall must not turn retained pre-existing registrations
    # into legacy-owned entries on a later run.
    history = any(tx['scope'] == scope and (client is None or client == tx['client'])
                  and any(item['file'] in targets for item in tx['files'])
                  for tx in data['transactions'])
    if not records and not history:
        changes, conflicts = legacy_plan(client, scope, home=home, project=project)
    return data, records, changes, sorted(set(conflicts)), sorted(set(backups))


def legacy_plan(client=None, scope='user', *, home=None, project=None):
    """Recognizable registrations only; native denies/scalars have no proven ownership."""
    from siftfetch.cli import _targets, _read_settings, _module_interpreter
    changes, conflicts = [], []
    state = {}
    for selected in ([client] if client else ['claude', 'codex']):
        for path in _targets(selected, scope, home, project):
            original = _read_settings(path)
            state[path] = (original, path.read_bytes() if path.exists() else None)
            if original.get('permissions', {}).get('deny') or 'web_search' in original or 'shell_environment_policy' in original:
                conflicts.append('legacy denies/scalars: ownership unknown; retained')
    for hooks in (False, True):
        for path, (original, raw) in list(state.items()):
            after = copy.deepcopy(original)
            if hooks:
                for event, groups in after.get('hooks', {}).items():
                    if not isinstance(groups, list):
                        raise ValueError('malformed legacy hooks')
                    retained = []
                    for group in groups:
                        if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                            retained.append(group)
                            continue
                        handlers = []
                        for handler in group['hooks']:
                            recognized = False
                            if isinstance(handler, dict) and handler.get('type') == 'command':
                                try:
                                    tokens = [t.strip('"\'') for t in shlex.split(handler.get('command', ''), posix=False)]
                                    recognized = _module_interpreter(tokens, 'siftfetch.hook') is not None
                                except ValueError:
                                    pass
                            if not recognized:
                                handlers.append(handler)
                        if handlers or not group['hooks']:
                            retained.append({**group, 'hooks': handlers})
                    after['hooks'][event] = retained
            else:
                for key in ('mcpServers', 'mcp_servers'):
                    entry = after.get(key, {}).get('siftfetch')
                    if isinstance(entry, dict) and _module_interpreter(
                            [entry.get('command'), *entry.get('args', [])], 'siftfetch.server'):
                        del after[key]['siftfetch']
                        if not after[key]:
                            del after[key]
            if after != original:
                text = edit_toml((raw or b'').decode('utf-8'), after) if path.suffix == '.toml' else json.dumps(after, indent=2) + '\n'
                changes.append((path, raw, text))
                state[path] = (after, text.encode())
    return changes, conflicts


def drift(data, targets):
    """Count drift without exposing hashes, settings values or arbitrary receipt paths."""
    from siftfetch.cli import _read_settings
    selected = {str(path.absolute()): path for path in targets}
    documents = {}
    changed = 0
    for tx in data['transactions']:
        if tx['state'] != 'complete':
            continue
        for item in tx['files']:
            if item['file'] not in selected:
                continue
            if item['file'] not in documents:
                documents[item['file']] = _read_settings(selected[item['file']])
            for edit in item['edits']:
                if not edit['owned']:
                    continue
                parent = _parent(documents[item['file']], edit['path'])
                current = parent.get(edit['path'][-1]) if parent else None
                if edit['kind'] == 'item':
                    matches = sum(digest(v) == edit['installed'] for v in current) if isinstance(current, list) else 0
                else:
                    matches = int(digest(current) == edit['installed'])
                changed += matches != 1
    return changed
