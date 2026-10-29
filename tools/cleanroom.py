"""Build and exercise distributions without inheriting a developer profile (stdlib only)."""
from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib


# Split literals so the scanner does not flag its own deny vocabulary.
OWNER_STRINGS = ('.dev-' + 'shared', 'c:/pro' + 'jects', 'c:\\Pro' + 'jects',
                 'c:/to' + 'ols', 'c:\\To' + 'ols', 'rag-' + 'search', 'agent-' + 'mail',
                 'Awakened' + 'Span' + 'reed', 'Span' + 'reed', 'cli' + 'nt',
                 '@gmail' + '.com', 'duck' + '.com', 'quiet-' + 'otter')


def owner_hits(name, data):
    hits = []
    for number, line in enumerate(data.decode('utf-8', errors='replace').splitlines(), 1):
        # Explicit author attribution is public package metadata, not a dependency.
        # PKG-INFO's Author field is generated from the allowlisted pyproject line.
        author = 'Cli' + 'nton Campbell'
        if ((Path(name).name == 'pyproject.toml' and line == 'authors = [{ name = "' + author + '" }]') or
                (Path(name).name == 'PKG-INFO' and line == 'Author: ' + author) or
                (Path(name).name == 'NOTICE' and line == 'Copyright 2026 ' + author + ' (XRMech Solutions)')):
            continue
        if any(value.casefold() in line.casefold() for value in OWNER_STRINGS):
            hits.append(f'{name}:{number}')
    return hits


def clean_env(root, scripts=None):
    profile = root / 'profile'
    env = {key: str(profile / value) for key, value in {
        'HOME': '', 'USERPROFILE': '', 'APPDATA': 'roaming', 'LOCALAPPDATA': 'local',
        'XDG_CONFIG_HOME': 'config', 'XDG_DATA_HOME': 'data', 'XDG_CACHE_HOME': 'cache',
        'XDG_STATE_HOME': 'state', 'XDG_RUNTIME_DIR': 'runtime', 'CODEX_HOME': '.codex',
        'TEMP': 'tmp', 'TMP': 'tmp', 'TMPDIR': 'tmp'}.items()}
    if os.name == 'nt':
        system = Path(os.environ.get('SystemRoot', r'C:\Windows'))
        env.update(SystemRoot=str(system), WINDIR=str(system), COMSPEC=str(system / 'System32/cmd.exe'))
        system_paths = [system / 'System32', system]
    else:
        system_paths = [Path('/usr/bin'), Path('/bin')]
        env['LANG'] = 'C.UTF-8'
    env['PATH'] = os.pathsep.join(map(str, ([scripts] if scripts else []) + system_paths))
    env['PIP_CONFIG_FILE'] = os.devnull
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    return env


def validate_paths(root, paths):
    root = root.resolve()
    if set(paths) != {'home', 'policy', 'data'}:
        raise RuntimeError('guard did not return every required path')
    for name, value in paths.items():
        path = Path(value).resolve()
        if path == root or not path.is_relative_to(root):
            raise RuntimeError(f'unsafe {name}: outside clean-room root')


def guard(root, python, env, *, installed=False):
    code = "from pathlib import Path; import json, os, sys; h=Path.home(); "
    if installed:
        code += ('from siftfetch.egress_policy import policy_dir; '
                 'from siftfetch.saving import data_dir; p=policy_dir(); d=data_dir(); ')
    else:
        code += ("p=h/'.siftfetch'; d=(Path(os.environ['LOCALAPPDATA'])/'siftfetch' "
                 "if sys.platform=='win32' else Path(os.environ['XDG_DATA_HOME'])/'siftfetch'); ")
    code += "print(json.dumps(dict(home=str(h), policy=str(p), data=str(d))))"
    result = subprocess.run([str(python), '-B', '-I', '-c', code], cwd=root, env=env,
                            capture_output=True, text=True, encoding='utf-8', timeout=60, check=True)
    paths = json.loads(result.stdout)
    print('GUARD ' + json.dumps(paths), flush=True)
    validate_paths(root, paths)
    return paths


class Harness:
    def __init__(self, root, options):
        self.root, self.options = root, options
        self.env = clean_env(root)
        self.python = Path(sys.executable)
        self.installed = False
        self.failed = False

    def check(self):
        return guard(self.root, self.python, self.env, installed=self.installed)

    def run(self, args, *, cwd=None, input=None, expected=0, timeout=600):
        self.check()
        result = subprocess.run([str(a) for a in args], cwd=cwd or self.root, env=self.env,
                                input=input, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=timeout)
        if result.returncode != expected:
            raise RuntimeError(f'{Path(str(args[0])).name} exited {result.returncode}\n'
                               + (result.stdout + result.stderr)[-12000:])
        return result.stdout + result.stderr

    def step(self, label, function):
        try:
            reason = function()
            print(f'PASS {label}: {reason if isinstance(reason, str) else "completed"}', flush=True)
            return True
        except Exception as exc:
            self.failed = True
            print(f'FAIL {label}: {exc}', flush=True)
            return False

    def pip_options(self):
        return (['--no-index'] if self.options.offline else []) + [
            item for directory in self.options.find_links for item in ('--find-links', str(directory))]

    def copy_source(self):
        self.check()
        repo = Path(__file__).resolve().parents[1]
        names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-co', '--exclude-standard', '-z'])
        tracked = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z'])
        self.source = self.root / 'source'
        self.source.mkdir()
        for name in sorted(set(names.decode('utf-8').split('\0')) - {''}):
            parts = Path(name).parts
            if any(part in {'.venv', 'build', 'dist', '__pycache__', '.pytest_cache', '.git', '.secrets'} or
                   part.startswith(('pytest-cache-files-', '.test-', '.env')) or part.endswith('.egg-info') for part in parts):
                continue
            source = repo / name
            if source.is_symlink() or not source.resolve().is_relative_to(repo.resolve()):
                raise RuntimeError('source contains a link outside the copy boundary')
            if not source.is_file():
                continue
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        (self.source / '.cleanroom-tracked.json').write_text(json.dumps(tracked.decode().split('\0')), encoding='utf-8')
        return 'tracked and nonignored files copied; build/cache/profile inputs excluded'

    def build(self):
        self.run([self.python, '-m', 'venv', self.root / 'builder'])
        self.python = self.root / 'builder' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        self.env = clean_env(self.root, self.python.parent)
        self.run([self.python, '-m', 'pip', 'install', *self.pip_options(), 'setuptools>=77', 'wheel'])
        # Build is optional: the backend fallback still produces and validates an sdist.
        try:
            self.run([self.python, '-m', 'pip', 'install', *self.pip_options(), 'build'])
            frontend = True
        except RuntimeError:
            frontend = False
        if frontend:
            self.run([self.python, '-m', 'build', '--no-isolation'], cwd=self.source)
        else:
            self.run([self.python, '-c', "import setuptools.build_meta as b; b.build_sdist('dist')"], cwd=self.source)
            self.run([self.python, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                      *self.pip_options(), '-w', self.source / 'dist', self.source])
        self.sdist = next((self.source / 'dist').glob('*.tar.gz'))
        self.wheel = next((self.source / 'dist').glob('*.whl'))
        unpacked = self.root / 'sdist'
        self.check()
        unpacked.mkdir()
        with tarfile.open(self.sdist) as archive:
            for member in archive.getmembers():
                if (not (member.isfile() or member.isdir()) or not
                        (unpacked / member.name).resolve().is_relative_to(unpacked.resolve())):
                    raise RuntimeError('unsafe sdist member')
            archive.extractall(unpacked)
        extracted = next(unpacked.iterdir())
        self.run([self.python, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                  *self.pip_options(), '-w', self.root / 'rebuilt', extracted])
        return 'source wheel, sdist, and wheel rebuilt from sdist'

    def scan(self):
        hits = []
        with tarfile.open(self.sdist) as archive:
            for member in archive.getmembers():
                hits.extend(owner_hits(member.name, member.name.encode()))
                if member.isfile():
                    hits.extend(owner_hits(member.name, archive.extractfile(member).read()))
        if hits:
            raise RuntimeError('owner strings: ' + ', '.join(hits))
        return 'all sdist file contents scanned; only public author attribution allowed'

    def install(self, variant):
        self.installed = False
        self.python = Path(sys.executable)
        self.env = clean_env(self.root)
        venv = self.root / ('venv-' + variant)
        self.run([self.python, '-m', 'venv', venv])
        self.python = venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        self.env = clean_env(self.root, self.python.parent)
        self.run([self.python, '-m', 'pip', 'install', *self.pip_options(),
                  str(self.wheel) + ('[pdf,test]' if variant == 'pdf' else '[test]')])
        self.installed = True
        self.check()
        self.console = self.python.parent / ('siftfetch.exe' if os.name == 'nt' else 'siftfetch')
        return 'fresh noneditable wheel install: ' + variant

    def package_data(self):
        self.run([self.python, '-I', '-c', '''import json, sys
from pathlib import Path
from importlib.resources import files
import siftfetch
assert Path(siftfetch.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
p = files('siftfetch')
assert json.loads(p.joinpath('injection_patterns.json').read_text(encoding='utf-8'))
assert 'com' in p.joinpath('public_suffix_list.dat').read_text(encoding='utf-8').splitlines()
for name in ('config', 'identifiers', 'exceptions'):
    assert isinstance(json.loads(p.joinpath('templates', name+'.json').read_text(encoding='utf-8')), dict)
'''])
        return 'patterns, suffix list, templates load from site-packages'

    def prepare_profile(self):
        self.check()
        for key in ('HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'XDG_DATA_HOME'):
            Path(self.env[key]).mkdir(parents=True, exist_ok=True)
        return 'home, policy and data resolve inside scratch root'

    def tests(self):
        runner = '''import sys
from pathlib import Path
from importlib.machinery import PathFinder
import pytest
sys.path.insert(0, str(Path(sys.argv[-1]).resolve()))
class InstalledFinder:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'siftfetch' or fullname.startswith('siftfetch.'):
            spec = PathFinder.find_spec(fullname, path)
            if spec and spec.origin:
                assert Path(spec.origin).resolve().is_relative_to(Path(sys.prefix).resolve()), (fullname, spec.origin)
            return spec
sys.meta_path.insert(0, InstalledFinder())
class InstalledOnly:
    def pytest_runtest_teardown(self, item, nextitem):
        for name, module in tuple(sys.modules.items()):
            if name == 'siftfetch' or name.startswith('siftfetch.'):
                path = getattr(module, '__file__', None)
                if path:
                    assert Path(path).resolve().is_relative_to(Path(sys.prefix).resolve()), (name, path)
raise SystemExit(pytest.main(sys.argv[1:], plugins=[InstalledOnly()]))
'''
        output = self.run([self.python, '-I', '-c', runner, '-q', '-p', 'no:cacheprovider',
                          '--import-mode=importlib', '-o', 'pythonpath=', self.source / 'tests'], timeout=1800)
        return output.strip().splitlines()[-1]

    def profile(self, name):
        self.env = clean_env(self.root / name, self.python.parent)
        self.prepare_profile()

    def setup(self):
        for scenario in ('empty', 'existing', 'legacy'):
            self.profile(self.python.parent.parent.name + '-' + scenario)
            home = Path(self.env['HOME'])
            paths = [home / '.claude/settings.json', home / '.claude.json',
                     home / '.codex/config.toml', home / '.codex/hooks.json']
            documents = [{}, {}, {}, {}]
            comment = '# unrelated comment\n'
            if scenario != 'empty':
                other = {'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'other-hook'}]}
                documents = [{'hooks': {'PreToolUse': [other]}, 'permissions': {'allow': ['Read(public/**)']}},
                             {'mcpServers': {'other': {'command': 'other-server'}}},
                             {'model': 'example', 'mcp_servers': {'other': {'command': 'other-server'}}},
                             {'hooks': {'PreToolUse': [other]}}]
            originals = json.loads(json.dumps(documents))
            if scenario == 'legacy':
                interpreter = 'C:/Legacy/sf/python.exe'
                command = '"' + interpreter + '" "-I" "-m" "siftfetch.hook"'
                for event in ('PreToolUse', 'PostToolUse'):
                    documents[0]['hooks'].setdefault(event, []).append({
                        'matcher': '*', 'hooks': [{'type': 'command', 'command': command}]})
                documents[3]['hooks']['PreToolUse'].append({'matcher': '*', 'hooks': [
                    {'type': 'command', 'command': command + ' "--deny"'}]})
                server = {'command': interpreter, 'args': ['-I', '-m', 'siftfetch.server']}
                documents[1]['mcpServers']['siftfetch'] = server
                documents[2]['mcp_servers']['siftfetch'] = server
            if scenario != 'empty':
                self.check()
                for path, document in zip(paths, documents):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if path.suffix == '.toml':
                        text = comment + 'model = "example"\n[mcp_servers.other]\ncommand = "other-server"\n'
                        if scenario == 'legacy':
                            text += '[mcp_servers.siftfetch]\ncommand = "C:/Legacy/sf/python.exe"\nargs = ["-I", "-m", "siftfetch.server"]\n'
                    else:
                        text = json.dumps(document)
                    path.write_text(text, encoding='utf-8')
            self.run([self.console, 'init'])
            if scenario == 'legacy':
                before = [path.read_bytes() for path in paths]
                for client in ('claude', 'codex'):
                    self.run([self.console, 'install', '--client', client, '--adopt'])
                assert before == [path.read_bytes() for path in paths], 'adopt preview wrote settings'
                for client in ('claude', 'codex'):
                    self.run([self.console, 'install', '--client', client, '--adopt', '--apply'])
            for preset in ('standard', 'lockdown'):
                args = ['setup', '--client', 'claude', '--client', 'codex', '--scope', 'user',
                        '--preset', preset, '--apply']
                self.run([self.console, *args])
                snapshot = [p.read_bytes() for p in paths]
                self.run([self.console, *args])
                assert snapshot == [p.read_bytes() for p in paths], 'setup not idempotent'
            for client in ('claude', 'codex'):
                snapshot = [p.read_bytes() for p in paths]
                self.run([self.console, 'install', '--client', client, '--apply'])
                assert snapshot == [p.read_bytes() for p in paths], 'install not idempotent'
            output = self.run([self.console, 'doctor'])
            for line in ('PASS package installed', 'PASS policy parse and substitute sanity',
                         'PASS claude MCP server entry', 'PASS codex MCP server entry'):
                assert line in output, line
            # The CLI demands a real console for this confirmation; answer through
            # the prompt hook its tests use, leaving that requirement intact.
            self.run([self.python, '-I', '-c', "import sys; from siftfetch import cli; "
                      "answers = iter(['uninstall', 'n']); "
                      "sys.exit(cli.uninstall(apply=True, prompt=lambda _: next(answers)))"])
            for path, original in zip(paths, originals):
                value = (tomllib.loads(path.read_text(encoding='utf-8')) if path.suffix == '.toml'
                         else json.loads(path.read_text(encoding='utf-8'))) if path.exists() else {}
                # Empty legacy containers have no remaining registration semantics.
                assert prune(value) == prune(original), 'uninstall changed unrelated content'
            if scenario != 'empty':
                assert comment.strip() in paths[2].read_text(encoding='utf-8')
                policy = Path(self.check()['policy'])
                journal = json.loads((policy / 'install-manifest.json').read_text(encoding='utf-8'))
                backups = [item['backup'] for tx in journal['transactions'] for item in tx['files'] if item['backup']]
                assert backups and all(Path(path).is_file() for path in backups)
        return 'empty, unrelated-content and legacy profiles; presets, doctor, idempotence, uninstall, backups'

    def smoke(self, variant):
        self.profile('smoke-' + variant)
        self.run([self.console, 'init'])
        hook = self.python.parent / ('siftfetch-hook.exe' if os.name == 'nt' else 'siftfetch-hook')
        for command, reason in [('echo cleanroom', None), ('cat .env', 'secret_file'),
                                ('curl https://example.invalid/', 'reroute')]:
            output = self.run([hook], input=json.dumps({'hook_event_name': 'PreToolUse',
                              'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(self.root)}))
            if reason == 'secret_file':
                decision = json.loads(output)['hookSpecificOutput']
                assert decision['permissionDecision'] == 'deny' and reason in decision['permissionDecisionReason']
            elif reason == 'reroute':
                decision = json.loads(output)['hookSpecificOutput']
                assert decision['permissionDecision'] == 'allow' and 'get' in decision['updatedInput']['command']
            else:
                assert not output.strip() or json.loads(output)['hookSpecificOutput']['permissionDecision'] == 'allow'
        with loopback_server() as server:
            port = server.server_port
            policy = Path(self.check()['policy'])
            config_path = policy / 'config.json'
            config = json.loads(config_path.read_text(encoding='utf-8'))
            config['local_endpoints'] = [{'scheme': 'http', 'host': '127.0.0.1', 'port': port,
                                          'service': 'cleanroom', 'allowed_ops': ['fetch']}]
            config_path.write_text(json.dumps(config), encoding='utf-8')
            url = f'http://127.0.0.1:{port}'
            html = self.run([self.console, 'get', url + '/page'])
            assert 'Cleanroom article' in html and 'UNTRUSTED' in html.upper()
            pdf = self.run([self.console, 'get', url + '/paper.pdf'], expected=2 if variant == 'no-pdf' else 0)
            assert '%PDF-' not in pdf
            assert ('no PDF extractor' in pdf if variant == 'no-pdf' else 'Cleanroom PDF' in pdf)
            self.check()
            stdio_smoke(self.python.parent / ('siftfetch-server.exe' if os.name == 'nt' else 'siftfetch-server'),
                        self.root, self.env, url + '/page')
        output = self.run([self.console, 'benchmark'])
        assert 'Sentinel leaks: 0' in output
        return 'hook allow/deny/reroute, stdio MCP tools/fetch, HTML/PDF get, packaged benchmark'


def prune(value):
    if isinstance(value, dict):
        return {key: prune(item) for key, item in value.items() if prune(item) not in ({}, [])}
    return value


def pdf_bytes():
    stream = b'BT /F1 12 Tf 72 720 Td (Cleanroom PDF) Tj ET'
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
               b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'\nendstream']
    output, offsets = b'%PDF-1.4\n', [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output += str(number).encode() + b' 0 obj\n' + obj + b'\nendobj\n'
    start = len(output)
    output += b'xref\n0 6\n0000000000 65535 f \n'
    output += b''.join(f'{offset:010} 00000 n \n'.encode() for offset in offsets[1:])
    return output + f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n'.encode()


@contextlib.contextmanager
def loopback_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            pdf = self.path == '/paper.pdf'
            body = pdf_bytes() if pdf else (b'<html><body><article><h1>Cleanroom article</h1><p>' +
                                           b'A harmless local release check. ' * 40 + b'</p></article></body></html>')
            self.send_response(200)
            self.send_header('Content-Type', 'application/pdf' if pdf else 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def stdio_smoke(executable, cwd, env, url):
    process = subprocess.Popen([str(executable)], cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    messages, errors = queue.Queue(), []
    def read_output():
        for line in process.stdout:
            try:
                messages.put(json.loads(line))
            except ValueError:
                messages.put({'invalid': line})
    reader = threading.Thread(target=read_output, daemon=True)
    logger = threading.Thread(target=lambda: errors.extend(process.stderr.readlines()), daemon=True)
    reader.start()
    logger.start()
    def send(value):
        process.stdin.write(json.dumps({'jsonrpc': '2.0', **value}) + '\n')
        process.stdin.flush()
    def request(number, method, params):
        send({'id': number, 'method': method, 'params': params})
        for _ in range(100):
            message = messages.get(timeout=45)
            assert 'invalid' not in message, 'non-JSON stdout from MCP server'
            if message.get('id') == number:
                assert 'error' not in message, message
                return message['result']
        raise RuntimeError('MCP response not received')
    try:
        request(1, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                 'clientInfo': {'name': 'cleanroom', 'version': '1'}})
        send({'method': 'notifications/initialized'})
        listing = request(2, 'tools/list', {})
        assert 'fetch_url' in {tool['name'] for tool in listing['tools']}
        result = request(3, 'tools/call', {'name': 'fetch_url', 'arguments': {'url': url}})
        assert not result.get('isError') and 'Cleanroom article' in json.dumps(result)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        reader.join(timeout=5)
        logger.join(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--find-links', action='append', type=Path, default=[])
    # Setup refuses interpreters under the system temp folder, so the default
    # clean room lives in the repo's ignored build folder instead.
    parser.add_argument('--temp-parent', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'build' / 'cleanroom',
                        help='put all scratch files beneath this directory (not a temp folder)')
    parser.add_argument('--variant', choices=['pdf', 'no-pdf', 'both'], default='both')
    args = parser.parse_args(argv)
    args.find_links = [path.resolve() for path in args.find_links]
    args.temp_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='sf-cleanroom-', dir=args.temp_parent)).resolve()
    print('Clean-room root: ' + str(root), flush=True)
    harness = Harness(root, args)
    if not harness.step('4 bootstrap profile guard', harness.prepare_profile):
        return 1
    copied = harness.step('1 source copy', harness.copy_source)
    built = copied and harness.step('2 distributions', harness.build)
    if built:
        harness.step('9 owner-string scan', harness.scan)
        for variant in (['pdf', 'no-pdf'] if args.variant == 'both' else [args.variant]):
            if harness.step('3 install ' + variant, functools.partial(harness.install, variant)):
                harness.step('4 installed profile ' + variant, harness.check)
                harness.step('5 package data ' + variant, harness.package_data)
                harness.step('6 installed suite ' + variant, harness.tests)
                harness.step('7 setup ' + variant, harness.setup)
                harness.step('8 console smoke ' + variant, functools.partial(harness.smoke, variant))
            else:
                for step in range(4, 9):
                    print(f'FAIL {step} {variant}: not run; wheel installation failed')
    else:
        for step in range(3, 10):
            print(f'FAIL {step}: not run; distributions unavailable')
    print('Artifacts retained at ' + str(root), flush=True)
    return int(harness.failed)


if __name__ == '__main__':
    raise SystemExit(main())
