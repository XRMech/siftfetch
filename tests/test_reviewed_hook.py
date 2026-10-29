import io
import json
import socket
import sys

import pytest

from siftfetch import egress_policy as ep, hook


@pytest.fixture
def invoke(tmp_path, monkeypatch, capsys):
    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "identifiers.json").write_text(json.dumps({"values": [
        {"label": "email", "kind": "email", "value": "synthetic@mail.test", "class": "exact"},
        {"label": "town", "kind": "text", "value": "Springfield", "class": "soft"}
    ]}), encoding="utf-8")
    # These regressions isolate pre-existing path/value guards; B8 routing has
    # its own integration and precedence tests in test_shell_fetch.py.
    (policy / "config.json").write_text('{"guard_lock": true, "shell_fetch": "off"}', encoding="utf-8")
    monkeypatch.setenv("SIFTFETCH_HOME", str(policy))
    monkeypatch.setenv("SIFTFETCH_DATA", str(tmp_path / "data"))
    monkeypatch.setattr(ep, "_cached", None)
    monkeypatch.setattr(sys, "argv", ["hook"])
    monkeypatch.delenv("AGENT_HEADLESS", raising=False)

    def call(tool, cwd=None, unattended=False, **tool_input):
        payload = {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd or tmp_path)}
        if unattended:
            payload["agent_id"] = "test-agent"
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
        assert hook.main() == 0
        output = capsys.readouterr().out
        return json.loads(output)["hookSpecificOutput"] if output else None
    call.policy = policy
    return call


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "NotebookEdit", "PowerShell"])
@pytest.mark.parametrize("prefix", ["//localhost/C$", "//127.0.0.1/C$", "//[::1]/C$",
                                    "//./C$", "//?/UNC/localhost/C$", "//?/C:", "//./C:",
                                    "//" + socket.gethostname() + "/C$",
                                    "//" + socket.getfqdn() + "/C$"])
def test_alternate_paths(invoke, tool, prefix):
    path = prefix + "/work/.claude/settings.json"
    for spelling in (path, path.replace("/", "\\")):
        args = {"command": f"Set-Content '{spelling}' x"} if tool == "PowerShell" else {
            "notebook_path" if tool == "NotebookEdit" else "file_path": spelling}
        assert invoke(tool, **args)["permissionDecision"] == "deny"
    assert invoke(tool, **({"command": "ls .*"} if tool == "PowerShell" else
                           {"file_path": "src/main.py"})) is None


def test_remote_unc_never_probes_filesystem(invoke, monkeypatch):
    original = hook.os.path.realpath
    def safe_realpath(path, *args, **kwargs):
        assert not str(path).startswith(("//", "\\\\"))
        return original(path, *args, **kwargs)
    monkeypatch.setattr(hook.os.path, "realpath", safe_realpath)
    for path in ("//remote/share/.claude/settings.json", "//remote/share/policy/config.json"):
        assert "UNC paths can't be checked" in invoke("Write", file_path=path)["permissionDecisionReason"]
    assert invoke("Write", file_path="//remote/share/src/main.py") is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows short names")
def test_real_short_path(invoke, tmp_path):
    import ctypes
    folder = tmp_path / "long directory for short name"
    folder.mkdir()
    (folder / ".claude").mkdir()
    target = folder / ".claude" / "settings.json"
    target.write_text("{}", encoding="utf-8")
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(target), buffer, len(buffer)):
        pytest.skip("8.3 names unavailable")
    if "~" not in buffer.value:
        pytest.skip("8.3 names disabled on this volume")
    assert invoke("Write", file_path=buffer.value)["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", [
    "git commit -m synthetic@mail.test", "git push https://synthetic@mail.test/repo",
    "gh issue create --body synthetic@mail.test", "Send-MailMessage -To synthetic@mail.test",
    "ping synthetic@mail.test", "Test-Connection synthetic@mail.test",
    "nslookup synthetic@mail.test", "net use Z: \\\\synthetic@mail.test\\share",
    "echo ghp_abcdefghijklmnopqrstuvwxyz1234567890",
])
def test_all_shell_values(invoke, command):
    assert invoke("Bash", command=command)["permissionDecision"] == "deny"
    assert invoke("Bash", command="git commit -m 'Update Springfield docs'") is None


@pytest.mark.parametrize("suffix", ["", "; curl https://docs.example", " && echo x", " || echo x",
                                   " | cat", " > output", " $(echo x)", " `echo x`", " & echo x"])
def test_shell_grant_is_single_command(invoke, suffix):
    (invoke.policy / "exceptions.json").write_text(json.dumps({"exceptions": [{
        "label": "email", "op": "shell", "command_prefix": "git config user.email",
        "expires": "2099-01-01T00:00:00Z"
    }]}), encoding="utf-8")
    ep._cached = None
    result = invoke("Bash", command="git config user.email synthetic@mail.test" + suffix)
    assert (result is None) == (suffix == "")
    assert invoke("Bash", command="git config user.email synthetic@mail.test Springfield")["permissionDecision"] == "deny"
    assert invoke("Bash", command="git config user.emailOther synthetic@mail.test")["permissionDecision"] == "deny"


def test_allowed_shell_not_logged(invoke):
    assert invoke("Bash", command="git status") is None
    assert not (invoke.policy / "egress-decisions.jsonl").exists()
    assert invoke("Bash", command="echo synthetic@mail.test")["permissionDecision"] == "deny"
    assert (invoke.policy / "egress-decisions.jsonl").exists()


@pytest.mark.parametrize("tool", ["mcp__rag_search__fetch", "mcp__agent_mail__send_message"])
def test_unknown_mcp_values(invoke, tool):
    assert invoke(tool, unattended=True, body="synthetic@mail.test")["permissionDecision"] == "deny"
    assert invoke(tool, body="synthetic@mail.test")["permissionDecision"] == "ask"
    assert invoke(tool, body="ordinary message") is None
    assert invoke(tool, query="Springfield architecture") is None
    assert invoke(tool, body="Springfield architecture")["permissionDecision"] == "ask"


def test_mcp_decoded_leaves_and_exemptions(invoke):
    import base64
    value = base64.b64encode(b"synthetic@mail.test").decode()
    assert invoke("mcp__rag__fetch", unattended=True, args=[{"query": value}])["permissionDecision"] == "deny"
    for tool in hook._GUARDED_MCP_TOOLS:
        assert invoke(tool, body="synthetic@mail.test") is None
    (invoke.policy / "config.json").write_text(json.dumps({"guard_lock": True,
        "mcp_local_tools": ["mcp__local__read", "mcp__local_server__*"]}), encoding="utf-8")
    for tool in ("mcp__local__read", "mcp__local_server__read"):
        assert invoke(tool, body="synthetic@mail.test") is None
    assert invoke("mcp__local__write", body="synthetic@mail.test")["permissionDecision"] == "ask"


def test_clean_mcp_not_logged(invoke):
    assert invoke("mcp__remote__search", query="ordinary documentation") is None
    assert not (invoke.policy / "egress-decisions.jsonl").exists()


WRITE_CASES = [
    "echo x >&{file}", "echo x 2>&{file}",
    "echo x 2>{file}", "echo x >|{file}", "echo x &>{file}", "echo x *>{file}",
    "echo x 2>>{file}", "curl https://docs.example -o {file}",
    "wget https://docs.example --output {file}", "curl https://docs.example --output-dir {folder}",
    "cd {folder}; curl -O https://docs.example/settings.json",
    "Invoke-WebRequest https://docs.example -OutFile {file}",
    "irm https://docs.example -OutFile {file}",
    "Start-BitsTransfer https://docs.example -Destination {file}",
    "tar -xf archive.tar -C {folder}", "tar --extract --directory={folder} -f archive.tar",
    "unzip archive.zip -d {folder}", "Expand-Archive archive.zip -DestinationPath {folder}",
    "7z x archive.zip -o{folder}", "certutil -decode input.txt {file}",
    "certutil -decodehex input.txt {file}", "certutil -urlcache -split -f https://docs.example {file}",
    "Export-Csv -Path {file}", "Export-Clixml {file}", "git -C {folder} pull",
    "git -C {folder} merge branch", "git clone https://docs.example/repo {folder}",
    "[IO.File]::WriteAllText('{file}', 'x')", "[System.IO.File]::AppendAllText('{file}', 'x')",
    "[IO.File]::Copy('source', '{file}')", "[IO.File]::Move('source', '{file}')",
    "[IO.File]::Replace('source', '{file}', 'backup')", "[IO.File]::Delete('{file}')",
    "Copy-Item -Destination {file} -LiteralPath source", "Move-Item -Destination {file} -Path source",
    "robocopy source {folder} /E", "xcopy source {folder} /E", "cp -r source {folder}",
    "Copy-Item source {folder} -Recurse", "cmd /c \"echo x > {file}\"",
    "bash -c 'echo x > {file}'", "pwsh -Command \"Set-Content {file} x\"",
]


@pytest.mark.parametrize("template", WRITE_CASES)
def test_guard_write_routes(invoke, tmp_path, template):
    folder = tmp_path / ".claude"
    folder.mkdir()
    target = folder / "settings.json"
    target.write_text("{}", encoding="utf-8")
    command = template.format(file=target.as_posix(), folder=folder.as_posix())
    assert invoke("PowerShell", command=command)["permissionDecision"] == "deny", command
    (invoke.policy / "config.json").write_text('{"guard_lock": false, "shell_fetch": "off"}', encoding="utf-8")
    ep._cached = None
    assert invoke("PowerShell", command=command) is None, command


@pytest.mark.parametrize("command", ["cat .claude/settings.json", "grep -o pattern src/main.py",
                                    "tar -tf archive.tar -C .claude", "curl -O https://docs.example/a",
                                    "echo x 2>&1", "echo 'text > .claude/settings.json'",
                                    "Copy-Item -Path .claude/settings.json -Destination backup.json"])
def test_write_controls(invoke, command):
    assert invoke("PowerShell", command=command) is None


def test_quoted_redirect_and_literal_variable(invoke, tmp_path):
    path = (tmp_path / ".claude" / "settings.json").as_posix()
    assert invoke("Bash", command=f"echo 'example > {path}'") is None
    assert invoke("PowerShell", command=f"$file='{path}'; echo x >$file")["permissionDecision"] == "deny"
    assert invoke("Bash", command="echo '$(cat .env)'") is None


@pytest.mark.parametrize("command", [
    'echo "`cat .env`"', "Write-Output (Get-Content .env)", "cat .env.dist",
    'cmd /c "cat .env"', 'cmd /k "type .env"', "bash -c 'cat .env'",
    "sh -c 'cat .env'", "zsh -c 'cat .env'", "wsl cat .env", "wsl -e sh -c 'cat .env'",
    "pwsh -Command 'Get-Content .env'", "powershell -c 'Get-Content .env'",
    "iex 'Get-Content .env'", "Invoke-Expression 'cat .env'",
    "Start-Process pwsh -ArgumentList '-Command', 'Get-Content .env'",
])
@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_nested_reads(invoke, command, mode):
    (invoke.policy / "config.json").write_text(json.dumps({"secret_file_mode": mode}), encoding="utf-8")
    ep._cached = None
    assert invoke("PowerShell", command=command)["permissionDecision"] == "deny"
    assert invoke("PowerShell", command=command.replace(".env", "notes.txt")) is None


@pytest.mark.parametrize("command", [
    "echo x | cat .env", "(cat .env)", "@(Get-Content .env)", "xargs -n 1 cat .env",
    "[IO.File]::OpenText('.env')", "New-Object IO.StreamReader('.env')", "File.OpenRead('.env')",
    "Get-Item .env | Get-Content", "Copy-Item -Destination backup -Path .env",
    "cp -t backup .env", "cp --target-directory=backup .env", "git diff -- .env", "git show HEAD:.env",
    "Import-Csv .env", "ConvertFrom-Json -Path .env", "jq . .env", "yq . .env", "paste .env",
    "join .env source", "comm .env source", "cmp .env source", "certutil -encode .env out",
])
def test_strict_read_routes(invoke, command):
    assert invoke("PowerShell", command=command)["permissionDecision"] == "deny"
    assert invoke("PowerShell", command=command.replace(".env", "notes.txt")) is None


def test_encoded_shell_reads(invoke):
    import base64
    value = base64.b64encode("Get-Content .env".encode("utf-16le")).decode()
    assert invoke("PowerShell", command="pwsh -EncodedCommand " + value)["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", ["grep -r foo .", "grep -R foo .", "rg --hidden foo .",
                                    "rg -uu foo .", "rg --no-ignore foo .", "findstr /s foo *",
                                    "Get-ChildItem . -Recurse | Select-String foo",
                                    "Get-ChildItem . -Recurse | Get-Content"])
def test_recursive_reads(invoke, tmp_path, command):
    # Mixed case: on a case-sensitive file system the walk must open the real name.
    work = tmp_path / "Work"
    work.mkdir()
    (work / ".env").touch()
    result = invoke("PowerShell", cwd=work, command=command)
    assert result["permissionDecision"] == "deny"
    assert "Exclude" in result["permissionDecisionReason"]
    (invoke.policy / "config.json").write_text('{"secret_file_mode": "standard"}', encoding="utf-8")
    ep._cached = None
    assert invoke("PowerShell", cwd=work, command=command) is None


@pytest.mark.parametrize("command", ["grep -rn TODO src --include=*.py", "rg -uu -t py foo .",
                                    "rg --hidden -g '*.py' foo .", "findstr /s foo *.py",
                                    "grep -r foo . --exclude=.env*", "rg --hidden -g '!.env*' foo .",
                                    "rg foo", "cat .env.example"])
def test_recursive_controls(invoke, tmp_path, command):
    work = tmp_path / "work"
    work.mkdir()
    (work / ".env").touch()
    assert invoke("PowerShell", cwd=work, command=command) is None


def test_recursive_policy_and_bound(invoke, tmp_path, monkeypatch):
    assert invoke("Bash", cwd=tmp_path, command="grep -r foo .")["permissionDecision"] == "deny"
    work = tmp_path / "work"
    work.mkdir()
    for i in range(3):
        (work / f"file{i}.txt").touch()
    monkeypatch.setattr(hook, "_WALK_LIMIT", 1)
    assert invoke("Bash", cwd=work, command="grep -r foo .") is None
    assert "recursive_walk_limit" in (invoke.policy / "egress-decisions.jsonl").read_text()


@pytest.mark.parametrize("template", ["rm -r {parent}", "mv {parent} elsewhere", "ren {parent} renamed",
                                     "Move-Item {parent} elsewhere", "Rename-Item {parent} renamed",
                                     "robocopy source {parent} /MIR", "robocopy source {parent} /PURGE",
                                     "robocopy {parent} elsewhere /MOVE"])
def test_policy_ancestors(invoke, tmp_path, template):
    assert invoke("PowerShell", command=template.format(parent=tmp_path.as_posix()))["permissionDecision"] == "deny"
    assert invoke("PowerShell", command=template.format(parent=(tmp_path / "sibling").as_posix())) is None


def test_missing_policy_stays_unknown(invoke, tmp_path, monkeypatch):
    missing = tmp_path / "not-created-policy"
    monkeypatch.setenv("SIFTFETCH_HOME", str(missing))
    ep._cached = None
    for _ in range(2):
        decision = invoke("Write", file_path=".claude/settings.json")
        assert decision["permissionDecision"] == "deny"
        assert "guard_lock_unknown" in decision["permissionDecisionReason"]
        assert str(missing) in decision["permissionDecisionReason"]
        assert invoke("WebSearch", query="ordinary documentation")["permissionDecision"] == "deny"
        assert not missing.exists()
    assert invoke("Write", file_path="src/main.py") is None


def test_project_mcp_lock(invoke):
    assert invoke("Write", file_path=".mcp.json")["permissionDecision"] == "deny"
    assert invoke("Bash", command="echo '{}' > .mcp.json")["permissionDecision"] == "deny"
    assert invoke("Bash", command="cat .mcp.json") is None
    (invoke.policy / "config.json").write_text('{"guard_lock": false}', encoding="utf-8")
    assert invoke("Write", file_path=".mcp.json") is None

@pytest.mark.parametrize('word', ['~/".sift"fetch/identifiers.json', r'~/.sift\fetch/identifiers.json', '~/.sift{fetch,x}/identifiers.json', "~/'.sift'fetch/identifiers.json"])
def test_joined_policy(invoke, word):
    assert invoke('Bash', command='cat ' + word)['permissionDecision'] == 'deny'
    assert invoke('Bash', command='cat docs/"guide".txt') is None


@pytest.mark.parametrize('word', ['.e""nv', ".e''nv", "'.en'v", r'.en\v', '.{env,x}', '.e`nv'])
def test_joined_env(invoke, word):
    assert invoke('Bash', command='cat ' + word)['permissionDecision'] == 'deny'
    assert invoke('Bash', command='cat ' + word + '.example') is None
    assert invoke('Bash', command='ls ' + word) is None

@pytest.mark.parametrize('flag', ['Path', 'LiteralPath'])
def test_colon_path_parameters(invoke, flag):
    assert invoke('PowerShell', command=f'Get-Content -{flag}:~/.sift*/identifiers.json')['permissionDecision'] == 'deny'
    assert invoke('PowerShell', command=f'Set-Content -{flag}:.claude/settings.json -Value x')['permissionDecision'] == 'deny'
    assert invoke('PowerShell', command=f'Copy-Item -{flag}:notes.txt -Destination:.claude/settings.json')['permissionDecision'] == 'deny'
    assert invoke('PowerShell', command=f'Get-Content -{flag}:notes.txt') is None


def test_colon_output_parameters(invoke):
    assert invoke('PowerShell', command='iwr https://docs.example -OutFile:.claude/settings.json')['permissionDecision'] == 'deny'
    for command in [r'curl -o C:\tmp\x https://docs.example', r'curl -oC:\tmp\x https://docs.example', 'iwr https://docs.example -OutFile:notes.txt']:
        assert invoke('PowerShell', command=command) is None
    assert hook._tokens(r'curl -oC:\tmp\x') == ['curl', r'-oC:\tmp\x']

@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
@pytest.mark.parametrize('flag', ['-e', '-ec'] + ['-encodedcommand'[:i] for i in range(3, 16)])
def test_encoded_aliases(invoke, shell, flag):
    import base64
    for text in ['Get-Content ~/.siftfetch/identifiers.json', 'Get-Content .env']:
        encoded = base64.b64encode(text.encode('utf-16le')).decode()
        assert invoke('PowerShell', command=f'{shell} {flag} {encoded}')['permissionDecision'] == 'deny'
    benign = base64.b64encode('Get-Content notes.txt'.encode('utf-16le')).decode()
    assert invoke('PowerShell', command=f'{shell} {flag} {benign}') is None


@pytest.mark.parametrize('prefix', ['bash -lc', 'sh -ec', 'zsh -xc', 'dash -ce', 'bash -c', 'cmd /s /c', 'cmd /d /c', 'cmd /k'] + ['pwsh ' + '-command'[:i] for i in range(4, 9)] + ['powershell -c'])
def test_nested_flag_spellings(invoke, prefix):
    assert invoke('Bash', command=prefix + ' "cat .env"')['permissionDecision'] == 'deny'
    assert invoke('Bash', command=prefix + ' "cat notes.txt"') is None

@pytest.mark.parametrize('verb', ['cd', 'Set-Location', 'sl', 'pushd', 'chdir'])
def test_short_policy_after_cd(tmp_path, monkeypatch, verb):
    parent = tmp_path / 'homedir'
    parent.mkdir()
    policy = parent / '.siftfetch'
    policy.mkdir()
    monkeypatch.setenv('SIFTFETCH_HOME', str(policy))
    original = hook.os.path.realpath
    alias = (parent / 'SIFTFE~1').as_posix().lower()
    def resolve(path, *args, **kwargs):
        return original(str(path).replace(alias, policy.as_posix().lower()), *args, **kwargs)
    monkeypatch.setattr(hook.os.path, 'realpath', resolve)
    assert hook._names_policy(f'{verb} "{parent.as_posix()}" && {verb} SIFTFE~1 && cat identifiers.json', str(tmp_path))
    assert not hook._names_policy(f'{verb} "{parent.as_posix()}" && {verb} docs && cat notes.txt', str(tmp_path))


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows short names')
def test_real_short_policy_after_cd(tmp_path, monkeypatch):
    import ctypes
    parent = tmp_path / 'homedir'
    parent.mkdir()
    policy = parent / '.siftfetch'
    policy.mkdir()
    monkeypatch.setenv('SIFTFETCH_HOME', str(policy))
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(policy), buffer, len(buffer)) or '~' not in buffer.value:
        pytest.skip('8.3 names unavailable on this volume')
    from pathlib import Path
    short = Path(buffer.value).name
    assert hook._names_policy(f'cd "{parent.as_posix()}" && cd {short} && cat identifiers.json', str(tmp_path))
    assert not hook._names_policy(f'cd "{parent.as_posix()}" && cat notes.txt', str(tmp_path))

@pytest.mark.parametrize('command', ['cmd 0<.env', '[string]$x = gc .env', '$env:X = gc .env', '${x} = gc .env', '[System.String[]]$x = gc .env'])
@pytest.mark.parametrize('mode', ['standard', 'strict'])
def test_assignment_and_numbered_input(command, mode):
    assert hook._reads_env(command, mode)
    assert not hook._reads_env(command.replace('.env', 'notes.txt'), mode)
    assert not hook._reads_env('cmd <<.env', mode)
    assert not hook._reads_env('$env:X = Write-Output .env', mode)

@pytest.mark.parametrize('tool', ['mcp__claude-in-chrome__navigate', 'mcp__Claude_Browser__navigate'])
def test_browser_private_destination_only_exemption(invoke, tool):
    assert invoke(tool, url='http://localhost:3000/') is None
    assert invoke(tool, url='http://localhost:3000/?value=synthetic@mail.test', unattended=True)['permissionDecision'] == 'deny'
    assert invoke(tool, url='http://localhost:3000/', body='synthetic@mail.test', unattended=True)['permissionDecision'] == 'deny'
    assert invoke('mcp__unknown__fetch', url='http://localhost:3000/')['permissionDecisionReason'].find('private_destination') >= 0
    from siftfetch import server
    with pytest.raises(ep.EgressDenied) as error:
        server.fetch_url_sync('http://localhost:3000/')
    assert error.value.decision.reason_code == 'private_destination'

@pytest.mark.parametrize('stage', ['_names_policy', '_locked_target', '_family'])
def test_pre_policy_exception_fails_closed(invoke, monkeypatch, stage):
    original = getattr(hook, stage)
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic pre-policy failure')
    monkeypatch.setattr(hook, stage, fail)
    result = invoke('Bash', command='cat notes.txt')
    assert result['permissionDecision'] == 'deny'
    assert 'guard_error: RuntimeError' in result['permissionDecisionReason']
    assert 'synthetic' not in result['permissionDecisionReason']
    monkeypatch.setattr(hook, stage, original)


def test_unresolvable_cloud_drive_path_is_checked_lexically(invoke, monkeypatch):
    # ShareFile-style drivers raise WinError 1005 from the final-path query.
    # Only S: fails, so pytest's own path handling keeps working mid-test.
    original = hook.os.path.realpath
    def refuse(path, *args, **kwargs):
        if str(path).upper().startswith('S:'):
            raise OSError(1005, 'The volume does not contain a recognized file system')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(hook.os.path, 'realpath', refuse)
    assert invoke('Bash', command=r'ls "S:\Share\FM\FM2s6"') is None
    # The lexical check still guards the policy folder on such a drive.
    assert invoke('Bash', command=f'cat "{invoke.policy}/config.json"')['permissionDecision'] == 'deny'


@pytest.mark.parametrize('command', [
    "grep -n 'Task<.*> ApplyDisplayAdjustmentsAsync' Imaging/ImageManager.cs",
    'grep -n "List<.*>" a.cs', "echo 'x <.env'",
])
def test_quoted_angle_bracket_is_not_a_dotenv_redirect(invoke, command):
    # A generic-type grep pattern used to read as an input redirect from '.*'.
    assert invoke('Bash', command=command) is None


@pytest.mark.parametrize('command', [
    'cat < .env', 'grep x < .*', "bash -c 'cat < .env'", "grep -n 'x' a.cs; cat < .env",
])
def test_real_dotenv_redirects_stay_denied(invoke, command):
    assert 'secret_file' in invoke('Bash', command=command)['permissionDecisionReason']


def test_guard_error_names_os_code_but_not_values_or_paths(invoke, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError(5, 'Access is denied', r'C:\secret\synthetic@mail.test.txt')
    monkeypatch.setattr(hook, '_names_policy', fail)
    reason = invoke('Bash', command='cat notes.txt')['permissionDecisionReason']
    assert 'guard_error: OSError [errno 5] Access is denied' in reason
    assert 'synthetic' not in reason and 'secret' not in reason


def test_malformed_input_names_parse_cause_and_redacts_policy(invoke, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{not json')))
    assert hook.main() == 0
    reason = json.loads(capsys.readouterr().out)['hookSpecificOutput']['permissionDecisionReason']
    assert 'malformed_input' in reason and 'JSONDecodeError' in reason
    assert hook._redact_policy(f'x {invoke.policy} y .siftfetch z').count('<policy folder>') == 2
    assert invoke('Bash', command='cat notes.txt') is None

@pytest.mark.parametrize('host', ['127.0.0.2', '127.255.1.9', '[::1]', 'localhost', 'TEST-PC', '192.168.1.77', '.', '?'])
def test_local_unc_short_policy(invoke, tmp_path, monkeypatch, host):
    monkeypatch.setattr(hook, '_local_unc_hosts', lambda: {'test-pc', '192.168.1.77', 'localhost', '.', '?'})
    original = hook._candidates
    def candidates(token, cwd):
        identity = hook._path_identity(token.replace('\\', '/')).lower()
        if identity.startswith('c:/users/synthetic/siftfe~1'):
            return [hook._policy_home() + '/identifiers.json']
        return original(token, cwd)
    monkeypatch.setattr(hook, '_candidates', candidates)
    path = f'//{host}/C$/Users/synthetic/SIFTFE~1/identifiers.json'
    assert hook._path_identity(path).startswith('C:/')
    assert invoke('PowerShell', command=f'cat "{path}"')['permissionDecision'] == 'deny'
    assert invoke('Write', file_path=path)['permissionDecision'] == 'deny'
    assert invoke('Write', file_path=f'//{host}/C$/src/notes.txt') is None


def test_local_unc_host_discovery(monkeypatch):
    hook._local_unc_hosts.cache_clear()
    monkeypatch.setattr(hook.socket, 'gethostname', lambda: 'TEST-PC')
    monkeypatch.setattr(hook.socket, 'getfqdn', lambda: 'TEST-PC.example')
    monkeypatch.setattr(hook.socket, 'getaddrinfo', lambda *args: [(0, 0, 0, '', ('192.168.1.77', 0))])
    try:
        assert hook._local_unc_host('TeSt-Pc')
        assert hook._local_unc_host('192.168.1.77')
        assert not hook._local_unc_host('192.168.1.78')
    finally:
        hook._local_unc_hosts.cache_clear()


@pytest.mark.parametrize('short', ['SIFTFE~1', 'SIFTFE~12', 'SI1234~1', 'POLICY~1'])
def test_remote_admin_short_policy(invoke, short):
    path = f'//remote/C$/Users/synthetic/{short}/identifiers.json'
    assert invoke('Bash', command=f'cat "{path}"')['permissionDecision'] == 'deny'
    assert invoke('Write', file_path=path)['permissionDecision'] == 'deny'
    assert invoke('Write', file_path='//remote/C$/src/notes.txt') is None

@pytest.mark.parametrize('word', ['.e""nv', ".e''nv", r'.en\v', '.e`nv', '.{env,x}'])
def test_joined_input_targets(word):
    assert hook._reads_env('cmd 0< ' + word, 'standard')
    assert not hook._reads_env('cmd 0< ' + word + '.example', 'standard')
    assert not hook._reads_env('cmd << ' + word, 'standard')


@pytest.mark.parametrize('flag', ['Path', 'LiteralPath'])
def test_colon_cd_before_locked_output(invoke, flag):
    assert invoke('PowerShell', command=f'Set-Location -{flag}:.claude; iwr https://docs.example -OutFile:settings.json')['permissionDecision'] == 'deny'
    assert invoke('PowerShell', command=f'Set-Location -{flag}:output; iwr https://docs.example -OutFile:settings.json') is None
