import pytest
from test_reviewed_hook import invoke


@pytest.mark.parametrize("command", [
    "cat <<'EOF' > brief.txt\nDo not read ~/.siftfetch or SIFTFETCH_HOME.\nEOF\n",
    'cat <<"EOF"\nThe policy lives in ~/.siftfetch.\nEOF\n',
    "cat <<-'EOF'\n\tMention ~/.siftfetch as prose.\n\tEOF\n",
    "echo 'The policy lives in ~/.siftfetch'",
    'printf "%s" "Do not read ~/.siftfetch"',
    "Write-Output 'SIFTFETCH_HOME holds the policy'",
    "grep '.siftfetch' README.md",
    "echo 'Notes | ~/.siftfetch is the policy folder'",
])
def test_literal_prose_allowed(invoke, command):
    assert invoke("Bash", command=command) is None


@pytest.mark.parametrize("command", [
    "cat ~/.siftfetch/config.json", "ls ~/.siftfetch", "cat $SIFTFETCH_HOME/config.json",
    "echo 'notes' > ~/.siftfetch/config.json",
    "cat <<'EOF' > ~/.siftfetch/config.json\nnotes\nEOF\n",
    "cat <<'EOF'\nnotes\nEOF\ncat ~/.siftfetch/config.json",
    "sh <<'EOF'\ncat ~/.siftfetch/config.json\nEOF\n",
    "cat <<'EOF' | sh\ncat ~/.siftfetch/config.json\nEOF\n",
    'echo "$(cat ~/.siftfetch/config.json)"',
    "python -c \"open('~/.siftfetch/config.json').read()\"",
    "echo 'cat ~/.siftfetch/config.json' | sh",
    "Write-Output 'Get-Content ~/.siftfetch/config.json' | Invoke-Expression",
])
def test_real_operands_remain_blocked(invoke, command):
    assert invoke("Bash", command=command)["permissionDecision"] == "deny"


def test_relocated_folder_prose_and_operand(invoke):
    path = invoke.policy.as_posix()
    assert invoke("Bash", command=f"echo 'Policy lives in {path}'") is None
    assert invoke("Bash", command=f"cat '{path}/config.json'")["permissionDecision"] == "deny"
