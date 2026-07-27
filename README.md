# ClaudeHooks

Python **regex guardrails** for Claude Code that inspect shell commands *before*
they run and block dangerous ones — protecting the host against **supply-chain
attacks**, **destructive commands**, and **host-hacking attempts**.

It ships as a `PreToolUse` hook: Claude Code hands each `Bash` command to the
hook, which returns `allow` / `ask` / `deny` based on documented attack patterns.

## Layout

| Path | Purpose |
|------|---------|
| `hooks/guardrails.py` | Detection engine — pure, side-effect-free regex rules + `scan()`. |
| `hooks/pretooluse_guard.py` | Claude Code `PreToolUse` hook entrypoint (stdin JSON → decision). |
| `tests/test_guardrails.py` | Payload-driven tests + false-positive guard. |
| `docs/RESEARCH.md` | Papers, MITRE ATT&CK mapping, and incidents behind each rule. |

## What it catches

- **Supply chain** — `curl … | bash`, `bash <(curl …)`, `eval "$(curl …)"`,
  installs from URLs/untrusted indexes, disabled TLS verification. *(T1195, T1105)*
- **Destructive** — `rm -rf /`, `--no-preserve-root`, `dd`/`mkfs` on block
  devices, fork bombs.
- **Host hacking** — reverse shells (`/dev/tcp`, `nc -e`, `socat EXEC`),
  persistence (cron, `authorized_keys`, systemd), privilege escalation (sudoers,
  setuid), credential theft (`~/.ssh/id_*`, `/etc/shadow`, env exfil),
  anti-forensics, firewall flushing. *(T1059, T1071, T1548, T1552, T1562, T1070)*

See [`docs/RESEARCH.md`](docs/RESEARCH.md) for the full threat model and citations.

## Install

Add to `.claude/settings.json` (use an absolute path):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command",
            "command": "python3 /abs/path/to/ClaudeHooks/hooks/pretooluse_guard.py" }
        ]
      }
    ]
  }
}
```

No third-party dependencies — standard-library Python 3.8+ only.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

Static regex is a **tripwire, not a sandbox**. Obfuscation can defeat any static
pattern; the rules target common, documented payload shapes with a low
false-positive rate and fail safe (`ask`/`deny` on match). Use alongside
least-privilege, egress control, and immutable infrastructure — never as the
only layer.
