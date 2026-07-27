# ClaudeHooks

Python **regex guardrails** for Claude Code that protect the host against
**supply-chain attacks**, **destructive commands**, **host-hacking attempts**,
and **prompt injection** — by inspecting content at the hook boundary and
returning `allow` / `ask` / `deny` (or stripping the payload) based on
documented attack patterns.

It ships **two complementary layers**:

1. **Action layer** — a `PreToolUse` hook that gates dangerous `Bash` commands.
2. **Content layer** — a prompt-injection hook (`UserPromptSubmit` + `PostToolUse`)
   that detects and strips injection payloads in the user's prompt and in
   *tool output* (indirect injection).

## Layout

| Path | Purpose |
|------|---------|
| `hooks/guardrails.py` | Command detection engine — pure regex rules + `scan()`. |
| `hooks/pretooluse_guard.py` | `PreToolUse` hook entrypoint (gates Bash commands). |
| `hooks/prompt_injection.py` | Prompt-injection detection + `sanitize()` (strips invisible carriers). |
| `hooks/prompt_injection_guard.py` | `UserPromptSubmit` / `PostToolUse` hook entrypoint. |
| `tests/test_guardrails.py` | Command payloads + false-positive guard. |
| `tests/test_prompt_injection.py` | Injection payloads (ASCII smuggling, base64 canary, homoglyphs) + false-positive guard. |
| `docs/RESEARCH.md` | Papers, MITRE ATT&CK / OWASP LLM mapping, and incidents behind each rule. |

## What it catches

- **Supply chain** — `curl … | bash`, `bash <(curl …)`, `eval "$(curl …)"`,
  installs from URLs/untrusted indexes, disabled TLS verification. *(T1195, T1105)*
- **Destructive** — `rm -rf /`, `--no-preserve-root`, `dd`/`mkfs` on block
  devices, fork bombs.
- **Host hacking** — reverse shells (`/dev/tcp`, `nc -e`, `socat EXEC`),
  persistence (cron, `authorized_keys`, systemd), privilege escalation (sudoers,
  setuid), credential theft (`~/.ssh/id_*`, `/etc/shadow`, env exfil),
  anti-forensics, firewall flushing. *(T1059, T1071, T1548, T1552, T1562, T1070)*

- **Prompt injection** *(OWASP LLM01/LLM02)* — invisible Unicode (zero-width,
  bidi, **Tag-block ASCII smuggling**), homoglyph/mixed-script, base64/hex
  payloads that decode to injection phrases, "ignore previous instructions"
  and role-override phrases, secret-exfiltration instructions, and HTML/CSS
  hidden content — scanned in both the user prompt and *tool output*
  (indirect injection). Based on
  ["Prompt Injection, Deconstructed"](https://securityhorror.blogspot.com/2026/07/prompt-injection-deconstructed_01586936738.html).

See [`docs/RESEARCH.md`](docs/RESEARCH.md) for the full threat model and citations.

## Install

Add to `.claude/settings.json` (use absolute paths):

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
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command",
            "command": "python3 /abs/path/to/ClaudeHooks/hooks/prompt_injection_guard.py" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|Read|Grep|mcp__github__.*",
        "hooks": [
          { "type": "command",
            "command": "python3 /abs/path/to/ClaudeHooks/hooks/prompt_injection_guard.py" }
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
