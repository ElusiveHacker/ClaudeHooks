# Research & Threat Model

This document records the papers, frameworks, and real-world incidents that each
guardrail rule in [`hooks/guardrails.py`](../hooks/guardrails.py) is derived from.
The guardrails are a **defence-in-depth tripwire** for a Claude Code
`PreToolUse` hook — they inspect shell commands before execution and
`deny`/`ask`/`allow` based on documented attack shapes.

> **Scope & honesty.** Static regex is not a sandbox. Obfuscation (variable
> indirection, string splitting, alternate encodings) can defeat any pattern.
> These rules target the *common, documented* payload forms with a low
> false-positive rate and fail safe (ask/deny on match). Pair them with
> least-privilege, network-egress control, and immutable infrastructure.

## 1. Supply-chain attacks

**Academic**
- Ohm, Plate, Sykosch, Meier — *Backstabber's Knife Collection: A Review of
  Open Source Software Supply Chain Attacks*, DIMVA 2020. Empirical review of
  174 malicious npm/PyPI/RubyGems packages; the dominant install-time behaviours
  are **remote payload download + execution** and **install-script abuse**
  (`preinstall`/`postinstall`). → rules `SUPPLYCHAIN_CURL_PIPE_SHELL`,
  `SUPPLYCHAIN_PROCESS_SUBSTITUTION`, `PKG_NPM_UNSAFE`, `PKG_PIP_REMOTE_SOURCE`.
- Duan, Alrawi, Kasturi, Elder, Saltaformaggio, Lee — *Towards Measuring Supply
  Chain Attacks on Package Managers for Interpreted Languages*, NDSS 2021.
  Typosquatting, dependency confusion, network-exfil.
- Zimmermann, Staicu, Tenny, Pradel — *Small World with High Risks: A Study of
  Security Threats in the npm Ecosystem*, USENIX Security 2019.
- Ken Thompson — *Reflections on Trusting Trust*, CACM 1984. The foundational
  argument for validating what you execute.

**Frameworks / standards**
- MITRE ATT&CK **T1195** Supply Chain Compromise, **T1105** Ingress Tool Transfer.
- NIST **SP 800-161r1** Cybersecurity Supply Chain Risk Management.
- OpenSSF **SLSA** (Supply-chain Levels for Software Artifacts).
- OWASP **Top 10 CI/CD Security Risks**.

**Real incidents encoded as rules**
- **Codecov Bash Uploader** (2021) — the `curl … | bash` uploader was trojanised
  to exfiltrate CI secrets. → `SUPPLYCHAIN_CURL_PIPE_SHELL`.
- **event-stream** (npm, 2018), **ua-parser-js** hijack (2021) — malicious
  install scripts. → `PKG_NPM_UNSAFE`.
- **PyPI typosquats** (`colourama`, etc.) and **dependency confusion**
  (Birsan, 2021). → `PKG_PIP_REMOTE_SOURCE`.
- **xz-utils backdoor / CVE-2024-3094** (2024) — malicious build-script
  injection into the release tarball.
- **SolarWinds SUNBURST** (2020) — build-pipeline compromise (motivating T1195).

## 2. Destructive commands

- GNU coreutils `--preserve-root` safeguard exists specifically because of
  `rm -rf /`. → `DESTRUCTIVE_RM_ROOT`, `DESTRUCTIVE_NO_PRESERVE_ROOT`.
- Disk clobbering via `dd`/`mkfs`/`shred`/`wipefs` on `/dev/sd*|nvme*` —
  standard IR/sysadmin canon. → `DESTRUCTIVE_DISK_OVERWRITE`,
  `DESTRUCTIVE_MKFS_WIPE`.
- Classic shell **fork bomb** `:(){ :|:& };:` (resource exhaustion, a local DoS).
  → `DESTRUCTIVE_FORK_BOMB`.

## 3. Host-hacking / post-exploitation — mapped to MITRE ATT&CK

Payload shapes are drawn from the **PayloadsAllTheThings** and **GTFOBins**
public catalogues (both defensive references).

| Technique | ATT&CK | Rule(s) |
|---|---|---|
| Reverse/bind shells (`/dev/tcp`, `nc -e`, `socat EXEC`, python/perl/php one-liners) | T1059, T1071 | `C2_DEV_TCP_REVERSE_SHELL`, `C2_NETCAT_EXEC`, `C2_SOCAT_EXEC`, `C2_SCRIPTING_REVERSE_SHELL` |
| Persistence (cron, `authorized_keys`, `.bashrc`, systemd, `rc.local`) | T1053, T1098, T1543, T1546 | `PERSIST_CRONTAB`, `PERSIST_AUTHORIZED_KEYS`, `PERSIST_SHELL_RC`, `PERSIST_SYSTEMD_RC` |
| Privilege escalation (`/etc/sudoers` NOPASSWD, setuid `chmod u+s`/`4755`) | T1548 | `PRIVESC_SUDOERS`, `PRIVESC_SETUID`, `PRIVESC_ADD_PRIVILEGED_USER` |
| Credential access (`.ssh/id_*`, `/etc/shadow`, `.aws/credentials`, env exfil) | T1552, T1041 | `CRED_SSH_PRIVATE_KEY`, `CRED_SENSITIVE_FILES`, `CRED_ENV_EXFIL` |
| Anti-forensics (`history -c`, `unset HISTFILE`) | T1070.003 | `ANTIFORENSIC_HISTORY` |
| Impair defences (`iptables -F`, `setenforce 0`, disabled TLS) | T1562 | `DEFENSE_FIREWALL_FLUSH`, `DEFENSE_TLS_DISABLED` |
| Obfuscated execution (`base64 -d | sh`, `xxd -r | sh`) | T1027 | `OBFUSCATED_BASE64_EXEC`, `OBFUSCATED_HEX_EXEC` |

## Severity → decision mapping

| Severity | Decision | Meaning |
|---|---|---|
| CRITICAL | `deny` | Unambiguously catastrophic (disk wipe, reverse shell, sudoers). |
| HIGH | `deny` | Very likely malicious/destructive. |
| MEDIUM | `ask` | Suspicious; defer to the human. |
| LOW | `allow` | Informational; surfaced but permitted. |

## 4. Prompt injection (content layer)

Source: **"Prompt Injection, Deconstructed"** —
<https://securityhorror.blogspot.com/2026/07/prompt-injection-deconstructed_01586936738.html>

The article's central thesis: in an LLM there is **no privilege boundary between
instructions and data** ("content is code"). Input-layer filtering is therefore a
*speed bump* — an attacker adds one more encoding layer or invisible code point
and walks past any static matcher. The durable controls are architectural. This
maps onto the two hooks in this repo:

- **Action layer (durable)** — the `PreToolUse` guard in `guardrails.py` already
  gates dangerous *actions* (curl|bash, postinstall abuse, exfil commands),
  which is exactly the "gate the action, not the string" control the article
  recommends.
- **Content layer (tripwire + sanitizer)** — `prompt_injection.py` implements the
  article's detection taxonomy and, crucially, `sanitize()` which *removes* the
  invisible smuggling channels outright (a real win, not just an alert).

### Techniques encoded as rules

| Article technique | Carrier | Rule | Decision |
|---|---|---|---|
| Invisible Unicode | zero-width `U+200B–200D/2060/FEFF`, bidi `U+202A–202E/2066–2069`, **Tag block `U+E0000–E007F` (ASCII smuggling)** | `PI_HIDDEN_UNICODE` | block |
| Single/nested encoding | base64/hex/rot13 that **decodes to** an injection phrase | `PI_ENCODED_PAYLOAD` | block |
| Direct injection / override | "ignore previous instructions", "reveal system prompt", the article's `INJECTED` canary | `PI_INJECTION_PHRASE` | block |
| Exfiltration (kill-chain) | "send/email/POST secrets to …" | `PI_EXFIL_INSTRUCTION` | block |
| Role redefinition | "you are now…", "developer mode", fake `System:` turn | `PI_ROLE_OVERRIDE` | warn |
| Homoglyph / mixed-script | Cyrillic/Greek lookalikes inside Latin words (`U+0430` vs `U+0061`) | `PI_HOMOGLYPH` | warn |
| Rendering-context hiding | `display:none`, `font-size:0`, `visibility:hidden`, off-screen | `PI_HTML_HIDDEN` | warn |
| Staged/nested assembly | "decode … then run / reassemble the fragments" | `PI_STAGED_DECODE` | warn |

All map to **OWASP LLM01** (Prompt Injection); exfiltration also touches **LLM02**.

### Faithful implementation details from the article

- **`sanitize()`** applies `unicodedata.normalize("NFKC", …)` *and* explicit
  enumeration+deletion of hidden code points — the article's key finding is that
  NFKC **alone does not strip** zero-width / Tag characters.
- **Length-delta signal:** `hidden_char_count()` flags content whose invisible
  character count is non-zero (article: `len(raw) - len(rendered_visible)`).
- **Tag-block round-trip:** `decode_tags()` inverts `chr(0xE0000 + ord(c))` to
  recover and report the smuggled shadow-ASCII.
- **Indirect injection is the primary agent threat**, so the hook scans
  `PostToolUse` output (poisoned issues, fetched pages, PR bodies), not only the
  user's prompt.

### Related prior work cited by the article
- Riley Goodside — ChatGPT ASCII-smuggling demonstration.
- Johann Rehberger — "ASCII Smuggler" tool; Microsoft Copilot Tag-block finding.
- Boucher & Anderson — *Trojan Source: Invisible Vulnerabilities* (2021), the
  bidi/homoglyph precedent.
- The **"lethal trifecta"** framing (private-data access + untrusted content +
  outbound channel) as the precondition for the agent kill-chain.

## Test corpus

Every rule is exercised by a documented payload:
- Command safety — [`tests/test_guardrails.py`](../tests/test_guardrails.py)
  (`MALICIOUS_PAYLOADS`) plus a `BENIGN_COMMANDS` false-positive guard.
- Prompt injection — [`tests/test_prompt_injection.py`](../tests/test_prompt_injection.py),
  including the article's `INJECTED` canary, an `to_tags()` ASCII-smuggling
  encoder, base64/nested-base64 payloads, and Cyrillic homoglyphs, plus a
  `BENIGN` false-positive guard.

The samples are **detection fixtures**, not functional weapons.
