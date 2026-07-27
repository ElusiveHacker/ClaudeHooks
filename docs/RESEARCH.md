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

## Test corpus

Every rule is exercised by a documented payload in
[`tests/test_guardrails.py`](../tests/test_guardrails.py) (`MALICIOUS_PAYLOADS`),
and a `BENIGN_COMMANDS` set guards against false positives on everyday developer
commands. The samples are **detection fixtures**, not functional weapons.
