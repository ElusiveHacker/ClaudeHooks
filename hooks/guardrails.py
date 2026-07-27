"""
guardrails.py — Regex-based command guardrails for Claude Code hooks.

Purpose
-------
Defence-in-depth inspection of shell commands *before* they are executed,
protecting the host against three broad classes of abuse:

    1. Supply-chain attacks   (remote code execution, malicious install scripts,
                               dependency confusion, disabled TLS verification)
    2. Destructive commands   (rm -rf /, disk overwrites, fork bombs)
    3. Host-hacking attempts   (reverse shells, persistence, credential theft,
                               privilege escalation, anti-forensics)

This module contains ONLY detection logic (a pure function of a string). It has
no side effects and no I/O, which keeps it trivially testable. The Claude Code
hook entrypoint lives in ``pretooluse_guard.py``.

Design notes / honest limitations
----------------------------------
Regex matching is a *tripwire*, not a sandbox. A determined attacker can obfuscate
around any static pattern (variable indirection, string splitting, alternate
encodings, unusual whitespace). These rules are tuned to catch the *common,
documented* payload shapes (see docs/RESEARCH.md) with a low false-positive rate,
and to fail safe by asking the human on medium-confidence matches rather than
silently allowing. Treat this as one layer among many (least-privilege, network
egress control, immutable infra), never the only one.

References
----------
See docs/RESEARCH.md for the papers, frameworks (MITRE ATT&CK, NIST SP 800-161,
SLSA) and real-world incidents each rule is derived from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List


class Severity(IntEnum):
    """Higher value = more dangerous. Ordering matters for aggregation."""

    LOW = 1       # informational; allow but surface
    MEDIUM = 2    # suspicious; ask the human
    HIGH = 3      # very likely malicious/destructive; deny
    CRITICAL = 4  # unambiguously catastrophic; deny


# Map a severity to the Claude Code PreToolUse permission decision.
DECISION_BY_SEVERITY = {
    Severity.LOW: "allow",
    Severity.MEDIUM: "ask",
    Severity.HIGH: "deny",
    Severity.CRITICAL: "deny",
}


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    description: str
    mitre: str = ""            # MITRE ATT&CK technique id(s), where applicable
    remediation: str = ""      # human-readable safer alternative


@dataclass
class Finding:
    """The result of a rule firing against a command."""

    rule: Rule
    match: str

    def as_dict(self) -> dict:
        return {
            "id": self.rule.id,
            "category": self.rule.category,
            "severity": self.rule.severity.name,
            "description": self.rule.description,
            "mitre": self.rule.mitre,
            "remediation": self.rule.remediation,
            "matched_text": self.match,
        }


# Compile with IGNORECASE by default; individual rules can override.
def _rx(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Reusable sub-patterns
# ---------------------------------------------------------------------------
# A shell interpreter that would execute piped-in text.
_SHELL = r"(?:ba|z|da|k)?sh\b|python[0-9.]*\b|perl\b|ruby\b|node\b|php\b"
# `rm` recursive+force flag clusters in any order / long-option form.
_RF_FLAGS = (
    r"(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r"
    r"|--recursive\s+--force|--force\s+--recursive"
    r"|-r\s+-f|-f\s+-r|-[rf])"
)
# Paths whose recursive removal is catastrophic.
_ROOT_TARGETS = (
    r"(?:/\s*$|/\*|~\s*$|~/\*|\$HOME\b|--no-preserve-root"
    r"|/(?:bin|boot|etc|lib|lib64|root|sbin|usr|var|home|dev|proc|sys)\b)"
)


# ---------------------------------------------------------------------------
# Rule set
# ---------------------------------------------------------------------------
RULES: List[Rule] = [
    # ---- Destructive filesystem --------------------------------------------
    Rule(
        id="DESTRUCTIVE_RM_ROOT",
        category="destructive",
        severity=Severity.CRITICAL,
        pattern=_rx(rf"\brm\s+(?:{_RF_FLAGS}\s+)+[^|&;\n]*{_ROOT_TARGETS}"),
        description="Recursive/forced deletion targeting a root, home, or system path.",
        remediation="Delete a specific, non-system path; avoid -rf on / ~ or /*.",
    ),
    Rule(
        id="DESTRUCTIVE_NO_PRESERVE_ROOT",
        category="destructive",
        severity=Severity.CRITICAL,
        pattern=_rx(r"--no-preserve-root"),
        description="Explicitly disables the coreutils safeguard against deleting /.",
        remediation="Never use --no-preserve-root.",
    ),
    Rule(
        id="DESTRUCTIVE_DISK_OVERWRITE",
        category="destructive",
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"\bdd\b[^|\n]*\bof=\s*/dev/(?:sd|nvme|hd|mmcblk|xvd|vd)"
            r"|>\s*/dev/(?:sd|nvme|hd)[a-z0-9]*\b"
        ),
        description="Raw write to a block device (destroys the disk / partition table).",
        remediation="Write to a regular file, not a /dev block device.",
    ),
    Rule(
        id="DESTRUCTIVE_MKFS_WIPE",
        category="destructive",
        severity=Severity.CRITICAL,
        pattern=_rx(r"\b(?:mkfs(?:\.\w+)?|wipefs|shred)\b[^|\n]*\s/dev/"),
        description="Formatting / wiping a block device.",
        remediation="Confirm the target device out-of-band before formatting.",
    ),
    Rule(
        id="DESTRUCTIVE_FORK_BOMB",
        category="destructive",
        severity=Severity.CRITICAL,
        pattern=_rx(r"[\w:]*\s*\(\s*\)\s*\{\s*[^}]*\|\s*[\w:]+\s*&\s*\}\s*;\s*[\w:]+"),
        description="Shell fork bomb (exhausts process table).",
        remediation="Do not run. Set ulimit -u to cap processes if testing.",
    ),
    Rule(
        id="DESTRUCTIVE_CHMOD_RECURSIVE_ROOT",
        category="destructive",
        severity=Severity.HIGH,
        pattern=_rx(r"\bchmod\s+-R\s+[0-7]{3,4}\s+(?:/\s*$|/\*|/(?:etc|usr|bin|var)\b)"),
        description="Recursive permission change across system directories.",
        remediation="Scope chmod to the specific files you own.",
    ),

    # ---- Supply chain: remote code execution -------------------------------
    Rule(
        id="SUPPLYCHAIN_CURL_PIPE_SHELL",
        category="supply_chain",
        severity=Severity.HIGH,
        pattern=_rx(rf"\b(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:{_SHELL})"),
        mitre="T1105/T1195",
        description="Downloading a script and piping it straight into an interpreter.",
        remediation="Download, read/verify (checksum or signature), then run.",
    ),
    Rule(
        id="SUPPLYCHAIN_PROCESS_SUBSTITUTION",
        category="supply_chain",
        severity=Severity.HIGH,
        pattern=_rx(rf"(?:{_SHELL}|source|eval)\s*(?:-\w+\s*)*<\(\s*(?:curl|wget|fetch)"),
        mitre="T1105",
        description="Executing a remote download via process substitution bash <(curl ...).",
        remediation="Fetch to a file and inspect before executing.",
    ),
    Rule(
        id="SUPPLYCHAIN_EVAL_REMOTE",
        category="supply_chain",
        severity=Severity.HIGH,
        pattern=_rx(r"\beval\s+[\"']?\$\(\s*(?:curl|wget|fetch)"),
        mitre="T1059/T1105",
        description="eval of remotely fetched content.",
        remediation="Never eval network responses.",
    ),
    Rule(
        id="SUPPLYCHAIN_REMOTE_TO_IP",
        category="supply_chain",
        severity=Severity.MEDIUM,
        pattern=_rx(r"\b(?:curl|wget|fetch)\b[^|\n]*\bhttps?://(?:\d{1,3}\.){3}\d{1,3}"),
        mitre="T1105",
        description="Downloading from a bare IP address (common in droppers).",
        remediation="Prefer a named, TLS-verified, reputable host.",
    ),

    # ---- Obfuscated execution ----------------------------------------------
    Rule(
        id="OBFUSCATED_BASE64_EXEC",
        category="obfuscation",
        severity=Severity.HIGH,
        pattern=_rx(
            rf"base64\s+(?:-d|-D|--decode)\b[^|\n]*\|\s*(?:{_SHELL})"
            rf"|echo\s+[A-Za-z0-9+/=]{{16,}}\s*\|\s*base64\s+(?:-d|-D|--decode)\s*\|\s*(?:{_SHELL})"
        ),
        mitre="T1027/T1059",
        description="Base64-decoding a blob and executing it.",
        remediation="Decode and inspect the payload before running it.",
    ),
    Rule(
        id="OBFUSCATED_HEX_EXEC",
        category="obfuscation",
        severity=Severity.HIGH,
        pattern=_rx(rf"\bxxd\s+-r\b[^|\n]*\|\s*(?:{_SHELL})"),
        mitre="T1027",
        description="Hex-decoding a blob and executing it.",
        remediation="Decode and inspect before running.",
    ),

    # ---- Reverse shells / C2 -----------------------------------------------
    Rule(
        id="C2_DEV_TCP_REVERSE_SHELL",
        category="reverse_shell",
        severity=Severity.CRITICAL,
        pattern=_rx(r"(?:>&|<>|0>&1)\s*/dev/tcp/|/dev/tcp/[^/\s]+/\d+"),
        mitre="T1071/T1059",
        description="Bash /dev/tcp reverse shell.",
        remediation="Legitimate work never needs /dev/tcp; remove it.",
    ),
    Rule(
        id="C2_NETCAT_EXEC",
        category="reverse_shell",
        severity=Severity.CRITICAL,
        pattern=_rx(r"\bn(?:c|cat)\b[^|\n]*\s-\w*(?:e|c)\b[^|\n]*(?:/bin/(?:ba)?sh|cmd)"),
        mitre="T1071",
        description="netcat with -e/-c spawning a shell (reverse/bind shell).",
        remediation="Do not expose a shell over the network.",
    ),
    Rule(
        id="C2_SOCAT_EXEC",
        category="reverse_shell",
        severity=Severity.CRITICAL,
        pattern=_rx(r"\bsocat\b[^|\n]*\b(?:EXEC|SYSTEM):"),
        mitre="T1071",
        description="socat spawning a program bound to a socket (shell relay).",
        remediation="Avoid socat EXEC/SYSTEM to network endpoints.",
    ),
    Rule(
        id="C2_SCRIPTING_REVERSE_SHELL",
        category="reverse_shell",
        severity=Severity.CRITICAL,
        pattern=_rx(
            r"(?:python[0-9.]*|perl|ruby|php)\b[^\n]*"
            r"(?:socket\.socket|fsockopen|Socket|pty\.spawn)[^\n]*"
            r"(?:/bin/(?:ba)?sh|subprocess|exec)"
        ),
        mitre="T1059/T1071",
        description="Interpreter one-liner opening a socket and spawning a shell.",
        remediation="Remove the socket-to-shell bridge.",
    ),

    # ---- Persistence -------------------------------------------------------
    Rule(
        id="PERSIST_AUTHORIZED_KEYS",
        category="persistence",
        severity=Severity.HIGH,
        pattern=_rx(r">>?\s*[^\n|;&]*\.ssh/authorized_keys"),
        mitre="T1098",
        description="Writing to ~/.ssh/authorized_keys (SSH backdoor key).",
        remediation="Manage authorized keys via reviewed, audited config.",
    ),
    Rule(
        id="PERSIST_CRONTAB",
        category="persistence",
        severity=Severity.HIGH,
        pattern=_rx(
            r"\|\s*crontab\b|\bcrontab\s+-r\b"
            r"|>>?\s*(?:/etc/cron|/var/spool/cron)"
        ),
        mitre="T1053",
        description="Installing or destroying a cron job (scheduled persistence).",
        remediation="Add scheduled tasks through reviewed configuration.",
    ),
    Rule(
        id="PERSIST_SYSTEMD_RC",
        category="persistence",
        severity=Severity.MEDIUM,
        pattern=_rx(r">>?\s*(?:/etc/systemd/system|/etc/rc\.local|/etc/init\.d)\b"),
        mitre="T1543",
        description="Writing a service/init unit (boot persistence).",
        remediation="Provision services via configuration management.",
    ),
    Rule(
        id="PERSIST_SHELL_RC",
        category="persistence",
        severity=Severity.MEDIUM,
        pattern=_rx(r">>?\s*[^\n|;&]*/\.(?:bashrc|bash_profile|profile|zshrc)\b"),
        mitre="T1546",
        description="Appending to a shell startup file (login persistence).",
        remediation="Confirm the appended content is expected.",
    ),

    # ---- Credential access -------------------------------------------------
    Rule(
        id="CRED_SSH_PRIVATE_KEY",
        category="credential_access",
        severity=Severity.HIGH,
        pattern=_rx(
            r"\b(?:cat|less|more|head|tail|cp|scp|curl|nc|base64|xxd)\b"
            r"[^\n|]*\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b"
        ),
        mitre="T1552.004",
        description="Reading/copying an SSH private key.",
        remediation="Private keys should never be piped or copied off-host.",
    ),
    Rule(
        id="CRED_SENSITIVE_FILES",
        category="credential_access",
        severity=Severity.HIGH,
        pattern=_rx(
            r"\b(?:cat|less|more|head|tail|cp|scp|curl|nc|grep)\b[^\n|]*"
            r"(?:/etc/shadow|\.aws/credentials|\.config/gcloud|"
            r"\.docker/config\.json|\.netrc|\.git-credentials|\.kube/config)\b"
        ),
        mitre="T1552",
        description="Reading a well-known secrets/credentials file.",
        remediation="Access secrets through a secrets manager, not raw files.",
    ),
    Rule(
        id="CRED_ENV_EXFIL",
        category="credential_access",
        severity=Severity.HIGH,
        pattern=_rx(r"\b(?:env|printenv|set)\b[^\n]*\|\s*(?:curl|wget|nc|ncat)\b"),
        mitre="T1552.001/T1041",
        description="Dumping environment variables to the network (secret exfiltration).",
        remediation="Never pipe the environment to a network tool.",
    ),

    # ---- Privilege escalation ----------------------------------------------
    Rule(
        id="PRIVESC_SUDOERS",
        category="privilege_escalation",
        severity=Severity.CRITICAL,
        pattern=_rx(r">>?\s*/etc/sudoers(?:\.d/\S+)?\b|NOPASSWD\s*:\s*ALL"),
        mitre="T1548.003",
        description="Modifying sudoers / adding passwordless sudo.",
        remediation="Edit sudoers only via visudo, under review.",
    ),
    Rule(
        id="PRIVESC_SETUID",
        category="privilege_escalation",
        severity=Severity.HIGH,
        pattern=_rx(r"\bchmod\s+(?:[ugoa]*\+s|[4-7][0-7]{3})\b"),
        mitre="T1548.001",
        description="Setting the setuid/setgid bit (privilege escalation vector).",
        remediation="Avoid setuid binaries; use capabilities or sudo policy.",
    ),
    Rule(
        id="PRIVESC_ADD_PRIVILEGED_USER",
        category="privilege_escalation",
        severity=Severity.MEDIUM,
        pattern=_rx(r"\b(?:useradd|adduser)\b[^\n]*|\busermod\s+-a?G\s+(?:sudo|wheel|admin)\b"),
        mitre="T1136",
        description="Creating a user or granting sudo/wheel membership.",
        remediation="Manage accounts via reviewed provisioning.",
    ),

    # ---- Anti-forensics / impair defenses ----------------------------------
    Rule(
        id="ANTIFORENSIC_HISTORY",
        category="anti_forensics",
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTSIZE=0\b"
            r"|>\s*[^\n|;&]*\.bash_history\b|ln\s+-sf?\s+/dev/null\s+[^\n]*\.bash_history"
        ),
        mitre="T1070.003",
        description="Clearing/disabling shell history (evidence removal).",
        remediation="Do not tamper with audit trails.",
    ),
    Rule(
        id="DEFENSE_FIREWALL_FLUSH",
        category="impair_defenses",
        severity=Severity.HIGH,
        pattern=_rx(
            r"\biptables\s+-F\b|\bnft\s+flush\b|\bufw\s+disable\b"
            r"|\bsetenforce\s+0\b|\bsystemctl\s+stop\s+(?:firewalld|ufw)\b"
        ),
        mitre="T1562.001/.004",
        description="Flushing firewall rules / disabling host security controls.",
        remediation="Change firewall/SELinux policy through change control.",
    ),
    Rule(
        id="DEFENSE_TLS_DISABLED",
        category="impair_defenses",
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"\bcurl\b[^\n|]*\s-\w*k\b|--insecure\b|--no-check-certificate\b"
            r"|NODE_TLS_REJECT_UNAUTHORIZED=0|PYTHONHTTPSVERIFY=0"
            r"|git\b[^\n]*sslVerify=false"
        ),
        mitre="T1562",
        description="Disabling TLS certificate verification (MITM / poisoned download risk).",
        remediation="Keep certificate verification enabled.",
    ),

    # ---- Package-manager supply-chain risk ---------------------------------
    Rule(
        id="PKG_PIP_REMOTE_SOURCE",
        category="supply_chain",
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"\bpip[0-9.]*\s+install\b[^\n]*"
            r"(?:https?://|git\+|--index-url|--extra-index-url|--trusted-host)"
        ),
        mitre="T1195.002",
        description="Installing a Python package from a URL/VCS or an untrusted index "
                    "(dependency-confusion / poisoned-index vector).",
        remediation="Install from a pinned, hash-verified requirements file.",
    ),
    Rule(
        id="PKG_NPM_UNSAFE",
        category="supply_chain",
        severity=Severity.MEDIUM,
        pattern=_rx(
            r"\bnpm\s+(?:i|install)\b[^\n]*(?:--unsafe-perm|https?://|git\+)"
            r"|\bnpm\b[^\n]*--registry=?\s*https?://(?!registry\.npmjs\.org)"
        ),
        mitre="T1195.002",
        description="npm install with --unsafe-perm, a URL/VCS spec, or a non-default registry.",
        remediation="Install from package-lock.json against the official registry.",
    ),
]


def scan(command: str) -> List[Finding]:
    """Return all findings for ``command`` (empty list == clean).

    Findings are sorted most-severe first so the caller can act on ``[0]``.
    """
    if not command:
        return []
    findings: List[Finding] = []
    for rule in RULES:
        m = rule.pattern.search(command)
        if m:
            findings.append(Finding(rule=rule, match=m.group(0).strip()))
    findings.sort(key=lambda f: f.rule.severity, reverse=True)
    return findings


def worst_severity(findings: List[Finding]) -> Severity | None:
    """Highest severity among findings, or None if clean."""
    return max((f.rule.severity for f in findings), default=None)


def decision_for(findings: List[Finding]) -> str:
    """Aggregate findings into a single decision: allow | ask | deny."""
    sev = worst_severity(findings)
    if sev is None:
        return "allow"
    return DECISION_BY_SEVERITY[sev]
