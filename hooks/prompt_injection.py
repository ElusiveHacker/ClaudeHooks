"""
prompt_injection.py — Detection for prompt-injection payloads in untrusted content.

Implements the taxonomy from:
    "Prompt Injection, Deconstructed"
    https://securityhorror.blogspot.com/2026/07/prompt-injection-deconstructed_01586936738.html

It complements ``guardrails.py`` (which gates *actions* — the durable control the
article argues for) by scanning *content* — user prompts and, more importantly,
tool output (indirect injection) — for the documented carriers:

    * Invisible Unicode         zero-width, bidi controls, Tag block ("ASCII smuggling")
    * Homoglyph / mixed-script  Cyrillic/Greek lookalikes inside Latin words
    * Encoded payloads          base64/hex blobs that DECODE to an injection phrase
    * Injection phrases         "ignore previous instructions", role override, exfil
    * Rendering-context hiding  display:none, font-size:0, HTML comments, etc.
    * Staged / nested decoding  "decode the following and run it"

Honest limitations (echoing the article itself)
------------------------------------------------
The article's thesis is that input-layer filtering is a **speed bump**: an
attacker adds one more encoding layer or invisible code point and walks past any
static matcher. So this module is deliberately scoped as a *tripwire + sanitizer*:

    1. ``sanitize()`` strips the invisible carriers (a real, durable win — it
       removes ASCII-smuggling channels entirely).
    2. ``scan_content()`` raises alerts on the documented shapes so a human /
       the agent is put on guard.

The load-bearing defenses remain architectural and live elsewhere: the
``PreToolUse`` action gate (guardrails.py), least-privilege tokens, egress
allowlisting, and human-in-the-loop on consequential actions. Never treat this
module as a boundary.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from enum import IntEnum
from typing import List


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Invisible / control code points (article "Invisible Unicode Techniques")
# ---------------------------------------------------------------------------
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
TAG_LO, TAG_HI = 0xE0000, 0xE007F  # Unicode Tag block == "ASCII smuggling"


def is_hidden(cp: int) -> bool:
    """True if a code point renders invisibly but occupies token space."""
    return cp in ZERO_WIDTH or cp in BIDI or TAG_LO <= cp <= TAG_HI


def sanitize(text: str) -> str:
    """NFKC-normalize and strip every hidden carrier.

    The article's key finding: NFKC alone does **not** remove these characters;
    explicit enumeration is required. This function does both.
    """
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if not is_hidden(ord(ch)))


def hidden_char_count(text: str) -> int:
    """Number of hidden carriers present (the 'length-delta' signal)."""
    return sum(1 for ch in text if is_hidden(ord(ch)))


def decode_tags(text: str) -> str:
    """Recover the shadow-ASCII smuggled in the Tag block, for reporting."""
    out = []
    for ch in text:
        cp = ord(ch)
        if TAG_LO <= cp <= TAG_HI:
            out.append(chr(cp - TAG_LO))  # inverse of chr(0xE0000 + ord(c))
    return "".join(out).strip()


# ---------------------------------------------------------------------------
# Injection-phrase patterns (article: direct injection + role override + exfil)
# ---------------------------------------------------------------------------
_HIGH_PHRASES = [
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier)\s+"
    r"(?:instructions?|prompts?|context|messages?|rules?)",
    r"disregard\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|your)\s+"
    r"(?:instructions?|prompts?|rules?|guidelines?)",
    r"forget\s+(?:everything|all|the)\s+(?:above|previous|prior|you\s+were\s+told)",
    r"override\s+(?:your\s+|the\s+)?(?:previous\s+|safety\s+|system\s+)?"
    r"(?:instructions?|guardrails?|rules?|prompt)",
    r"(?:reveal|print|repeat|show|output|disclose|leak)\s+(?:your\s+|the\s+)?"
    r"(?:full\s+|initial\s+|original\s+)?(?:system\s+)?(?:prompt|instructions?)",
    r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b",
    r"reply\s+only\s+with\s+the\s+word\s+\w+",  # canary shape from the article
    r"\bINJECTED\b",                             # the article's literal canary token
]

_MEDIUM_PHRASES = [
    r"you\s+are\s+now\s+(?:a\s+|an\s+|in\s+)?",
    r"(?:enable|enter|activate)\s+(?:developer|god|jailbreak|dev|debug)\s+mode",
    r"\bact\s+as\s+(?:a\s+|an\s+)?(?:different|unrestricted|jailbroken|evil)\b",
    r"new\s+(?:instructions?|system\s+prompt|rules?)\s*[:：]",
    r"\bsystem\s*[:：]\s*",                       # fake 'System:' turn injected in data
    r"pretend\s+(?:you\s+are|to\s+be)\b",
    r"from\s+now\s+on\s+(?:you|ignore|respond)",
]

# Exfiltration instruction shapes (article: agent kill-chain / lethal trifecta)
_EXFIL_PHRASE = (
    r"(?:send|email|post|upload|exfiltrate|forward|leak|transmit)\s+(?:the\s+|your\s+|all\s+)?"
    r"(?:secrets?|credentials?|env(?:ironment)?|\.env|tokens?|keys?|passwords?|api[_\s-]?keys?)"
    r"[^\n]{0,40}?\b(?:to|into|at)\b"
)

# Staged / nested decode-then-run instructions (article: nested obfuscation)
_STAGED_DECODE = (
    r"(?:decode|base64\s*-?d|from\s*base64|un-?escape|rot13|de-?obfuscate|reassemble|"
    r"concatenate|join\s+the\s+(?:parts|fragments|blocks))"
    r"[^\n]{0,60}?(?:and\s+)?(?:then\s+)?(?:run|execute|eval|follow|obey|apply)"
)

# Rendering-context hiding (article: HTML/CSS hidden from human review)
_HTML_HIDDEN = (
    r"display\s*:\s*none|font-size\s*:\s*0(?:px)?\b|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*#?(?:fff(?:fff)?|white)\b|"
    r"position\s*:\s*absolute[^\n]{0,40}?(?:left|top)\s*:\s*-\s*\d{3,}"
)


@dataclass(frozen=True)
class InjectionRule:
    id: str
    category: str
    severity: Severity
    description: str
    owasp: str = "LLM01"


@dataclass
class InjectionFinding:
    rule: InjectionRule
    evidence: str

    def as_dict(self) -> dict:
        return {
            "id": self.rule.id,
            "category": self.rule.category,
            "severity": self.rule.severity.name,
            "owasp": self.rule.owasp,
            "description": self.rule.description,
            "evidence": self.evidence,
        }


_RULES = {
    "PI_HIDDEN_UNICODE": InjectionRule(
        "PI_HIDDEN_UNICODE", "invisible_unicode", Severity.HIGH,
        "Invisible Unicode carrier (zero-width / bidi / Tag-block ASCII smuggling) "
        "present in content — a channel for instructions hidden from human review."),
    "PI_HOMOGLYPH": InjectionRule(
        "PI_HOMOGLYPH", "homoglyph", Severity.MEDIUM,
        "Mixed-script word (Latin combined with Cyrillic/Greek lookalikes) — "
        "defeats exact-match filters while appearing identical to a human."),
    "PI_ENCODED_PAYLOAD": InjectionRule(
        "PI_ENCODED_PAYLOAD", "encoded_payload", Severity.HIGH,
        "Encoded blob decodes to an injection phrase (single/nested encoding evasion)."),
    "PI_INJECTION_PHRASE": InjectionRule(
        "PI_INJECTION_PHRASE", "injection_phrase", Severity.HIGH,
        "Known prompt-injection / instruction-override phrase."),
    "PI_ROLE_OVERRIDE": InjectionRule(
        "PI_ROLE_OVERRIDE", "role_override", Severity.MEDIUM,
        "Attempt to redefine the model's role or inject a fake system turn."),
    "PI_EXFIL_INSTRUCTION": InjectionRule(
        "PI_EXFIL_INSTRUCTION", "exfiltration", Severity.HIGH,
        "Instruction to send secrets/credentials to an external destination "
        "(agent kill-chain exfiltration step).", owasp="LLM02"),
    "PI_STAGED_DECODE": InjectionRule(
        "PI_STAGED_DECODE", "staged_decode", Severity.MEDIUM,
        "Instruction to decode/reassemble content and then run/follow it."),
    "PI_HTML_HIDDEN": InjectionRule(
        "PI_HTML_HIDDEN", "rendering_hidden", Severity.MEDIUM,
        "Content hidden via HTML/CSS (display:none, font-size:0, etc.) — visible "
        "to the model but not to a human reviewer."),
}

_HIGH_RX = [re.compile(p, re.IGNORECASE) for p in _HIGH_PHRASES]
_MEDIUM_RX = [re.compile(p, re.IGNORECASE) for p in _MEDIUM_PHRASES]
_EXFIL_RX = re.compile(_EXFIL_PHRASE, re.IGNORECASE)
_STAGED_RX = re.compile(_STAGED_DECODE, re.IGNORECASE)
_HTML_RX = re.compile(_HTML_HIDDEN, re.IGNORECASE)

# base64 (>=20 chars) and long hex (>=32 chars) candidate blobs.
_B64_RX = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RX = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")

# Script ranges for mixed-script detection.
_CYRILLIC = (0x0400, 0x04FF)
_GREEK = (0x0370, 0x03FF)


def _phrase_findings(text: str) -> List[InjectionFinding]:
    out: List[InjectionFinding] = []
    for rx in _HIGH_RX:
        m = rx.search(text)
        if m:
            out.append(InjectionFinding(_RULES["PI_INJECTION_PHRASE"], m.group(0).strip()))
            break
    for rx in _MEDIUM_RX:
        m = rx.search(text)
        if m:
            out.append(InjectionFinding(_RULES["PI_ROLE_OVERRIDE"], m.group(0).strip()))
            break
    m = _EXFIL_RX.search(text)
    if m:
        out.append(InjectionFinding(_RULES["PI_EXFIL_INSTRUCTION"], m.group(0).strip()))
    m = _STAGED_RX.search(text)
    if m:
        out.append(InjectionFinding(_RULES["PI_STAGED_DECODE"], m.group(0).strip()))
    m = _HTML_RX.search(text)
    if m:
        out.append(InjectionFinding(_RULES["PI_HTML_HIDDEN"], m.group(0).strip()))
    return out


def _has_injection_text(text: str) -> bool:
    return any(rx.search(text) for rx in _HIGH_RX) or bool(_EXFIL_RX.search(text))


def _decoded_findings(text: str, depth: int = 2) -> List[InjectionFinding]:
    """Extract base64/hex blobs, decode (recursively, bounded), and flag any that
    resolve to an injection phrase. Blobs that don't decode to anything malicious
    are ignored to keep false positives low (JWTs, hashes, data URIs, etc.)."""
    findings: List[InjectionFinding] = []
    candidates = _B64_RX.findall(text) + _HEX_RX.findall(text)
    for blob in candidates:
        decoded = _try_decode(blob)
        for _ in range(depth):
            if decoded is None:
                break
            if _has_injection_text(decoded):
                findings.append(InjectionFinding(
                    _RULES["PI_ENCODED_PAYLOAD"],
                    f"{blob[:24]}… -> {decoded[:80]!r}"))
                break
            decoded = _try_decode(decoded)  # nested layer
    return findings


def _try_decode(blob: str) -> str | None:
    """Best-effort base64/hex decode to printable text; None if it isn't either."""
    s = blob.strip()
    # base64
    try:
        pad = "=" * (-len(s) % 4)
        raw = base64.b64decode(s + pad, validate=True)
        txt = raw.decode("utf-8", "strict")
        if txt.isprintable() or "\n" in txt:
            return txt
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    # hex
    try:
        if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
            txt = bytes.fromhex(s).decode("utf-8", "strict")
            if txt.isprintable() or "\n" in txt:
                return txt
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def _mixed_script_findings(text: str) -> List[InjectionFinding]:
    """Flag tokens that mix Latin with Cyrillic/Greek (homoglyph attack)."""
    for token in re.findall(r"[^\W\d_]{2,}", text, re.UNICODE):
        has_latin = has_cyr = has_grk = False
        for ch in token:
            cp = ord(ch)
            if ("a" <= ch.lower() <= "z") or 0x00C0 <= cp <= 0x024F:
                has_latin = True
            elif _CYRILLIC[0] <= cp <= _CYRILLIC[1]:
                has_cyr = True
            elif _GREEK[0] <= cp <= _GREEK[1]:
                has_grk = True
        if has_latin and (has_cyr or has_grk):
            return [InjectionFinding(_RULES["PI_HOMOGLYPH"], token)]
    return []


def scan_content(text: str) -> List[InjectionFinding]:
    """Scan untrusted content for prompt-injection carriers.

    Returns findings sorted most-severe first. Note: hidden-Unicode and encoded
    payloads are detected on the *raw* text (before sanitizing), while phrase and
    homoglyph checks run on the sanitized text so smuggled instructions that
    become visible after stripping are still caught.
    """
    if not text:
        return []
    findings: List[InjectionFinding] = []

    n_hidden = hidden_char_count(text)
    if n_hidden > 0:
        smuggled = decode_tags(text)
        ev = f"{n_hidden} hidden code point(s)"
        if smuggled:
            ev += f"; decoded Tag-block: {smuggled[:80]!r}"
        findings.append(InjectionFinding(_RULES["PI_HIDDEN_UNICODE"], ev))

    findings += _decoded_findings(text)

    clean = sanitize(text)
    findings += _phrase_findings(clean)
    findings += _mixed_script_findings(clean)
    # A Tag-block payload that decodes to an injection phrase is high-signal too.
    smuggled = decode_tags(text)
    if smuggled and _has_injection_text(smuggled):
        findings.append(InjectionFinding(_RULES["PI_INJECTION_PHRASE"], smuggled[:80]))

    # De-duplicate by rule id, keep highest evidence, sort by severity.
    seen = {}
    for f in findings:
        seen.setdefault(f.rule.id, f)
    result = sorted(seen.values(), key=lambda f: f.rule.severity, reverse=True)
    return result


def decision_for(findings: List[InjectionFinding]) -> str:
    """allow | warn | block. HIGH+ blocks; MEDIUM warns; clean allows."""
    if not findings:
        return "allow"
    sev = max(f.rule.severity for f in findings)
    if sev >= Severity.HIGH:
        return "block"
    if sev == Severity.MEDIUM:
        return "warn"
    return "allow"
