#!/usr/bin/env python3
"""
pretooluse_guard.py — Claude Code PreToolUse hook entrypoint.

Wire this into ``.claude/settings.json``:

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              { "type": "command",
                "command": "python3 /abs/path/to/hooks/pretooluse_guard.py" }
            ]
          }
        ]
      }
    }

Contract (Claude Code hooks)
----------------------------
* Input  : a JSON object on stdin. For the Bash tool the command lives at
           ``tool_input.command``.
* Output : a JSON object on stdout describing the permission decision. We use
           the structured ``hookSpecificOutput`` form:

               {
                 "hookSpecificOutput": {
                   "hookEventName": "PreToolUse",
                   "permissionDecision": "allow" | "ask" | "deny",
                   "permissionDecisionReason": "..."
                 }
               }

  - ``deny``  blocks the call and returns the reason to the model.
  - ``ask``   defers to the human for confirmation.
  - ``allow`` proceeds (we still emit a note for LOW findings).

Fail-open vs fail-closed: if we cannot parse the input we ``allow`` (exit 0)
so a malformed event never bricks the session — the guardrail is additive, and
a broken hook must not become a denial-of-service against the user. Detection
logic that *does* run always fails safe (deny/ask on match).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running both as a module and as a standalone script path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from guardrails import decision_for, scan  # noqa: E402


def _emit(decision: str, reason: str) -> None:
    """Write the structured PreToolUse decision and exit 0."""
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def _extract_command(event: dict) -> str:
    """Pull the shell command out of a PreToolUse event.

    Only the Bash tool carries an executable command string; for any other tool
    there is nothing for these rules to inspect.
    """
    if event.get("tool_name") != "Bash":
        return ""
    return (event.get("tool_input") or {}).get("command", "") or ""


def main() -> None:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Fail open on unparseable input (see module docstring).
        _emit("allow", "guardrail: could not parse hook input; allowing.")

    command = _extract_command(event)
    if not command:
        _emit("allow", "guardrail: no shell command to inspect.")

    findings = scan(command)
    decision = decision_for(findings)

    if decision == "allow":
        _emit("allow", "guardrail: no dangerous patterns detected.")

    top = findings[0]
    others = len(findings) - 1
    reason = (
        f"guardrail {decision.upper()} [{top.rule.severity.name}] "
        f"{top.rule.id} ({top.rule.category}): {top.rule.description} "
        f"Matched: {top.match!r}."
    )
    if top.rule.mitre:
        reason += f" MITRE {top.rule.mitre}."
    if top.rule.remediation:
        reason += f" Safer: {top.rule.remediation}"
    if others > 0:
        reason += f" (+{others} more finding(s): " + ", ".join(
            f"{f.rule.id}" for f in findings[1:]
        ) + ")"

    _emit(decision, reason)


if __name__ == "__main__":
    main()
