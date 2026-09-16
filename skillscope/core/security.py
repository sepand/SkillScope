"""Deterministic, pattern-based scan for malicious or unsafe content in a SKILL.md.

This is a heuristic lint, not a malware scanner: it flags patterns worth a human's
attention immediately (remote-code-execution one-liners, destructive commands,
credential/secret access, exfiltration phrasing, prompt-injection language, obfuscated
payloads) without needing the Claude API, so something is always shown even offline.
Natural-language malicious *intent* that doesn't match these patterns is caught
separately by the semantic analyzer (see analyzer.py).
"""

from __future__ import annotations

import re

from .models import SEVERITY_RANK, SecurityFinding

# (category, severity, pattern, explanation)
_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "remote_code_execution", "critical",
        re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[23]?)\b", re.IGNORECASE),
        "Downloads a remote script and pipes it directly into a shell/interpreter without inspection.",
    ),
    (
        "remote_code_execution", "critical",
        re.compile(r"Invoke-(WebRequest|RestMethod)\b[^\n]*\|\s*(iex|Invoke-Expression)\b", re.IGNORECASE),
        "Downloads remote content and executes it via PowerShell Invoke-Expression.",
    ),
    (
        "remote_code_execution", "high",
        re.compile(r"\bexec\s*\(\s*(base64\.)?b64decode\(|eval\s*\(\s*atob\(", re.IGNORECASE),
        "Decodes and executes what appears to be an obfuscated payload.",
    ),
    (
        "destructive_command", "critical",
        re.compile(r"rm\s+-rf\s+(/|~|\$HOME|\*)(?!\S)", re.IGNORECASE),
        "Recursively force-deletes a broad path (root, home directory, or everything).",
    ),
    (
        "destructive_command", "high",
        re.compile(r"\bDROP\s+(TABLE|DATABASE)\b", re.IGNORECASE),
        "Irreversibly drops a database or table.",
    ),
    (
        "destructive_command", "high",
        re.compile(r"git\s+push\s+[^\n]*--force\b", re.IGNORECASE),
        "Force-pushes, which can silently overwrite remote history other people depend on.",
    ),
    (
        "credential_access", "high",
        re.compile(r"(\.ssh/id_rsa|\.aws/credentials|\.npmrc\b|\bid_rsa\b|\.env\b|credentials\.json)", re.IGNORECASE),
        "References a credential/secret file or path; verify it isn't being read for exfiltration.",
    ),
    (
        "data_exfiltration", "critical",
        re.compile(r"curl\s+[^\n]*-X\s*POST[^\n]*\$\((cat|env)\b", re.IGNORECASE),
        "Appears to POST the contents of a local file or environment variables to a remote endpoint.",
    ),
    (
        "data_exfiltration", "high",
        re.compile(
            r"\b(exfiltrat\w*|send[^\n.]{0,30}(api[_ -]?key|secret|token|password|credentials)[^\n.]{0,20}to\b"
            r"|upload[^\n.]{0,20}(secret|credential|password))",
            re.IGNORECASE,
        ),
        "Natural-language instruction to send sensitive data to an external destination.",
    ),
    (
        "prompt_injection", "high",
        re.compile(
            r"\b(ignore (all )?(previous|prior|above) instructions"
            r"|disregard (your|the) (instructions|guidelines)"
            r"|do not (tell|inform|mention (this|it) to) the user"
            r"|hide this from the user"
            r"|without (asking|telling) the user)\b",
            re.IGNORECASE,
        ),
        "Phrasing consistent with a prompt-injection attempt, or instructs the agent to act "
        "covertly without the user's awareness.",
    ),
    (
        "prompt_injection", "medium",
        re.compile(r"\b(you are now|act as (a )?(DAN|an unrestricted|a jailbroken)|bypass (safety|restrictions|guardrails))\b", re.IGNORECASE),
        "Attempts to redefine the agent's identity or bypass its safety behavior.",
    ),
    (
        "obfuscation", "medium",
        re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),
        "Contains a long base64-like blob; verify what it decodes to before trusting this skill.",
    ),
    (
        "privilege_escalation", "medium",
        re.compile(r"\bchmod\s+(-R\s+)?777\b", re.IGNORECASE),
        "Grants world-writable (or world-executable) permissions, which weakens file security.",
    ),
    (
        "persistence", "medium",
        re.compile(r"(\bcrontab\s+-e\b|/etc/cron\.|HKCU\\[^\n]*\\Run\b|LaunchAgents)", re.IGNORECASE),
        "Modifies scheduled tasks or startup entries, which can be used to persist unwanted behavior.",
    ),
]

_MAX_EXCERPT_LEN = 200


def scan(content: str) -> list[SecurityFinding]:
    """Scans raw SKILL.md content (frontmatter + body) for suspicious patterns."""
    findings: list[SecurityFinding] = []
    seen: set[tuple[str, str]] = set()

    for category, severity, pattern, explanation in _PATTERNS:
        for m in pattern.finditer(content):
            excerpt = m.group(0).strip()
            if len(excerpt) > _MAX_EXCERPT_LEN:
                excerpt = excerpt[:_MAX_EXCERPT_LEN] + "..."
            key = (category, excerpt)
            if key in seen:
                continue
            seen.add(key)
            findings.append(SecurityFinding(
                severity=severity, category=category, excerpt=excerpt, issue=explanation, source="pattern",
            ))

    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    return findings
