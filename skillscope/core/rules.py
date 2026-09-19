"""SkillScope's local "malicious skill behavior" rule database.

A versioned, pure-Python module - deliberately not a YAML/JSON data file (which would
need its own Pyodide-safe loader for no real benefit) and deliberately not a live external
fetch (the user asked for "a maintained local dataset, not live-fetched from an unverified
external API"). Every rule below carries a `citation` back to the concrete research it's
based on; nothing here is invented.

OWASP Agentic Skills Top 10 status, verified by directly fetching the project's pages in
the same session this module was written (not from an AI-summarized pass): it is an OWASP
**Incubator** project, version 0.0.0, explicitly "active development" - not a ratified
standard. Its content is licensed **CC-BY-SA-4.0**; the citations below that reference it
are attribution for that reuse, not a claim of official/certified status.
"""

from __future__ import annotations

import json
import re

from .models import SecurityFinding

RULESET_VERSION = "2026-09-16.1"

OWASP_AST_SOURCE = (
    "OWASP Agentic Skills Top 10 (Incubator project, v0.0.0, active development, not a "
    "ratified standard) - https://owasp.github.io/www-project-agentic-skills-top-10/ - "
    "content licensed CC-BY-SA-4.0; reproduced/adapted here with attribution."
)

_DATADOG_CITATION = (
    "Datadog Security Labs, \"Malicious skills / supply chain risks in coding agents with "
    "dynamic context\" - https://securitylabs.datadoghq.com/articles/"
    "malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/"
)
_SNYK_CITATION = (
    "Snyk ToxicSkills research on skills.sh/ClawHub-distributed skills "
    "(https://github.com/snyk-labs/toxicskills-goof) - a 3,984-skill sample study."
)

# (category, severity, compiled_regex, explanation, citation)
MALICIOUS_PATTERNS: list[tuple[str, str, re.Pattern, str, str]] = [
    (
        "dynamic_context_execution", "critical",
        re.compile(r"!`[^\n`]*\b(curl|wget|nc|bash)\b", re.IGNORECASE),
        "Uses Claude Code's dynamic-context `!` syntax to run a shell command that "
        "executes BEFORE the agent ever reviews this file's content - this bypasses "
        "model-level review entirely, not just human review.",
        _DATADOG_CITATION,
    ),
    (
        "over_privileged_frontmatter", "high",
        re.compile(r"allowed-tools\s*:.*Bash\(\*\)", re.IGNORECASE),
        "Frontmatter pre-approves unrestricted Bash execution for the entire time this "
        "skill is active. A reviewer scanning only the instructional prose would miss "
        "this - it's a silent, standing grant, not something the skill asks permission "
        "for at the point of use.",
        _DATADOG_CITATION,
    ),
    (
        "disguised_exfiltration", "critical",
        re.compile(r"gh\s+auth\s+token\b[\s\S]{0,500}?curl\s[^\n]*-X\s*POST", re.IGNORECASE),
        "Reads a GitHub auth token and then POSTs data via curl shortly after, in the same "
        "file - matches a documented pattern where this was framed as \"uploading a "
        "report\" while actually exfiltrating the token.",
        _DATADOG_CITATION,
    ),
    (
        "obfuscation", "high",
        re.compile(
            r"(curl|wget)\s[^\n]*\.(zip|7z)\b[\s\S]{0,200}?(unzip\s+-P\s|7z\s+x\s+-p)",
            re.IGNORECASE,
        ),
        "Downloads a password-protected archive and extracts it with the password inline - "
        "a documented technique for evading static antivirus scanning of archive contents "
        "(the scanner never sees the plaintext files without the password).",
        _SNYK_CITATION,
    ),
    (
        "hardcoded_secret", "high",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Contains what looks like an AWS access key ID hardcoded in the file.",
        _SNYK_CITATION,
    ),
    (
        "hardcoded_secret", "high",
        re.compile(
            # Captures the FULL value (quoted-to-matching-quote, or up to the next
            # whitespace/quote) rather than stopping at the first non-alnum character -
            # a truncated match here would make redact_secrets() below only redact a
            # prefix of the real secret, leaking the rest to the semantic-analysis API.
            r"\b(api[_-]?key|secret|token|password)\s*[:=]\s*"
            r"(\"[^\"]{16,}\"|'[^']{16,}'|[^\s\"']{16,})",
            re.IGNORECASE,
        ),
        "Contains what looks like a hardcoded credential/secret assignment. Roughly 1 in "
        "10 malicious skills sampled by Snyk had a hardcoded secret like this.",
        _SNYK_CITATION,
    ),
]

# Kept separate from MALICIOUS_PATTERNS: always low severity, with an explicit
# high-false-positive-rate caveat, per Datadog's own guidance not to flag a URL alone.
WEAK_SIGNALS: list[tuple[str, str, re.Pattern, str, str]] = [
    (
        "external_reference", "low",
        re.compile(r"https?://[^)\s\"'>]*\.(com|io|zone|dev|cloud|net)\b", re.IGNORECASE),
        "References an external URL. This is a weak signal on its own (most skills "
        "legitimately link to docs) - only meaningful combined with other findings above.",
        _DATADOG_CITATION,
    ),
]

_INSTALL_RE = re.compile(
    r"\b(pip3?\s+install|npm\s+install|npx\s+install|go\s+get|gem\s+install)\b",
    re.IGNORECASE,
)
_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def _strip_fenced_code_blocks(content: str) -> str:
    """Removes fenced code blocks so setup-doc install commands (e.g. this project's own
    README `pip install -r requirements.txt`) don't trip the runtime-install rule below."""
    return _FENCE_RE.sub("", content)


def scan_runtime_installs(content: str) -> list[SecurityFinding]:
    """Flags a package-manager install command appearing in prose, outside a fenced code
    block. This is the one OWASP AST02 (Supply Chain Compromise) sub-case decidable from a
    single file's content - a documented setup step in a normal ```` ``` ```` fence is not
    what this flags; an install instruction embedded in the skill's freeform instructions
    is, since it's a runtime dependency the agent would be told to pull in unreviewed."""
    prose = _strip_fenced_code_blocks(content)
    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    for m in _INSTALL_RE.finditer(prose):
        excerpt = m.group(0).strip()
        if excerpt in seen:
            continue
        seen.add(excerpt)
        findings.append(SecurityFinding(
            severity="medium",
            category="supply_chain_runtime_install",
            excerpt=excerpt,
            issue=(
                "Instructs installing a package at runtime, outside of a documented setup "
                "code block. Review the install target - this is a supply-chain vector "
                "OWASP AST02 flags, and SkillScope can't verify what the named package "
                "actually is or where it comes from."
            ),
            source="pattern",
            citation=(
                "OWASP Agentic Skills Top 10 AST02 (Supply Chain Compromise) - "
                "https://owasp.github.io/www-project-agentic-skills-top-10/top10 "
                "(OWASP Incubator project, not a ratified standard)."
            ),
        ))
    return findings


def scan_malicious_patterns(content: str) -> list[SecurityFinding]:
    """Runs MALICIOUS_PATTERNS + the runtime-install check against raw content."""
    findings: list[SecurityFinding] = []
    seen: set[tuple[str, str]] = set()

    for category, severity, pattern, explanation, citation in MALICIOUS_PATTERNS:
        for m in pattern.finditer(content):
            excerpt = m.group(0).strip()
            key = (category, excerpt)
            if key in seen:
                continue
            seen.add(key)
            findings.append(SecurityFinding(
                severity=severity, category=category, excerpt=excerpt,
                issue=explanation, source="pattern", citation=citation,
            ))

    findings.extend(scan_runtime_installs(content))
    return findings


def scan_weak_signals(content: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    for category, severity, pattern, explanation, citation in WEAK_SIGNALS:
        for m in pattern.finditer(content):
            excerpt = m.group(0).strip()
            if excerpt in seen:
                continue
            seen.add(excerpt)
            findings.append(SecurityFinding(
                severity=severity, category=category, excerpt=excerpt,
                issue=explanation, source="pattern", citation=citation,
            ))
    return findings


# Small, explicitly narrow and decaying - not a guarantee of coverage, just named IOCs
# from one research pass. (indicator, kind, explanation, citation)
KNOWN_THREAT_INDICATORS: list[tuple[str, str, str, str]] = [
    ("zaycv", "author_account", "Matches a threat-actor account name identified in Snyk's ToxicSkills research (published 40+ near-identical malicious skills).", _SNYK_CITATION),
    ("Aslaep123", "author_account", "Matches a threat-actor account name identified in Snyk's ToxicSkills research (crypto-targeting skills).", _SNYK_CITATION),
    ("ClawHavoc", "campaign_name", "Matches the name of a documented supply-chain compromise campaign (~1,184 skills compromised via injection into existing packages).", _SNYK_CITATION),
]


def scan_threat_indicators(content: str, frontmatter: dict) -> list[SecurityFinding]:
    """Checks frontmatter author/name fields and raw content against a small, named,
    known-stale-quickly list of indicators from one research pass - not a general
    detector."""
    findings: list[SecurityFinding] = []
    haystacks = [
        str(frontmatter.get("author", "")),
        str(frontmatter.get("name", "")),
        content,
    ]
    lowered_haystacks = [h.lower() for h in haystacks]

    for indicator, kind, explanation, citation in KNOWN_THREAT_INDICATORS:
        needle = indicator.lower()
        if any(needle in h for h in lowered_haystacks):
            findings.append(SecurityFinding(
                severity="high",
                category="known_threat_indicator",
                excerpt=indicator,
                issue=(
                    f"{explanation} This is a small, narrow, quickly-stale named-IOC list "
                    f"(kind: {kind}) from one research pass, not a guarantee of broad "
                    "coverage - absence of a match here means nothing either way."
                ),
                source="pattern",
                citation=citation,
            ))
    return findings


def check_combined_payload_injection(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Correlation, not a new regex: Snyk found 91% of confirmed-malicious skills combined
    an obfuscated/encoded payload with prompt-injection priming text, not just one or the
    other. If both categories already fired independently, escalate with one additional
    finding naming the combination - the co-occurrence is itself the signal."""
    has_obfuscation = any(f.category == "obfuscation" for f in findings)
    has_injection = any(f.category == "prompt_injection" for f in findings)
    if not (has_obfuscation and has_injection):
        return []
    return [SecurityFinding(
        severity="critical",
        category="combined_payload_and_injection",
        excerpt="(correlation of separate findings above, not a single excerpt)",
        issue=(
            "This file has BOTH an obfuscated/encoded payload finding AND a "
            "prompt-injection-phrasing finding. Independently, most bad but the pattern "
            "of the two happening together in one file matches what confirmed-malicious "
            "skills look like far more often than either alone."
        ),
        source="pattern",
        citation=_SNYK_CITATION + " (91% of confirmed-malicious skills combined both.)",
    )]


# --- Dependency-manifest checks (package.json / requirements.txt / Pipfile / go.mod) ---
# Narrowly scoped to a small number of concrete, widely-documented supply-chain
# techniques that are decidable from a single manifest file's own text, with no
# package-registry lookup
# needed - this is NOT a general dependency auditor (no typosquat detection, no CVE
# database; those need external registry/vulnerability data SkillScope doesn't have and
# has deliberately not wired up as a live external fetch - see module docstring).
_MANIFEST_INSTALL_HOOK_CITATION = (
    "Documented npm supply-chain technique: a malicious package version adds a "
    "preinstall/install/postinstall lifecycle script that runs automatically on "
    "`npm install`, before a human ever reviews the code - the mechanism used in the 2018 "
    "event-stream compromise and the 2021 ua-parser-js/coa/rc compromises."
)
_MANIFEST_VCS_BYPASS_CITATION = (
    "pip supports installing a dependency directly from a VCS URL (git+/hg+/svn+/bzr+) "
    "instead of a published package-index release - a supported feature, but one that "
    "bypasses the index's own review/typosquat protections entirely, so the actual "
    "target warrants a manual look."
)
_MANIFEST_GO_REPLACE_CITATION = (
    "Go's own module documentation: a 'replace' directive silently substitutes a "
    "different source (fork, URL, or local path) for a dependency's declared module path "
    "- reviewers should verify the replacement target matches intent."
)

_MANIFEST_NETWORK_EXEC_RE = re.compile(
    r"\b(curl|wget)\b|\bnc\s+-|\beval\s*\(|base64\s+(-d|--decode)\b",
    re.IGNORECASE,
)
# pip's own requirements.txt line syntax: `git+https://...` (optionally `-e git+...`).
_PIP_VCS_INSTALL_RE = re.compile(
    r"^\s*(?:-e\s+)?(?:git|hg|svn|bzr)\+[a-z][a-z0-9+.-]*://\S+",
    re.IGNORECASE | re.MULTILINE,
)
# Pipfile's TOML inline-table syntax: `name = {git = "https://...", ...}` - a different
# spelling of the same VCS-bypass dependency, not decidable with the regex above.
_PIPFILE_VCS_RE = re.compile(
    r"\{[^{}]*\b(?:git|hg|svn|bzr)\s*=\s*[\"'][^\"']+[\"'][^{}]*\}",
    re.IGNORECASE,
)
# go.mod's single-line form: `replace old/module => new/module v1.2.3`.
_GO_REPLACE_SINGLE_RE = re.compile(r"^[ \t]*replace\s+(?!\()\S+.*=>.*\S", re.MULTILINE)
# go.mod's block form: `replace (\n  old => new\n  ...\n)` - each inner line omits the
# `replace` keyword, so it needs its own extraction pass over the block's body.
_GO_REPLACE_BLOCK_RE = re.compile(r"replace\s*\(([^)]*)\)", re.DOTALL)
_GO_REPLACE_BLOCK_LINE_RE = re.compile(r"^[ \t]*\S+.*=>.*\S", re.MULTILINE)


def _scan_package_json_scripts(content: str) -> list[SecurityFinding]:
    """Flags an npm lifecycle install script that runs a network-fetch-and-execute or
    decode/eval pattern - these hooks run automatically on `npm install`, before any
    human reviews the code."""
    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    findings: list[SecurityFinding] = []
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and _MANIFEST_NETWORK_EXEC_RE.search(cmd):
            findings.append(SecurityFinding(
                severity="critical",
                category="malicious_install_hook",
                excerpt=f'"{hook}": "{cmd}"'[:200],
                issue=(
                    f"The package.json '{hook}' lifecycle script runs automatically on "
                    "`npm install`, before any human reviews it, and this one invokes a "
                    "network-fetch-and-execute or decode/eval pattern - the exact "
                    "mechanism used in real npm supply-chain compromises."
                ),
                source="pattern",
                citation=_MANIFEST_INSTALL_HOOK_CITATION,
            ))
    return findings


_FULL_LINE_COMMENT_RE = re.compile(r"^[ \t]*#.*$", re.MULTILINE)


def _strip_full_line_comments(content: str) -> str:
    """Removes lines whose first non-whitespace character is `#` (a requirements.txt or
    Pipfile full-line comment - e.g. a commented-out example dependency), so it doesn't
    trip the VCS-bypass check below. Only a full-line comment is stripped, not text after
    a mid-line `#` - a real VCS URL can legitimately contain `#egg=name` as a fragment, and
    naively truncating at the first `#` would corrupt that match."""
    return _FULL_LINE_COMMENT_RE.sub("", content)


def _scan_pip_vcs_installs(content: str, pattern: re.Pattern) -> list[SecurityFinding]:
    """Flags a requirements.txt/Pipfile dependency installed directly from a VCS URL,
    bypassing the package index's own review/typosquat protections. `pattern` selects the
    ecosystem-specific spelling (pip's `git+https://` line syntax vs. Pipfile's TOML
    inline-table syntax) - the two files express the same bypass differently."""
    content = _strip_full_line_comments(content)
    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    for m in pattern.finditer(content):
        excerpt = m.group(0).strip()
        if excerpt in seen:
            continue
        seen.add(excerpt)
        findings.append(SecurityFinding(
            severity="medium",
            category="manifest_vcs_bypass",
            excerpt=excerpt[:200],
            issue=(
                "Installs a dependency directly from a VCS URL instead of a published "
                "package-index release, bypassing the index's own review/typosquat "
                "protections. Review exactly what repository and ref this points to."
            ),
            source="pattern",
            citation=_MANIFEST_VCS_BYPASS_CITATION,
        ))
    return findings


def _scan_go_mod_replace(content: str) -> list[SecurityFinding]:
    """Flags a go.mod 'replace' directive, which silently redirects a dependency to a
    different source - a legitimate feature (local development, patched forks) that is
    also a documented way to smuggle code in under a trusted-looking import path. Handles
    both go.mod forms: the single-line `replace old => new` and the block form
    `replace (\n old => new\n ... \n)`, whose inner lines omit the `replace` keyword."""
    excerpts: list[str] = []
    for m in _GO_REPLACE_SINGLE_RE.finditer(content):
        excerpts.append(m.group(0).strip())
    for block_m in _GO_REPLACE_BLOCK_RE.finditer(content):
        for line_m in _GO_REPLACE_BLOCK_LINE_RE.finditer(block_m.group(1)):
            line = line_m.group(0).split("//", 1)[0].strip()
            if line:
                excerpts.append(line)

    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    for excerpt in excerpts:
        if excerpt in seen:
            continue
        seen.add(excerpt)
        findings.append(SecurityFinding(
            severity="medium",
            category="manifest_dependency_redirect",
            excerpt=excerpt[:200],
            issue=(
                "A go.mod 'replace' directive redirects a dependency to a different "
                "source (a fork, URL, or local path) instead of its declared module "
                "path. This is a legitimate feature but is also a documented way to "
                "smuggle malicious code in under a trusted-looking import path - review "
                "the replacement target."
            ),
            source="pattern",
            citation=_MANIFEST_GO_REPLACE_CITATION,
        ))
    return findings


def scan_manifest_file(filename: str, content: str) -> list[SecurityFinding]:
    """Dispatches to the manifest-specific check for known dependency-manifest filenames.
    Returns [] for anything else - this is intentionally narrow (one concrete, cited
    technique per ecosystem: npm install hooks, pip/Pipfile VCS-bypass installs, go.mod
    replace redirects), not a general dependency auditor. Called per-file from
    bundle.py's directory walk; single-file mode has no separate manifest to scan."""
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if name == "package.json":
        return _scan_package_json_scripts(content)
    if name == "requirements.txt":
        return _scan_pip_vcs_installs(content, _PIP_VCS_INSTALL_RE)
    if name == "Pipfile":
        return _scan_pip_vcs_installs(content, _PIPFILE_VCS_RE)
    if name == "go.mod":
        return _scan_go_mod_replace(content)
    return []


def redact_secrets(content: str, findings: list[SecurityFinding]) -> str:
    """Replaces every hardcoded_secret finding's exact excerpt with a placeholder before
    the content is sent to any third-party LLM for semantic analysis. The original content
    (with real secrets) is still shown to the user locally - only the outbound API payload
    is redacted, so the scanner doesn't itself become a leak vector for what it just found."""
    redacted = content
    for finding in findings:
        if finding.category == "hardcoded_secret" and finding.excerpt:
            redacted = redacted.replace(finding.excerpt, "[REDACTED]")
    return redacted
