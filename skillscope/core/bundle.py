"""Builds a SkillBundle: every file in a skill's own directory, each text file scanned
through the same content-layer checks single-file mode uses. This is the concrete
implementation of "analyze the entire skill directory, not just SKILL.md" and of OWASP
AST08's mandate to scan the code layer and the natural-language layer independently - each
bundled script is its own code-layer unit, SKILL.md's prose is the natural-language layer.

Not mirrored into docs/pysrc/ - needs real filesystem access (see discovery.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import SecurityFinding
from .parser import extract_references
from .safe_fs import walk_files
from .security import scan as scan_security
from .unicode_scan import scan_hidden_unicode

# Extensions treated as text and content-scanned. Anything else is listed (name/size) but
# not opened - SkillScope can't meaningfully pattern-scan a binary, and trying invites
# encoding-error noise for no security benefit. Reviewers should still see it listed so
# they know what wasn't inspected.
_TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
    ".sh", ".bash", ".ps1", ".rb", ".go", ".rs", ".toml", ".cfg", ".ini", ".html", ".css",
}

# A SKILL.md bundle's own scripts are small; skip content-scanning anything larger rather
# than loading it fully into memory, and list it as "not inspected" instead.
_MAX_FILE_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024

# Matches discovery.py's _EXCLUDED_DIR_NAMES - a skill bundling a virtualenv or build
# output shouldn't have that vendored tree walked any more than node_modules should.
_SKIPPED_DIR_NAMES = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox",
})

# Used by checklist.py's AST04 permission-understating cross-check: frontmatter says no
# network access, but a bundled file makes one anyway - the concrete example OWASP AST04
# itself gives.
_NETWORK_CALL_RE = re.compile(
    r"\b(curl|wget)\b|requests\.(get|post|put|delete|patch)\s*\(|fetch\s*\(",
    re.IGNORECASE,
)

_HOOK_GAP_CITATION = (
    "Acknowledged research gap: neither Datadog Security Labs' dynamic-context article "
    "nor Snyk's ToxicSkills research (both reviewed while building this feature) "
    "deep-dived hook-directory or settings.json-override semantics."
)


@dataclass
class BundleFile:
    relpath: str
    size_bytes: int
    is_text: bool


@dataclass
class SkillBundle:
    root: str
    scope: str
    skill_md_relpath: str
    files: list[BundleFile] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    # Tool/command names referenced anywhere in the bundle's text files (SKILL.md and
    # bundled scripts alike) - used by checklist.py's AST03 declared-vs-used cross-check.
    used_tools: list[str] = field(default_factory=list)
    # True if any text file in the bundle makes a network call (curl/wget/HTTP request) -
    # used by checklist.py's AST04 permission-understating cross-check.
    uses_network: bool = False


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in _TEXT_EXTENSIONS


def build_bundle(
    skill_dir: Path, scope: str = "unknown", max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
) -> SkillBundle:
    """Walks `skill_dir` (a single skill's own directory - not recursing into a nested
    separate skill, that's discovery.py's job) via safe_fs.walk_files(), which never
    follows a symlink, so a file/directory symlinked outside `skill_dir` is neither read
    nor listed. Scans every text file's content through the same checks single-file mode
    uses. Every finding is tagged with the relative file it came from via
    `SecurityFinding.source_file`."""
    skill_dir = Path(skill_dir)
    files: list[BundleFile] = []
    findings: list[SecurityFinding] = []
    used_tools: set[str] = set()
    total_bytes = 0
    saw_hook_or_settings = False
    saw_network_call = False

    for path in sorted(walk_files(skill_dir, skip_dir_names=_SKIPPED_DIR_NAMES)):
        relparts = path.relative_to(skill_dir).parts
        relpath = str(path.relative_to(skill_dir))
        try:
            size = path.stat().st_size
        except OSError:
            continue

        total_bytes += size
        is_text = _is_text_file(path)
        files.append(BundleFile(relpath=relpath, size_bytes=size, is_text=is_text))

        if path.name == "settings.json" or "hooks" in relparts:
            saw_hook_or_settings = True

        if not is_text or size > _MAX_FILE_BYTES or total_bytes > max_total_bytes:
            continue  # listed above, but not content-scanned - too large or not text

        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # unreadable as UTF-8 text - listed, not scanned

        # SKILL.md itself is already fully analyzed separately by run_analysis() (which
        # also runs frontmatter recommendations, threat indicators, and the single-file
        # checklist) - re-scanning it here would duplicate every one of its findings.
        # Everything else about it (size, listing, tool/network usage for the aggregate
        # checks below) is still tracked.
        if relpath != "SKILL.md":
            file_findings = scan_security(content) + scan_hidden_unicode(content)
            for finding in file_findings:
                finding.source_file = relpath
            findings.extend(file_findings)

        for ref in extract_references(content):
            if ref.kind in ("tool", "command"):
                used_tools.add(ref.value.lower())

        if _NETWORK_CALL_RE.search(content):
            saw_network_call = True

    if saw_hook_or_settings:
        findings.append(SecurityFinding(
            severity="medium",
            category="unreviewed_hook_or_settings",
            excerpt="(presence flag only - no specific line)",
            issue=(
                "This skill bundles a hooks/ directory or a settings.json override. "
                "SkillScope only flags presence here, not semantics - see citation. "
                "Review these files manually; the absence of other findings elsewhere in "
                "this bundle does not mean they're safe."
            ),
            source="pattern",
            citation=_HOOK_GAP_CITATION,
        ))

    return SkillBundle(
        root=str(skill_dir), scope=scope, skill_md_relpath="SKILL.md",
        files=files, findings=findings, used_tools=sorted(used_tools),
        uses_network=saw_network_call,
    )
