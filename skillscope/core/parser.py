"""Deterministic, non-AI structural parsing of SKILL.md content.

Handles: YAML frontmatter extraction, section/body splitting, detection of
tool/command/file/url references, and structural lint warnings. Works on
arbitrary SKILL.md-shaped files, not just a single fixed schema, since teams
write their own conventions on top of the frontmatter + markdown body idea.
"""

from __future__ import annotations

import re

import yaml

from .flow import build_fallback_diagram
from .models import Reference, Section, StructuralAnalysis, StructuralWarning
from .security import scan as scan_security

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?\n)---\s*\n?", re.DOTALL)
HEADER_RE = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)

CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
URL_RE = re.compile(r"https?://[^\s)>\]\"']+")
FILE_PATH_RE = re.compile(
    r"\b[\w][\w\-./]*\.(?:md|py|js|ts|tsx|jsx|json|ya?ml|sh|txt|csv|html?|toml|cfg|ini)\b",
    re.IGNORECASE,
)
SEE_OTHER_RE = re.compile(
    r"\b(?:see|refer to|reference)\s+(?:also\s+)?[`\"']?([\w\-./]+\.\w+)[`\"']?",
    re.IGNORECASE,
)
COMMAND_VERB_RE = re.compile(
    r"^(git|npm|pip|pip3|python3?|node|curl|wget|docker|make|cargo|go|bash|sh|yarn|pnpm)\b"
)

KNOWN_TOOLS = {
    "Bash", "Read", "Write", "Edit", "Grep", "Glob", "Agent", "Task",
    "WebFetch", "WebSearch", "NotebookEdit", "TodoWrite", "MultiEdit",
    "ExitPlanMode", "AskUserQuestion", "Artifact",
}

TRIGGER_PHRASES = [
    "use when", "use this when", "use this skill when", "trigger:",
    "trigger when", "invoke when", "use for", "use if", "call this when",
    "activate when", "applies when",
]

MIN_DESCRIPTION_LEN = 20
MAX_DESCRIPTION_LEN = 1024


def parse_frontmatter(content: str) -> tuple[dict, str, str | None]:
    """Returns (frontmatter_dict, remaining_body, error_message)."""
    match = FRONTMATTER_RE.match(content)
    if not match:
        return {}, content, "no_frontmatter"

    raw_yaml = match.group(1)
    body = content[match.end():]
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return {}, body, f"Malformed YAML frontmatter: {exc}"

    if data is None:
        return {}, body, "Frontmatter block is empty"
    if not isinstance(data, dict):
        return {}, body, "Frontmatter must be a YAML mapping (key: value pairs)"

    return data, body, None


def extract_sections(body: str) -> list[Section]:
    headers = list(HEADER_RE.finditer(body))
    if not headers:
        stripped = body.strip()
        if not stripped:
            return []
        return [Section(heading="(body)", level=0, content=stripped)]

    sections: list[Section] = []
    preamble = body[: headers[0].start()].strip()
    if preamble:
        sections.append(Section(heading="(preamble)", level=0, content=preamble))

    for i, header_match in enumerate(headers):
        level = len(header_match.group(1))
        heading = header_match.group(2).strip()
        start = header_match.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        section_body = body[start:end].strip()
        sections.append(Section(heading=heading, level=level, content=section_body))

    return sections


def extract_references(body: str) -> list[Reference]:
    references: list[Reference] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, context: str = "") -> None:
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        references.append(Reference(kind=kind, value=value, context=context))

    for m in URL_RE.finditer(body):
        add("url", m.group(0))

    for m in SEE_OTHER_RE.finditer(body):
        add("file_reference", m.group(1), context="referenced but not auto-followed")

    for m in CODE_SPAN_RE.finditer(body):
        token = m.group(1).strip()
        if not token or " " in token and not COMMAND_VERB_RE.match(token):
            if COMMAND_VERB_RE.match(token):
                add("command", token)
            continue
        if token in KNOWN_TOOLS:
            add("tool", token)
        elif COMMAND_VERB_RE.match(token):
            add("command", token)
        elif FILE_PATH_RE.search(token):
            add("file_reference", token)

    for m in FILE_PATH_RE.finditer(body):
        add("file_reference", m.group(0))

    for tool in KNOWN_TOOLS:
        if re.search(rf"\b{re.escape(tool)}\b", body):
            add("tool", tool)

    return references


def _has_trigger_language(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in TRIGGER_PHRASES)


def lint(frontmatter: dict, frontmatter_error: str | None, body: str) -> list[StructuralWarning]:
    warnings: list[StructuralWarning] = []

    if frontmatter_error == "no_frontmatter":
        warnings.append(StructuralWarning(
            severity="error",
            message="No YAML frontmatter block found (expected a '---' delimited block at the top of the file).",
        ))
    elif frontmatter_error:
        warnings.append(StructuralWarning(severity="error", message=frontmatter_error))

    if not frontmatter_error or frontmatter_error == "no_frontmatter":
        name = frontmatter.get("name")
        if not name or not str(name).strip():
            warnings.append(StructuralWarning(
                severity="error", message="Missing required frontmatter field 'name'.", field="name",
            ))

        description = frontmatter.get("description")
        if description is None or not str(description).strip():
            warnings.append(StructuralWarning(
                severity="error",
                message="Missing or empty required frontmatter field 'description'.",
                field="description",
            ))
        else:
            desc = str(description).strip()
            if len(desc) < MIN_DESCRIPTION_LEN:
                warnings.append(StructuralWarning(
                    severity="warning",
                    message=f"Description is very short ({len(desc)} chars) - likely too vague for reliable triggering.",
                    field="description",
                ))
            elif len(desc) > MAX_DESCRIPTION_LEN:
                warnings.append(StructuralWarning(
                    severity="warning",
                    message=f"Description is very long ({len(desc)} chars) - consider tightening it for reliable triggering.",
                    field="description",
                ))

            if not _has_trigger_language(desc) and not _has_trigger_language(body):
                warnings.append(StructuralWarning(
                    severity="warning",
                    message="No explicit trigger condition detected (e.g. 'Use when...', 'Trigger:'). "
                            "It may be unclear to a reader (or to Claude) when this skill should activate.",
                ))

    if not body.strip():
        warnings.append(StructuralWarning(
            severity="error", message="No instructional body content found after the frontmatter.",
        ))

    return warnings


def parse_skill(content: str) -> StructuralAnalysis:
    if not content or not content.strip():
        return StructuralAnalysis(
            frontmatter={},
            frontmatter_error="empty_file",
            body="",
            sections=[],
            references=[],
            warnings=[StructuralWarning(severity="error", message="The file is empty.")],
            security_findings=[],
        )

    frontmatter, body, frontmatter_error = parse_frontmatter(content)
    sections = extract_sections(body)
    references = extract_references(body)
    warnings = lint(frontmatter, frontmatter_error, body)
    security_findings = scan_security(content)
    flow_diagram = build_fallback_diagram(body)

    return StructuralAnalysis(
        frontmatter=frontmatter,
        frontmatter_error=frontmatter_error,
        body=body,
        sections=sections,
        references=references,
        warnings=warnings,
        security_findings=security_findings,
        flow_diagram=flow_diagram,
    )
