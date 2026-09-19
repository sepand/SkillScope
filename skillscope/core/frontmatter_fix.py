"""Turns a missing-field recommendation (frontmatter_advisor.py) into something the user
can act on directly: a copy-pasteable YAML snippet, or a whole corrected SKILL.md.

SkillScope stays read-only - build_corrected_skill_md() never writes to disk itself and
never touches the caller's original file; it only returns corrected text for the caller
(CLI/web/Pyodide) to show or offer as a download.

The corrected file is produced by text-splicing the original frontmatter block, not by a
yaml.safe_load -> yaml.safe_dump round-trip (which would alphabetize keys and silently
drop comments). Every splice is re-parsed and checked against the original frontmatter
before being kept; a field that can't be safely merged is appended as a commented
suggestion instead of risking a corrupted file (see build_corrected_skill_md's docstring).
"""

from __future__ import annotations

import re
from typing import Optional

import yaml

from .models import FrontmatterFixResult, StructuralWarning

# See parser.py::FRONTMATTER_RE for why [ \t]* (not \s*) precedes each required \n - \s*\n
# has many ways to split a run of blank lines, a polynomial-backtracking shape on
# adversarial input.
FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?", re.DOTALL)

_TEMPLATE_INDENT = "  "

# One canonical block per field frontmatter_advisor.py recommends. Keys match the `field`
# path StructuralWarning already carries for each recommendation - no new fields invented.
FIELD_SNIPPETS: dict[str, str] = {
    "permissions.network": 'permissions:\n  network:\n    deny: "*"',
    "permissions.shell": "permissions:\n  shell: false",
    "permissions.tools": "permissions:\n  tools:\n    - Read\n    - Grep",
    "platforms": "platforms:\n  - claude",
    "risk_tier": "risk_tier: low",
    "author.identity": 'author:\n  identity: "your-name-or-org"',
    "author.signing_key": 'author:\n  signing_key: "your-public-key-fingerprint"',
    "content_hash": 'content_hash: "sha256:..."\nsignature: "..."',
}


def suggest_field_snippet(field_path: str, frontmatter: dict) -> str:
    """A copy-pasteable snippet for one missing field. If the field's parent key already
    exists as a mapping, shows just the sub-block to merge in by hand instead of a
    duplicate top-level key (the full canonical block is still what gets used internally
    for the auto-merge in build_corrected_skill_md)."""
    template = FIELD_SNIPPETS.get(field_path)
    if template is None:
        return ""

    parts = field_path.split(".")
    parent = parts[0]
    if len(parts) == 1 or not isinstance(frontmatter.get(parent), dict):
        return template

    lines = template.splitlines()[1:]  # drop the top-level `parent:` line
    dedented = [
        line[len(_TEMPLATE_INDENT):] if line.startswith(_TEMPLATE_INDENT) else line
        for line in lines
    ]
    return f"# add under your existing `{parent}:` block\n" + "\n".join(dedented)


def _detect_child_indent(lines: list[str], key_line_idx: int) -> Optional[str]:
    for line in lines[key_line_idx + 1:]:
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        indent = line[: len(line) - len(stripped)]
        return indent or None  # no indent = next top-level key, i.e. an empty/flow block
    return None


def _splice_field(yaml_text: str, field_path: str, frontmatter: dict) -> Optional[str]:
    """Returns spliced YAML text, or None if it's not safe to attempt (caller falls back
    to a commented suggestion block instead)."""
    template = FIELD_SNIPPETS.get(field_path)
    if template is None:
        return None

    top_key = field_path.split(".", 1)[0]

    if not isinstance(frontmatter.get(top_key), dict):
        # Parent doesn't exist (or isn't a mapping) yet - append the whole block fresh.
        return yaml_text.rstrip("\n") + "\n" + template.rstrip("\n") + "\n"

    lines = yaml_text.splitlines()
    key_re = re.compile(rf"^{re.escape(top_key)}:\s*(#.*)?$")
    key_idx = next((i for i, line in enumerate(lines) if key_re.match(line)), None)
    if key_idx is None:
        return None  # can't find the block form of an existing mapping key - don't guess

    existing_indent = _detect_child_indent(lines, key_idx)
    if existing_indent is None:
        return None  # empty or flow-style (`key: {...}`) mapping - too risky to splice into

    sub_lines = template.splitlines()[1:]  # drop the top-level `top_key:` line
    reindented = [
        existing_indent + line[len(_TEMPLATE_INDENT):] if line.startswith(_TEMPLATE_INDENT)
        else existing_indent + line.lstrip()
        for line in sub_lines
    ]

    insert_at = key_idx + 1
    new_lines = lines[:insert_at] + reindented + lines[insert_at:]
    result = "\n".join(new_lines)
    return result + "\n" if yaml_text.endswith("\n") else result


def _as_comment_block(snippet: str) -> str:
    return "\n".join(f"# {line}" if line else "#" for line in snippet.splitlines())


def build_corrected_skill_md(
    raw_content: str, frontmatter: dict, warnings: list[StructuralWarning]
) -> FrontmatterFixResult:
    """Splices every missing-field recommendation in `warnings` into a corrected copy of
    `raw_content`'s frontmatter block, field by field. After each splice, the result is
    re-parsed and every key already in `frontmatter` must still round-trip to its original
    value - if it doesn't (or the splice couldn't be attempted at all), that one field is
    NOT applied; instead its snippet is appended as a `#`-commented suggestion at the end
    of the frontmatter block, and its path is recorded in `unmerged_fields`. This keeps a
    partially-unmergeable result honest and safe rather than silently corrupting the file.
    """
    fields = [w.field for w in warnings if w.field and w.field in FIELD_SNIPPETS]

    match = FRONTMATTER_RE.match(raw_content)
    if not match:
        return FrontmatterFixResult(content=raw_content, applied_fields=[], unmerged_fields=fields)

    original_yaml = match.group(1)
    rest = raw_content[match.end():]

    current_yaml = original_yaml
    applied: list[str] = []
    unmerged: list[str] = []
    comment_blocks: list[str] = []

    # `working_view` evolves as fields are applied (so a later permissions.* splice sees
    # the permissions: block a prior one just added, instead of re-appending a duplicate
    # top-level key); `frontmatter` itself stays the fixed baseline the safety check below
    # verifies against, so an earlier successful splice can't be silently undone later.
    working_view = dict(frontmatter)

    for field_path in fields:
        candidate = _splice_field(current_yaml, field_path, working_view)
        if candidate is not None:
            try:
                new_data = yaml.safe_load(candidate)
            except yaml.YAMLError:
                new_data = None
            if isinstance(new_data, dict) and all(
                key in new_data and new_data[key] == value for key, value in frontmatter.items()
            ):
                current_yaml = candidate
                working_view = new_data
                applied.append(field_path)
                continue

        unmerged.append(field_path)
        comment_blocks.append(_as_comment_block(FIELD_SNIPPETS[field_path]))

    if comment_blocks:
        header = "# --- SkillScope: suggested additions (could not be safely auto-merged) ---"
        current_yaml = current_yaml.rstrip("\n") + "\n" + header + "\n" + "\n".join(comment_blocks) + "\n"

    if not current_yaml.endswith("\n"):
        current_yaml += "\n"

    corrected = "---\n" + current_yaml + "---\n" + rest
    return FrontmatterFixResult(content=corrected, applied_fields=applied, unmerged_fields=unmerged)
