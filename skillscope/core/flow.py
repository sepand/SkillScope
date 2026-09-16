"""Deterministic fallback flow diagram: builds a simple linear Mermaid flowchart from a
top-level numbered list found in the skill body.

This is what's shown when semantic analysis hasn't run (no API key) or didn't produce a
diagram of its own — it can't detect branches/decisions the way the AI-generated version
can, but it still gives a readable at-a-glance sequence when the skill has an obvious
numbered list of steps.
"""

from __future__ import annotations

import re

_STEP_RE = re.compile(r"^[ \t]*(\d+)[.)][ \t]+(.+)$", re.MULTILINE)
_MD_STRIP_RE = re.compile(r"[`*_]")
_MAX_STEPS = 15
_MAX_LABEL_LEN = 70


def _clean_label(text: str) -> str:
    text = _MD_STRIP_RE.sub("", text).strip()
    text = text.replace('"', "'")
    text = re.sub(r"\s+", " ", text)
    if len(text) > _MAX_LABEL_LEN:
        text = text[: _MAX_LABEL_LEN - 3].rstrip() + "..."
    return text or "Step"


def build_fallback_diagram(body: str) -> str | None:
    matches = _STEP_RE.findall(body)
    if len(matches) < 2:
        return None

    steps = [_clean_label(text) for _, text in matches[:_MAX_STEPS]]
    truncated = len(matches) > _MAX_STEPS

    lines = ["flowchart TD", '    start(["Start"])']
    node_ids = []
    for i, label in enumerate(steps, 1):
        node_id = f"step{i}"
        node_ids.append(node_id)
        lines.append(f'    {node_id}["{label}"]')
    if truncated:
        lines.append('    more["...additional steps..."]')
        node_ids.append("more")
    lines.append('    done(["Done"])')

    chain = ["start"] + node_ids + ["done"]
    for a, b in zip(chain, chain[1:]):
        lines.append(f"    {a} --> {b}")

    return "\n".join(lines)
