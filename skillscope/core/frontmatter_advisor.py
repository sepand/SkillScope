"""Recommends missing frontmatter fields based on the OWASP Agentic Skills Top 10
project's "Universal Skill Format" proposal.

Status, verified by directly fetching the raw spec in the same session this module was
written: OWASP Incubator project, draft/proposal status (parent project is v0.0.0, "active
development") - not a ratified standard. SkillScope stays read-only: these are surfaced as
`info`-severity recommendations only, never written back into the user's file.
"""

from __future__ import annotations

from typing import Any, Optional

from .models import StructuralWarning

_USF_CITATION = (
    "OWASP Agentic Skills Top 10 project's Universal Skill Format proposal "
    "(raw.githubusercontent.com/OWASP/www-project-agentic-skills-top-10/main/"
    "universal-skill-format.md - OWASP Incubator project, draft/proposal status, content "
    "CC-BY-SA-4.0)."
)


def _get(frontmatter: dict, *path: str) -> Optional[Any]:
    node: Any = frontmatter
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def recommend_frontmatter(frontmatter: dict) -> list[StructuralWarning]:
    """Reports missing high-value Universal Skill Format fields. Only recommends fields
    with a clear, direct security rationale (permissions/provenance/integrity) - not every
    field the spec defines (e.g. `changelog.*`, `requires.*` are skipped as lower-value, to
    avoid recommending fields just because they exist)."""
    if not isinstance(frontmatter, dict) or not frontmatter:
        return []

    warnings: list[StructuralWarning] = []

    def recommend(field_path: str, message: str) -> None:
        warnings.append(StructuralWarning(severity="info", message=message, field=field_path))

    if _get(frontmatter, "permissions", "network") is None:
        recommend(
            "permissions.network",
            "Consider adding a `permissions.network` field (Universal Skill Format "
            'proposal): deny-by-default is recommended, e.g. `permissions.network.deny: '
            '"*"` unless this skill genuinely needs network access. ' + _USF_CITATION,
        )

    if _get(frontmatter, "permissions", "shell") is None:
        recommend(
            "permissions.shell",
            "Consider adding a `permissions.shell` boolean field (Universal Skill Format "
            "proposal) to make shell-execution capability explicit rather than implicit. "
            + _USF_CITATION,
        )

    if _get(frontmatter, "permissions", "tools") is None:
        recommend(
            "permissions.tools",
            "Consider adding an explicit `permissions.tools` whitelist (Universal Skill "
            "Format proposal) instead of a broad grant like `allowed-tools: Bash(*)`. "
            + _USF_CITATION,
        )

    if _get(frontmatter, "platforms") is None:
        recommend(
            "platforms",
            "Consider adding a `platforms` field listing which agent platforms this skill "
            "targets (Universal Skill Format proposal) - this is what lets a scanner "
            "cross-check that porting to another platform didn't drop security metadata. "
            + _USF_CITATION,
        )

    if _get(frontmatter, "risk_tier") is None:
        recommend(
            "risk_tier",
            "Consider adding a `risk_tier` field (Universal Skill Format proposal) to "
            "support automated governance/approval policies. " + _USF_CITATION,
        )

    author_identity = _get(frontmatter, "author", "identity")
    if author_identity is None:
        recommend(
            "author.identity",
            "Consider adding `author.identity` (Universal Skill Format proposal) for "
            "verifiable provenance. " + _USF_CITATION,
        )
    elif _get(frontmatter, "author", "signing_key") is None:
        recommend(
            "author.signing_key",
            "author.identity is present but author.signing_key is not - consider adding "
            "it for cryptographic verification (Universal Skill Format proposal). "
            + _USF_CITATION,
        )

    if _get(frontmatter, "content_hash") is None and _get(frontmatter, "signature") is None:
        recommend(
            "content_hash",
            "Consider adding `content_hash` and `signature` fields (Universal Skill "
            "Format proposal) for integrity verification. SkillScope only checks for "
            "their presence here - it does not verify a signature. " + _USF_CITATION,
        )

    return warnings
