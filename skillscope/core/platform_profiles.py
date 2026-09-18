"""Platform-to-manifest-filename mapping for OWASP AST10 (Cross-Platform Reuse).

Filenames only - sourced from the OWASP Universal Skill Format proposal's own stated goal
of unifying these formats (raw.githubusercontent.com/OWASP/www-project-agentic-skills-top-10/
main/universal-skill-format.md, fetched directly while researching this feature): Claude
Code (SKILL.md), OpenClaw (SKILL.md), Cursor/Codex (manifest.json), VS Code (package.json).
Nothing about each platform's actual permission/security schema is claimed or implemented
here - only the filename a scanner would look for, which is all AST10's bundle-aware check
(checklist.py::evaluate_bundle_checks) needs: whether a declared platform's manifest is
actually present alongside SKILL.md.

(An earlier draft of this feature's plan listed "copilot"/"gemini" as platform choices, but
no manifest filename for either was ever verified against a real source - only Claude Code,
OpenClaw, Cursor/Codex, and VS Code were. Listing invented filenames for the other two would
violate the "do not invent" constraint this feature was built under, so they're left out.)
"""

from __future__ import annotations

PLATFORM_MANIFESTS: dict[str, str] = {
    "claude": "SKILL.md",
    "openclaw": "SKILL.md",
    "cursor": "manifest.json",
    "vscode": "package.json",
}

# Manifest filenames worth checking bundle.files for, deduplicated (some platforms share
# a filename - e.g. "manifest.json" isn't unique to one platform).
KNOWN_MANIFEST_FILENAMES: frozenset[str] = frozenset(PLATFORM_MANIFESTS.values())
