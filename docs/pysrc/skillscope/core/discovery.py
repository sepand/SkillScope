"""Recursive discovery of SKILL.md files under a directory - the entry point for
directory/bundle-mode scanning (as opposed to single-file mode).

Not mirrored into docs/pysrc/ (see scripts/sync_pyodide.py) - like pipeline.py, this needs
real filesystem access (pathlib globbing, home-directory/`.git` lookups) that the static
Pyodide demo has no equivalent for and never calls.

Recursion is required, not optional: Claude Code auto-discovers `.claude/skills/` in
nested subfolders, so a single compromised package deep in a monorepo can smuggle in a
skill even if the repo root looks clean (Datadog Security Labs' "nested/monorepo skill
discovery" finding).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .safe_fs import walk_files

# Directories never worth descending into for skill discovery - version control internals,
# dependency/build output, and caches. Not a full `.gitignore` parser (that would need a
# new dependency like `pathspec`); this hardcoded list covers the common case at zero cost.
# (This is a performance/noise filter, not the security boundary - safe_fs.walk_files()
# never follows a symlink regardless of name, which is what actually keeps traversal
# inside the scanned root.)
_EXCLUDED_DIR_NAMES = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox",
})


@dataclass
class DiscoveredSkill:
    path: Path  # path to the SKILL.md file itself
    scope: str  # "personal" | "project" | "plugin" | "unknown"

    @property
    def skill_dir(self) -> Path:
        return self.path.parent


def _detect_scope(skill_md_path: Path) -> str:
    """Heuristic only - the `.claude-plugin`/`plugin.json` marker convention was not
    independently verified against Claude Code's own source, so `unknown` is a valid,
    honest outcome here, not a bug. Use --scope to override when this guesses wrong."""
    skill_dir = skill_md_path.parent

    try:
        personal_root = Path.home() / ".claude" / "skills"
        if skill_dir == personal_root or personal_root in skill_dir.parents:
            return "personal"
    except RuntimeError:
        pass  # home directory not resolvable in this environment - fall through

    for ancestor in [skill_dir, *skill_dir.parents]:
        if (ancestor / ".claude-plugin").is_dir() or (ancestor / "plugin.json").is_file():
            return "plugin"
        if (ancestor / ".git").exists():
            return "project"

    return "unknown"


def discover_skill_dirs(root: Path, scope_override: str | None = None) -> list[DiscoveredSkill]:
    """Recursively finds every real (non-symlink) SKILL.md under `root`, skipping the
    excluded directory names above. Never follows a symlink - see safe_fs.py - so a
    symlinked "SKILL.md" pointing outside `root` is simply never found, not partially
    trusted. `scope_override` (from the CLI's --scope flag) is used verbatim instead of the
    heuristic when the caller already knows the answer."""
    root = Path(root)
    discovered: list[DiscoveredSkill] = []
    for path in sorted(walk_files(root, skip_dir_names=_EXCLUDED_DIR_NAMES)):
        if path.name != "SKILL.md":
            continue
        scope = scope_override if scope_override and scope_override != "auto" else _detect_scope(path)
        discovered.append(DiscoveredSkill(path=path, scope=scope))
    return discovered
