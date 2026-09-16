"""Mirrors skillscope/core (and its __init__ files) into docs/pysrc/.

The GitHub Pages static demo (docs/index.html) runs the real analysis modules in-browser
via Pyodide instead of reimplementing parsing/security/flow logic in JavaScript. GitHub
Pages only serves the configured root (docs/), so the package needs a copy inside that
root. This script is the single place that copy is made — re-run it after editing
anything under skillscope/core/ (or skillscope/__init__.py) and before deploying/testing
the docs/ site, so the two don't drift apart.

Usage: python scripts/sync_pyodide.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "skillscope"
DEST_ROOT = REPO_ROOT / "docs" / "pysrc" / "skillscope"

# Only the modules Pyodide actually needs: pure-Python analysis logic with no heavy or
# native dependencies. analyzer.py's `import anthropic` is deferred inside a function we
# never call from the browser (the browser calls the Anthropic API directly via fetch),
# so analyzer.py loads fine without the anthropic package installed.
FILES = [
    "__init__.py",
    "core/__init__.py",
    "core/models.py",
    "core/parser.py",
    "core/security.py",
    "core/flow.py",
    "core/analyzer.py",
]


def main() -> None:
    if DEST_ROOT.exists():
        shutil.rmtree(DEST_ROOT)

    for rel in FILES:
        src = SRC_ROOT / rel
        dest = DEST_ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        print(f"copied {src.relative_to(REPO_ROOT)} -> {dest.relative_to(REPO_ROOT)}")

    print(f"\nSynced {len(FILES)} files into {DEST_ROOT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
