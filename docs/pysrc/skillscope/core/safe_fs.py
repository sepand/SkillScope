"""Symlink-safe directory walking, shared by discovery.py and bundle.py.

Both modules are pointed at untrusted, potentially attacker-controlled directories (a
downloaded/cloned skill someone wants vetted before installing). `pathlib.Path.rglob()`
follows symlinked directories by default on every Python version this project supports
(3.10-3.12; only 3.13+ gained an opt-out via `recurse_symlinks=False`, not something we can
rely on here) — a skill directory could contain a symlink or, on Windows, a directory
**junction** (creatable without elevated privileges, unlike a real symlink) pointing
outside the scanned root. Left unchecked, that causes an arbitrary file elsewhere on disk
(an SSH key, `~/.aws/credentials`, another project's `.env`) to be read, its content
pattern-scanned, and a matching excerpt surfaced in a report — or, with `--semantic`, sent
to a third-party LLM.

Two independent checks are needed, not one: `Path.is_symlink()` catches a real symlink but
**does not detect a Windows junction** (verified empirically - a junction's reparse tag
differs from a symlink's, so `is_symlink()` returns False for it even though `iterdir()`/
`is_dir()` transparently follow it). `Path.resolve()`, however, follows both a symlink and
a junction to their real target - so a resolved-path containment check (does the entry
still live under the scanned root once resolved?) catches what `is_symlink()` misses. This
module uses both: reject any real symlink outright (also closes off a same-tree symlink
loop), and reject anything whose resolved path escapes the root (closes the junction gap).
A `visited` set additionally guards against a cycle from any other reparse-point trick.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator


def walk_files(root: Path, skip_dir_names: frozenset[str] = frozenset()) -> Iterator[Path]:
    """Yields every regular file under `root` whose full path resolves to somewhere under
    `root` and that isn't itself a symlink. Directories whose name is in `skip_dir_names`
    are pruned entirely (a performance/noise filter, not the security boundary - the
    containment check above is what actually keeps traversal inside `root`). `root` itself
    is the caller-supplied, trusted scan root; only what's found *inside* it is untrusted."""
    root = Path(root)
    real_root = root.resolve()
    visited_dirs = {real_root}
    stack = [root]

    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue

        for entry in entries:
            if entry.is_symlink():
                continue  # a real symlink - never follow, in or out of the tree

            try:
                real_entry = entry.resolve()
            except OSError:
                continue

            if real_entry != real_root and not real_entry.is_relative_to(real_root):
                continue  # resolves outside the scanned root (e.g. a junction) - skip

            try:
                is_dir = entry.is_dir()
            except OSError:
                continue

            if is_dir:
                if entry.name in skip_dir_names or real_entry in visited_dirs:
                    continue
                visited_dirs.add(real_entry)
                stack.append(entry)
                continue

            try:
                if entry.is_file():
                    yield entry
            except OSError:
                continue
