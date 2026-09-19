# Contributing to SkillScope

Thanks for considering a contribution. This document covers the conventions this project
has settled on — most of them exist for a concrete reason (a bug they prevent, a
consistency guarantee they preserve), explained inline rather than asserted.

## Before you start

- **Read the [README](README.md) first**, especially "Repo structure" and "Malicious-behavior
  rule database & OWASP checklist" — it covers the architecture and design decisions this
  file assumes you already know.
- **Open an issue before a large change.** Small fixes (a bug, a false positive, a wording
  correction) can go straight to a PR. Anything that adds a new detection category, a new
  input mode, or a new dependency should start as an issue so the design gets discussed
  before code gets written — this project has a strong "do not invent, do not bloat" bias,
  and it's cheaper to catch scope creep in a proposal than in a PR review.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env        # optional - only needed to test semantic (AI) analysis
```

See the README's [Setup](README.md#setup) section for the full walkthrough, including
multi-provider LLM setup (`requirements-providers.txt`).

## Testing: there is no test framework, and that's deliberate

This repo has no pytest suite, no CI test job, and no linter gate. Verification is done
via **documented CLI invocations against fixtures**, with an expected exit code:

```bash
python -m skillscope.cli test_skills/well_written --no-semantic --json    # expect exit 0
python -m skillscope.cli test_skills/malicious_patterns --no-semantic     # expect exit 1
python -m skillscope.cli test_skills_dirs --no-semantic                   # expect exit 0
```

If you add a detection rule or fix a bug, **add or extend a fixture** under `test_skills/`
(single-file) or `test_skills_dirs/` (directory/bundle mode) that demonstrates it, and
document the invocation + expected exit code in your PR description (README's own fixture
list is a template for the phrasing). `hidden_unicode/` and `malicious_patterns/` are
*deliberately* malicious fixtures — real payloads, on purpose, so the detectors have
something real to catch. Don't "fix" them if you notice they contain a real
zero-width-Unicode payload or a shell one-liner; that's the point.

### Test adversarially, not just the happy path

If you're adding or editing a regex-based detector (most of `rules.py`), test more than
"a malicious example fires" and "a clean example doesn't." Specifically check:

- **A commented-out version** of the malicious pattern (does your regex respect the file
  format's own comment syntax, or does it fire on dead code?)
- **Alternate syntax forms** the same underlying file format allows (e.g. a config format
  with both a single-line and a block form — missing one is a false negative, not a
  cosmetic gap)
- **A common legitimate pattern** that shares surface features with the malicious one (e.g.
  downloading a prebuilt binary via `curl` without piping it to a shell is normal; piping
  it to `bash` is not — a rule that can't tell the difference will be too noisy to trust)

This isn't hypothetical caution — every one of these categories has caused a real,
shipped false positive or false negative in this project's history. Test for them before
opening the PR, not after a reviewer finds them.

## Adding a rule to the malicious-behavior database (`rules.py`)

Every entry in `rules.py` carries a `citation` back to real, concrete research — a
security-labs writeup, a documented CVE/incident, an official spec. **Nothing is invented.**
If you can't point to a real source describing the technique, it doesn't belong in this
file as a standalone pattern; consider whether it fits better as a `low`-severity "weak
signal" (explicitly caveated as high-false-positive-rate) or whether it needs more
research first.

When citing the [OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/),
keep the existing framing intact: it is an **Incubator project, not a ratified standard**,
and its content is CC-BY-SA-4.0 — reproduce that context, don't imply certified/official
status.

## Cross-cutting things that will break silently if missed

These aren't style preferences — each one is a real failure mode with no test to catch it,
so it's on you (and your reviewer) to check by hand.

- **New `models.py` dataclass fields need a default.** The static Pyodide demo's JS glue
  constructs `SecurityFinding`/`SkillAnalysis`/etc. by keyword from Python; a non-defaulted
  new field throws there with nothing to catch it locally.
- **New heavy/optional imports must be deferred.** `analyzer.py`'s `import anthropic`
  happens inside the function that needs it, not at module scope, specifically so the
  module still loads under Pyodide (which can't import everything real Python can). Follow
  the same pattern for any new provider or dependency.
- **Any new filesystem-walking code must go through `safe_fs.py`**, not raw `pathlib`
  recursion. `Path.rglob()` follows symlinks and Windows junctions by default — `safe_fs.py`
  exists specifically to stop a scanned skill directory from reading something outside its
  own tree (an SSH key, `~/.aws/credentials`) via a symlink trick.
- **Editing a module that's mirrored into `docs/pysrc/` needs a re-sync.** Run
  `python scripts/sync_pyodide.py` after any change to a `skillscope/core/` module (check
  `scripts/sync_pyodide.py`'s `FILES` list to see what's mirrored) and commit the result
  alongside your source change — the static demo silently runs stale logic otherwise.
  **Adding a brand-new module** that needs to be mirrored requires updating it in *two*
  places, not one: `scripts/sync_pyodide.py`'s `FILES` list, and `docs/index.html`'s own
  `PY_FILES` list + its `fetch()` calls in `initPyodide()`.
- **The Flask web app and the static Pyodide demo are two near-identical files, kept in
  sync by hand.** A change to `skillscope/web/templates/index.html`'s rendering logic
  almost always needs the same change applied to `docs/index.html` at its own (usually
  offset) line numbers — don't assume line numbers match between the two files.
- **Secrets are redacted before any outbound LLM call, never before what's shown locally.**
  `rules.py::redact_secrets()` runs on the copy sent to a provider API
  (`pipeline.py::run_analysis()`), not on `SkillAnalysis.raw_content` — the user should
  always see their real file; only the network request is redacted. If you add a new
  secret-detection pattern, confirm it flows through this same redaction path.

## Dependency policy

- New dependencies are pinned to an **exact version, at least 14 days old** at the time of
  pinning (see the comment atop `requirements.txt`) — a deliberate delay against
  very-recently-published-package supply-chain risk (this isn't hypothetical: see the
  LiteLLM incident referenced in this project's design notes).
- Prefer zero new dependencies over one. Several features in this codebase were
  deliberately built with stdlib-only code (`json`, `re`, `pathlib`) specifically to avoid
  pulling in something heavier for a narrowly-scoped check.

## Commit and PR conventions

- Branch off `main`, one focused change per branch/PR.
- Write commit messages that explain *why*, not just *what* — especially for a bug fix,
  state what broke and what you verified after the fix (this project's own commit history
  is a good model to follow).
- Before opening a PR that touches `skillscope/core/` or either web frontend, run the
  regression fixtures above and mention the results in the PR description.
- For anything security-relevant (a new detection rule, a change to `safe_fs.py`, anything
  touching what gets sent to a third-party API), give your own diff a dedicated
  security-focused re-read before requesting review — walk through what an attacker-
  controlled skill file could contain and confirm your change doesn't open a new path for
  it to read, execute, or exfiltrate something. If you're using an AI coding assistant
  that has a security-review capability, running it against the diff is a good complement
  to this, not a replacement for it.

## Reporting a security issue

If you find a way to make SkillScope itself unsafe (not a gap in what it *detects* in
skills — an actual vulnerability in SkillScope's own code, like a path-traversal in the
folder-upload handling), please open a private security advisory on GitHub rather than a
public issue.

## License

By contributing, you agree your contribution is licensed under this project's
[MIT No Attribution license](LICENSE.md).
