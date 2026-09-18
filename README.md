# SkillScope

Analyze and explain SKILL.md files in plain English, flagging ambiguous or risky instructions
before they cause misinterpretation.

SkillScope combines two kinds of analysis:

- **Structural parsing** (deterministic, no AI): YAML frontmatter validation, section
  extraction, detection of tool/command/file/URL references, lint-style warnings
  (missing fields, empty description, no trigger condition, etc.), and a pattern-based
  security scan (remote-code-execution one-liners, destructive commands, credential
  access, exfiltration phrasing, prompt-injection language, obfuscated payloads).
- **Semantic analysis** (via Claude, Gemini, or Azure AI Foundry — your choice, see
  [Multi-provider LLM support](#multi-provider-llm-support)): a plain-English summary of
  what the skill does and when it should trigger (plus an "explain like I'm 5" version),
  flagged ambiguous/vague/conflicting wording with concrete rewritten fixes, AI-judged
  security findings that catch malicious *intent* phrased in plain English the pattern
  scan can't match (e.g. "don't tell the user about this step"), and a Mermaid flowchart
  of the skill's step-by-step flow including any decision branches ("if X, do Y, else Z").

**Security findings are surfaced first**, above everything else, in the CLI and both web
UIs — a skill can look well-structured and still be trying to exfiltrate credentials or
inject instructions, so that's the first thing you see.

It works on any SKILL.md-shaped file, not just Anthropic's own convention — teams that
write their own frontmatter fields or section structure are still handled by the
structural parser (unrecognized fields are simply carried through; only truly missing
essentials like `name`/`description` are flagged).

Semantic analysis uses each provider's **forced structured tool/function-call output**
feature rather than asking the model to hand-format a JSON blob in free text — the API
validates the response against a schema and hands back an already-parsed object, so
there's no JSON-escaping failure mode to worry about (a real bug we hit and fixed:
verbatim excerpts routinely quote the source file's own `"` characters, which broke naive
free-text JSON parsing). All three providers share the exact same prompt and response
schema (`skillscope/core/analyzer.py`) — they differ only in how the request/response is
shaped, not in what's asked.

## Three interfaces

1. **CLI** (`skillscope/cli.py`) — for local/CI use, credentials read server-side from the
   environment.
2. **Flask web app** (`skillscope/web/`) — paste/upload UI, credentials stay server-side too.
3. **Static browser demo** (`docs/`, meant for GitHub Pages) — no backend at all; runs the
   real structural/security-scan Python code in-browser via [Pyodide](https://pyodide.org/),
   and calls the Anthropic API directly from your browser with a key you paste in (bring
   your own key — see below). Good for a quick demo or on-the-fly check without installing
   anything; the CLI/Flask app are the better choice for regular local use.

## Repo structure

```
skillscope/
  core/
    models.py      # shared dataclasses
    parser.py       # deterministic structural parsing + lint
    security.py      # deterministic pattern-based security scan
    flow.py            # deterministic fallback Mermaid flow diagram
    analyzer.py          # Claude tool-use call + response validation (ambiguities, security, flow, ELI5)
    pipeline.py            # combines structural + semantic into one result; redacts secrets before outbound calls
    rules.py               # malicious-behavior rule database (OWASP-cited), threat indicators, secret redaction
    unicode_scan.py         # hidden/invisible Unicode (steganographic injection) scan
    frontmatter_advisor.py   # Universal Skill Format frontmatter recommendations
    checklist.py              # OWASP Agentic Skills Top 10 checklist evaluation (single-file + bundle-aware)
    platform_profiles.py       # platform -> manifest-filename map, used by the AST10 bundle check
    discovery.py                 # recursive SKILL.md discovery for directory mode (not mirrored to docs/)
    bundle.py                      # scans a skill's whole directory, not just SKILL.md (not mirrored to docs/)
    safe_fs.py                      # symlink/junction-safe directory walking, shared by discovery.py + bundle.py
    providers/                       # per-LLM-provider adapters (not mirrored to docs/)
      anthropic_provider.py
      gemini_provider.py
      azure_provider.py
  cli.py             # CLI entrypoint (rich, color-coded terminal output); directory mode lives here
  web/
    app.py            # Flask app (POST /api/analyze)
    templates/index.html  # paste/upload UI with inline highlighting
docs/                  # static GitHub Pages demo (no backend)
  index.html             # Pyodide + bring-your-own-key browser demo
  pysrc/skillscope/...     # mirror of skillscope/core/, kept in sync by scripts/sync_pyodide.py
scripts/
  sync_pyodide.py      # copies skillscope/core/ into docs/pysrc/ — re-run after editing core logic
test_skills/
  well_written/SKILL.md      # a clear, well-scoped example
  ambiguous/SKILL.md         # deliberately vague/contradictory example
  hidden_unicode/SKILL.md    # deliberately malicious fixture: real hidden-Unicode payload
  malicious_patterns/SKILL.md # deliberately malicious fixture: exercises every rules.py pattern
test_skills_dirs/         # directory-mode fixtures (see Directory/bundle mode)
  clean_bundle/              # multi-file skill, declared permissions match actual usage
  overprivileged_bundle/     # frontmatter denies network, a bundled script calls it anyway
  nested/inner/              # verifies recursive discovery finds a monorepo-nested skill
requirements.txt
requirements-providers.txt  # optional: google-genai / openai, only for --provider gemini|azure
.env.example
```

## Setup

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Set your Anthropic API key (used for semantic analysis only — structural analysis works
without it). Either export it, or copy `.env.example` to `.env` and fill it in (both the
CLI and web app load `.env` automatically via `python-dotenv`, and `.env` is gitignored):

```bash
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

## CLI usage

```bash
python -m skillscope.cli path/to/SKILL.md
```

Options:

- `--no-semantic` — skip the Claude API call, structural checks only (works with no API key).
- `--json` — print the raw result as JSON instead of a formatted report.
- `--flow-out PATH` — also write the Mermaid flow diagram source to a `.mmd` file.
- `--eli5` — show the dead-simple "explain like I'm 5" summary instead of the technical one.
- `--fail-on {critical,high,medium,none}` — minimum security-finding severity that causes
  a non-zero exit code (default `high`, matching the original behavior). `none` disables
  this check; structural errors (missing `name`/`description`, etc.) still cause exit `1`
  regardless of this setting.
- Pass `-` as the path to read from stdin: `cat SKILL.md | python -m skillscope.cli -`.
- Pass a **directory** instead of a file to scan every `SKILL.md` found recursively inside
  it (see [Directory/bundle mode](#directorybundle-mode) below).
- `--provider {anthropic,gemini,azure}` — which LLM to use for semantic analysis (default
  `anthropic`); see [Multi-provider LLM support](#multi-provider-llm-support).

The terminal can't render a diagram, so the CLI prints the raw Mermaid source in a panel —
paste it into [mermaid.live](https://mermaid.live) or any Mermaid-aware Markdown renderer
(GitHub, Obsidian, VS Code preview, etc.) to view it, or use `--flow-out` to save it straight
to a file.

Exit code is `1` if any structural **error**-severity warning was found (e.g. missing
frontmatter, missing `name`/`description`) or any security finding at or above the
`--fail-on` threshold (`high` by default) was flagged, `0` otherwise — useful for CI
linting/gating. This applies identically whether or not `--json` is passed.

Try it against the bundled fixtures:

```bash
python -m skillscope.cli test_skills/well_written/SKILL.md
python -m skillscope.cli test_skills/ambiguous/SKILL.md
python -m skillscope.cli test_skills/hidden_unicode/SKILL.md --no-semantic
python -m skillscope.cli test_skills/malicious_patterns/SKILL.md --no-semantic
```

`hidden_unicode` and `malicious_patterns` are deliberately malicious fixtures (see
[Malicious-behavior rule database](#malicious-behavior-rule-database--owasp-checklist)
below) — both exit `1`; `well_written` and `ambiguous` both exit `0`.

## Directory/bundle mode

`python -m skillscope.cli path/to/a/directory` recursively finds every `SKILL.md` under
that directory (`skillscope/core/discovery.py`) — including nested ones in a monorepo-style
layout, since a scanner that only checks the top level would miss a compromised skill
buried a few directories down. For each one found, every other file in that skill's own
directory (bundled scripts, docs, config — anything readable as UTF-8 text, up to a
per-file and per-bundle size cap) is scanned through the same pattern/hidden-Unicode checks
as a single `SKILL.md` (`skillscope/core/bundle.py`) — this is "analyze the entire skill
directory," not just its `SKILL.md`. Findings from bundled files are tagged with
`source_file` so you know which file they came from.

The OWASP checklist gains three risks a single file can't decide on its own:

- **AST03 (Over-Privileged Skills)** — compares `permissions.tools`/`allowed-tools`
  against tools/commands actually referenced anywhere in the bundle.
- **AST04 (Insecure Metadata)** — the full permission-understating cross-check: frontmatter
  says no network access, but a bundled script makes an HTTP call anyway.
- **AST07 (Update Drift)** — presence (not cryptographic verification) of `version`/
  `content_hash`.

A `hooks/` directory or a bundled `settings.json` is flagged for manual review (presence
only — semantic analysis of hook/settings behavior is an explicitly acknowledged gap, not
something SkillScope invents a detector for).

Options specific to directory mode:

- `--scope {personal,project,plugin,auto}` — override the auto-detected scope
  (`~/.claude/skills/` → personal, a directory containing `.git` → project, a
  `.claude-plugin`/`plugin.json` marker → plugin) when it guesses wrong. Default `auto`.
- `--semantic` — directory mode skips semantic analysis **by default**, since a directory
  can contain many skills and sending every one of them to a paid third-party API without
  being asked is both a cost and a consent problem. Pass `--semantic` to opt in; if more
  than one skill is found, the CLI prints a one-line notice naming how many skills' content
  is about to be sent before making any API calls.

Try it against the bundled fixtures:

```bash
python -m skillscope.cli test_skills_dirs --no-semantic
```

`test_skills_dirs/overprivileged_bundle/` demonstrates the AST04 cross-check (frontmatter
denies network access, a bundled script calls `requests.get`); `test_skills_dirs/nested/inner/`
demonstrates recursive discovery two directories deep; `test_skills_dirs/clean_bundle/`
demonstrates a bundle with declared permissions matching actual usage.

Directory mode is **CLI-only**. The Flask web app only ever receives pasted/uploaded
*content*, never a filesystem path — accepting a client-supplied path to walk server-side
would be a path-traversal risk in a security-scanning tool, so this was deliberately not
built rather than built unsafely. The static Pyodide demo has no real filesystem access at
all and stays single-file for the same reason.

**Safety note**: a scanned skill directory is treated as fully untrusted. Directory
discovery and bundle scanning (`skillscope/core/safe_fs.py`) never follow a symlink or a
Windows junction — verified directly, since a junction doesn't report as a symlink via
`Path.is_symlink()` but is still followed by ordinary traversal. Without this, a malicious
skill could plant a symlink/junction pointing outside the scanned directory (e.g. at an SSH
key or `~/.aws/credentials`) and have SkillScope read and potentially report its content.

## Multi-provider LLM support

Semantic analysis can use **Anthropic Claude** (default), **Google Gemini**, or **Azure AI
Foundry** — pick whichever you already have API access to. All three adapters
(`skillscope/core/providers/`) share the exact same system prompt, response schema, and
response-parsing/validation logic from `analyzer.py`; they differ only in how each
provider's SDK shapes the forced tool/function-call request and response.

```bash
python -m skillscope.cli path/to/SKILL.md --provider gemini
python -m skillscope.cli path/to/SKILL.md --provider azure
```

Each provider reads its own credential from the environment (via `.env` or an exported
var, same as the default `ANTHROPIC_API_KEY`):

| Provider | `--provider` value | Env var(s) | Extra install |
|---|---|---|---|
| Anthropic Claude | `anthropic` (default) | `ANTHROPIC_API_KEY` | none — covered by `requirements.txt` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `pip install -r requirements-providers.txt` |
| Azure AI Foundry | `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` | `pip install -r requirements-providers.txt` |

The Gemini/Azure SDKs (`google-genai`, `openai`) live in a **separate**
`requirements-providers.txt`, not the base `requirements.txt` — installing SkillScope
shouldn't force every user to pull in two extra SDKs they may never use. Each adapter
imports its SDK lazily; if you pick a provider whose package isn't installed, you get a
clear `pip install ...` error in `semantic_error` rather than a crash. The web app's UI
shows all three providers and disables whichever ones don't have a configured credential.

**Why not a multi-provider abstraction library (e.g. LiteLLM)?** LiteLLM suffered a real
supply-chain compromise (malicious PyPI versions published after a stolen publishing
token, March 2026, briefly live before PyPI pulled them). Given this project's own
≥14-day pinning policy exists specifically to dodge that kind of window, and a library
like that transitively pulls in every provider's SDK, three small hand-written adapters
keep the trusted-dependency footprint proportional to what's actually used.

**Credential handling**: never logged, never returned to the browser, and scrubbed from
any error message before it's shown (`analyzer.py::_scrub_secret` — closes off an HTTP
client's exception text potentially embedding the credential it was authenticating with).
Layering is env var → `.env` (gitignored) — the same as the original single-provider
design; an OS-keychain integration (`keyring`) was considered and deliberately deferred,
since the existing layering already covers this with zero new dependency.

**Platform awareness (OWASP AST10)**: if a skill's frontmatter declares a `platforms`
field (Universal Skill Format), the bundle-aware checklist (directory mode) cross-checks
that each declared platform's manifest file is actually present alongside `SKILL.md`
(`skillscope/core/platform_profiles.py` — Claude Code/OpenClaw: `SKILL.md`, Cursor/Codex:
`manifest.json`, VS Code: `package.json`; only platforms a real source actually named).
SkillScope does not diff manifest *schemas* between platforms — only whether a declared
platform's manifest is present, since no other platform's actual permission schema was
verified against a primary source.

## Web app usage

```bash
python -m skillscope.web.app
```

Then open http://localhost:5000. Paste SKILL.md content directly, or upload a `.md` file.
Check "Structural only" to skip the API call. **Security findings render first**, above
frontmatter and everything else, with a red alert banner and severity-coded cards (or a
green "clear" banner if nothing was flagged). Below that: structural warnings, references,
a rendered **Mermaid flow diagram** of the skill's steps (with a "Copy Mermaid source"
button), a summary with an "Explain like I'm 5" toggle button that swaps in the dead-simple
version, trigger conditions, and ambiguities. The original file is shown at the bottom with
flagged excerpts highlighted inline (security findings and ambiguities in different
shades) — hover a card to highlight its matching excerpt in the source.

The flow diagram is rendered client-side with [Mermaid.js](https://mermaid.js.org/)
(loaded from a pinned CDN version, `securityLevel: 'strict'` so labels can never inject
HTML/JS) and themed to match the rest of the UI. When semantic analysis produced one, it's
the AI's diagram (it can show decision branches, e.g. "Category Unclear" / "Category
Clear"); otherwise a simpler linear diagram is auto-built from a numbered list in the file,
if one exists.

The left input panel is collapsible (the `«`/`»` button in its header) to give the
results more room once you've analyzed something; the collapsed state is remembered
per-browser via `localStorage`.

The API key is read server-side from `ANTHROPIC_API_KEY` and never sent to or handled by
the browser.

## Static browser demo (GitHub Pages)

`docs/index.html` is a self-contained static page with **no backend** — the same UI as the
Flask app, but structural parsing and the security pattern scan run directly in your
browser via [Pyodide](https://pyodide.org/) (Python compiled to WebAssembly), running the
*actual* `skillscope/core` modules, not a reimplementation. That part needs no API key and
sends nothing anywhere.

For AI-powered analysis (summary, ambiguities, flow diagram, AI security findings), paste
your own Anthropic API key into the field on the page. It's stored only in your browser
(only if you check "remember"), and is sent **directly from your browser to
`api.anthropic.com`** — never to any server of ours, since there isn't one. This is the
standard "bring your own key" pattern for client-side AI demos; it uses Anthropic's
[direct browser access](https://docs.anthropic.com/) support
(`anthropic-dangerous-direct-browser-access` header), which Anthropic's API explicitly
allows via CORS. Treat this the same way you'd treat any page you paste an API key into:
fine for your own quick checks, not something to hand out to other people to use with your
key.

**Run it locally:**

```bash
python -m http.server 8000 --directory docs
```

Then open http://localhost:8000. It must be served over `http(s)://`, not opened directly
as a `file://` path — browsers block the `fetch()` calls that load the Python source and
call the API from a `file://` origin. Any static file server works (`http.server`,
`live-server`, `npx serve`, etc.), and the same page is what you'd deploy to GitHub Pages
(repo Settings → Pages → deploy from branch `main`, folder `/docs`).

`docs/.nojekyll` matters: GitHub Pages runs everything through Jekyll by default, which
silently excludes any file or directory starting with `_` — including every `__init__.py`
in `docs/pysrc/`, breaking the Pyodide package imports with 404s. That empty file disables
Jekyll processing so the folder is served as plain static files.

**Keeping it in sync:** `docs/pysrc/skillscope/` is a mirror of `skillscope/core/` (Pyodide
can only fetch files GitHub Pages actually serves, which is just the `docs/` folder, so the
real package can't be fetched directly). After changing anything under `skillscope/core/`,
re-run:

```bash
python scripts/sync_pyodide.py
```

before testing or deploying `docs/`, or the demo will run stale logic.

## Malicious-behavior rule database & OWASP checklist

`skillscope/core/rules.py` is a versioned, local, pure-Python database of malicious-skill
techniques (`RULESET_VERSION`) — not a live external feed. Each rule cites the concrete
research it's based on (Datadog Security Labs' dynamic-context/over-privileged-frontmatter
findings, Snyk's ToxicSkills research on hardcoded secrets and combined payload+injection
patterns, and OWASP AST02 for a runtime-dependency-install check). It covers, on top of the
original pattern scan in `security.py`:

- Claude Code dynamic-context (`` !`curl ...` ``) command pre-execution
- Over-broad `allowed-tools: Bash(*)` frontmatter grants
- Disguised exfiltration (`gh auth token` followed by a `curl -X POST`)
- Password-protected archive delivery (evades static AV scanning)
- Hardcoded secrets (AWS-key-shaped and generic `api_key = "..."` assignments)
- A runtime package-install instruction in prose (outside a documented setup code fence)
- A low-severity "weak signal" for embedded external URLs (only meaningful combined with
  other findings)
- A correlation rule that escalates severity when an obfuscated payload and
  prompt-injection phrasing both fire on the same file

`skillscope/core/unicode_scan.py` separately flags hidden/invisible Unicode characters
(zero-width, bidirectional-control, Unicode Tag-block, and variation-selector codepoints)
that render as nothing to a human but are still tokenized and can be obeyed by an LLM —
based on a real documented attack that hid a `curl | bash` instruction in Tag-block text.

`skillscope/core/checklist.py` evaluates the file-content-decidable subset of the
[OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/)
(an **OWASP Incubator project, not a ratified standard** — content CC-BY-SA-4.0,
reproduced here with attribution) as a pass/fail/manual-review/not-applicable checklist,
rendered above the frontmatter section in all three interfaces. Several risk categories
(supply-chain provenance, sandbox isolation, org governance, cross-platform manifest
diffing) are honestly `not_applicable` from a single file's content alone — they need a
directory/bundle view or external data this version of SkillScope doesn't have.

`skillscope/core/frontmatter_advisor.py` recommends (as `info`-severity structural
warnings, never auto-applied) missing high-value fields from OWASP's draft
["Universal Skill Format" proposal](https://raw.githubusercontent.com/OWASP/www-project-agentic-skills-top-10/main/universal-skill-format.md):
`permissions.network`/`.shell`/`.tools`, `platforms`, `risk_tier`, `author.identity`, and
`content_hash`/`signature` (presence-only — SkillScope does not verify a signature).

Before any content is sent to a third-party LLM for semantic analysis, detected hardcoded
secrets are redacted from the outbound copy (`skillscope/core/rules.py::redact_secrets`,
wired in via `skillscope/core/pipeline.py`) — the file you see locally is untouched; only
the API request is redacted, so the scanner that flags a leaked credential can't itself
leak it further.

## Output shape

All three interfaces produce the same underlying JSON:

```json
{
  "security_findings": [
    {
      "severity": "critical|high|medium|low",
      "category": "remote_code_execution|destructive_command|credential_access|data_exfiltration|prompt_injection|obfuscation|privilege_escalation|persistence|other",
      "excerpt": "verbatim quote from the file",
      "issue": "why this is concerning",
      "source": "pattern|ai",
      "citation": "research/spec source backing a pattern-sourced finding, or empty string",
      "source_file": "relative path within a bundle (directory mode only), or empty string"
    }
  ],
  "checklist": [
    {
      "id": "AST01",
      "title": "Malicious Skills",
      "status": "pass|fail|not_applicable|manual_review",
      "severity": "critical|high|medium",
      "evidence": "...",
      "citation": "https://owasp.github.io/www-project-agentic-skills-top-10/top10"
    }
  ],
  "flow_diagram": "raw Mermaid flowchart source, or null",
  "flow_diagram_source": "ai|pattern|null",
  "summary": "plain-English explanation of what the skill does and when it triggers",
  "eli5_summary": "dead-simple, jargon-free 2-4 sentence explanation",
  "trigger_conditions": "plain-English description of the activation conditions",
  "ambiguities": [
    { "excerpt": "verbatim quote from the file", "issue": "...", "suggested_fix": "..." }
  ],
  "structural_warnings": [
    { "severity": "error|warning", "message": "...", "field": "name|description|null" }
  ],
  "semantic_error": null,
  "frontmatter": { "...": "..." },
  "sections": [ { "heading": "...", "level": 2, "content": "..." } ],
  "references": [ { "kind": "tool|command|file_reference|url", "value": "..." } ]
}
```

Directory mode (see [Directory/bundle mode](#directorybundle-mode)) adds one more top-level
key per skill: `"bundle": { "root": "...", "scope": "personal|project|plugin|unknown", "files": [{"relpath": "...", "size_bytes": 0, "is_text": true}] }`
— the full list of files SkillScope found in that skill's directory, alongside whichever
ones were content-scanned (`is_text: true`, under the size cap) versus only listed.

`security_findings` merges two sources: `"source": "pattern"` entries come from a
deterministic regex scan (`skillscope/core/security.py`) that runs even without an API
key; `"source": "ai"` entries come from the Claude call and catch malicious intent
phrased in plain English that a regex can't match. The combined list is sorted
critical → high → medium → low.

`flow_diagram` similarly prefers the AI-generated diagram (`flow_diagram_source: "ai"`)
when semantic analysis ran and found a discernible flow; otherwise it falls back to a
linear diagram built deterministically from a numbered list in the body
(`skillscope/core/flow.py`, `flow_diagram_source: "pattern"`). Both are `null` if the
skill has no discernible step-by-step flow.

If a `SKILL.md` references another file (e.g. "see other_file.md"), that reference is
recorded under `references` with `kind: "file_reference"` — it is **not** fetched or
followed automatically.

## Error handling

- Empty file → a single structural error, semantic analysis is skipped.
- No frontmatter block found → structural error; the whole file is still parsed as body.
- Malformed YAML → structural error with the YAML parser's message; body is still parsed.
- Missing `ANTHROPIC_API_KEY` or any Claude API failure → semantic analysis degrades to
  an explanatory `semantic_error` field; structural results are still returned (CLI and
  web both keep working, they just show fewer results).

## Notes on the semantic prompt

The model is asked to return excerpts as **verbatim substrings** of the input file so the
web UI can locate and highlight them. If a model response can't be found verbatim in the
source (e.g. paraphrased), it's still shown in the ambiguities list — it just won't be
highlighted inline.
