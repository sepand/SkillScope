# SkillScope

Analyze and explain SKILL.md files in plain English, flagging ambiguous or risky instructions
before they cause misinterpretation.

SkillScope combines two kinds of analysis:

- **Structural parsing** (deterministic, no AI): YAML frontmatter validation, section
  extraction, detection of tool/command/file/URL references, lint-style warnings
  (missing fields, empty description, no trigger condition, etc.), and a pattern-based
  security scan (remote-code-execution one-liners, destructive commands, credential
  access, exfiltration phrasing, prompt-injection language, obfuscated payloads).
- **Semantic analysis** (via the Claude API): a plain-English summary of what the skill
  does and when it should trigger (plus an "explain like I'm 5" version), flagged
  ambiguous/vague/conflicting wording with concrete rewritten fixes, AI-judged security
  findings that catch malicious *intent* phrased in plain English the pattern scan can't
  match (e.g. "don't tell the user about this step"), and a Mermaid flowchart of the
  skill's step-by-step flow including any decision branches ("if X, do Y, otherwise Z").

**Security findings are surfaced first**, above everything else, in the CLI and both web
UIs — a skill can look well-structured and still be trying to exfiltrate credentials or
inject instructions, so that's the first thing you see.

It works on any SKILL.md-shaped file, not just Anthropic's own convention — teams that
write their own frontmatter fields or section structure are still handled by the
structural parser (unrecognized fields are simply carried through; only truly missing
essentials like `name`/`description` are flagged).

Semantic analysis uses Claude's **tool-use (structured output)** feature rather than
asking the model to hand-format a JSON blob in free text — the API validates the response
against a schema and hands back an already-parsed object, so there's no JSON-escaping
failure mode to worry about (a real bug we hit and fixed: verbatim excerpts routinely
quote the source file's own `"` characters, which broke naive free-text JSON parsing).

## Three interfaces

1. **CLI** (`skillscope/cli.py`) — for local/CI use, `ANTHROPIC_API_KEY` read server-side.
2. **Flask web app** (`skillscope/web/`) — paste/upload UI, API key stays server-side too.
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
    pipeline.py            # combines structural + semantic into one result
  cli.py             # CLI entrypoint (rich, color-coded terminal output)
  web/
    app.py            # Flask app (POST /api/analyze)
    templates/index.html  # paste/upload UI with inline highlighting
docs/                  # static GitHub Pages demo (no backend)
  index.html             # Pyodide + bring-your-own-key browser demo
  pysrc/skillscope/...     # mirror of skillscope/core/, kept in sync by scripts/sync_pyodide.py
scripts/
  sync_pyodide.py      # copies skillscope/core/ into docs/pysrc/ — re-run after editing core logic
test_skills/
  well_written/SKILL.md   # a clear, well-scoped example
  ambiguous/SKILL.md      # deliberately vague/contradictory example
requirements.txt
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
- Pass `-` as the path to read from stdin: `cat SKILL.md | python -m skillscope.cli -`.

The terminal can't render a diagram, so the CLI prints the raw Mermaid source in a panel —
paste it into [mermaid.live](https://mermaid.live) or any Mermaid-aware Markdown renderer
(GitHub, Obsidian, VS Code preview, etc.) to view it, or use `--flow-out` to save it straight
to a file.

Exit code is `1` if any structural **error**-severity warning was found (e.g. missing
frontmatter, missing `name`/`description`) or any **critical**/**high**-severity security
finding was flagged, `0` otherwise — useful for CI linting/gating.

Try it against the bundled fixtures:

```bash
python -m skillscope.cli test_skills/well_written/SKILL.md
python -m skillscope.cli test_skills/ambiguous/SKILL.md
```

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
      "source": "pattern|ai"
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
