"""SkillScope CLI: analyze a SKILL.md file and print a plain-English, color-coded report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core.discovery import DiscoveredSkill, discover_skill_dirs
from .core.pipeline import run_analysis, run_bundle_analysis

load_dotenv()

SEVERITY_STYLE = {"error": "bold red", "warning": "yellow", "info": "cyan"}
SEVERITY_LABEL = {"error": "STRUCTURAL ERROR", "warning": "STRUCTURAL WARNING", "info": "INFO"}

SEC_SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan"}
SEC_BORDER_STYLE = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}

CHECKLIST_STATUS_STYLE = {
    "pass": "bold green", "fail": "bold red", "manual_review": "yellow", "not_applicable": "grey50",
}
CHECKLIST_STATUS_LABEL = {
    "pass": "PASS", "fail": "FAIL", "manual_review": "MANUAL REVIEW", "not_applicable": "N/A",
}

# Ordered weakest-to-strongest; --fail-on picks the minimum severity that fails the build.
FAIL_ON_LEVELS = {
    "critical": {"critical"},
    "high": {"critical", "high"},
    "medium": {"critical", "high", "medium"},
    "none": set(),
}


def read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def render_security_findings(console: Console, findings: list) -> None:
    if not findings:
        console.print(Panel(
            "No malicious content, intent, or suspicious scripts detected.",
            title="Security Findings", border_style="green",
        ))
        return

    for f in findings:
        sev = f.get("severity", "medium")
        body = Text()
        body.append(f" {sev.upper()} ", style=SEC_SEVERITY_STYLE.get(sev, "bold yellow"))
        body.append(f" [{f.get('category', 'other')}] ", style="bold")
        body.append(f"{f.get('issue', '')}\n\n")
        body.append("Excerpt: ", style="bold")
        body.append(f"\"{f.get('excerpt', '')}\"", style="italic")
        title = f"{sev.upper()} - Security Finding"
        console.print(Panel(body, title=title, border_style=SEC_BORDER_STYLE.get(sev, "yellow")))


def render_checklist(console: Console, checklist: list) -> None:
    if not checklist:
        return
    ctable = Table(show_header=True, header_style="bold", box=None)
    ctable.add_column("ID", width=8)
    ctable.add_column("Title", width=28)
    ctable.add_column("Status", width=16)
    ctable.add_column("Evidence")
    for c in checklist:
        status = c.get("status", "")
        style = CHECKLIST_STATUS_STYLE.get(status, "white")
        label = CHECKLIST_STATUS_LABEL.get(status, status.upper())
        # Wrap every cell in Text() rather than passing raw strings: "evidence" embeds
        # verbatim excerpts from the (untrusted) scanned file, and a plain str passed to
        # add_row() is re-parsed as Rich markup - Text() does not re-parse, matching the
        # safe pattern already used by render_security_findings() above.
        ctable.add_row(Text(c.get("id", "")), Text(c.get("title", "")), Text(label, style=style), Text(c.get("evidence", "")))
    console.print(Panel(
        ctable,
        title="OWASP Agentic Skills Top 10 checklist",
        subtitle="[grey50]OWASP Incubator project, draft/unratified - not a certified standard[/grey50]",
        border_style="blue",
    ))


def render_flow_diagram(console: Console, flow_diagram: str | None, source: str | None, flow_out: str | None) -> None:
    if not flow_diagram:
        console.print(Panel(
            "No step-by-step flow was identified for this skill.",
            title="Flow Diagram", border_style="grey50",
        ))
        return

    label = "AI-generated, includes decision branches" if source == "ai" else "auto-generated from a numbered list"
    body = Text(flow_diagram, style="cyan")
    console.print(Panel(
        body,
        title="Flow Diagram (Mermaid)",
        subtitle=f"[grey50]{label} - paste into https://mermaid.live or a Mermaid-aware Markdown renderer to view[/grey50]",
        border_style="blue",
    ))

    if flow_out:
        with open(flow_out, "w", encoding="utf-8") as f:
            f.write(flow_diagram + "\n")
        console.print(f"[grey50]Flow diagram written to {flow_out}[/grey50]")


def render(console: Console, source_label: str, result: dict, flow_out: str | None = None, eli5: bool = False) -> None:
    console.print(Panel(f"[bold]{source_label}[/bold]", style="bold blue", expand=False))

    render_security_findings(console, result.get("security_findings") or [])
    render_checklist(console, result.get("checklist") or [])

    fm = result.get("frontmatter") or {}
    if fm:
        fm_table = Table(show_header=False, box=None, padding=(0, 1))
        for k, v in fm.items():
            fm_table.add_row(f"[bold]{k}[/bold]", str(v))
        console.print(Panel(fm_table, title="Frontmatter", border_style="grey50"))

    warnings = result.get("structural_warnings") or []
    if warnings:
        wtable = Table(show_header=True, header_style="bold", box=None)
        wtable.add_column("Severity", width=18)
        wtable.add_column("Message")
        for w in warnings:
            sev = w.get("severity", "warning")
            style = SEVERITY_STYLE.get(sev, "white")
            wtable.add_row(Text(SEVERITY_LABEL.get(sev, sev.upper()), style=style), w.get("message", ""))
        console.print(Panel(wtable, title="Structural Warnings", border_style="yellow"))
    else:
        console.print(Panel("No structural issues found.", border_style="green"))

    refs = result.get("references") or []
    if refs:
        rtable = Table(show_header=True, header_style="bold", box=None)
        rtable.add_column("Kind", width=16)
        rtable.add_column("Value")
        for r in refs:
            rtable.add_row(r.get("kind", ""), r.get("value", ""))
        console.print(Panel(rtable, title=f"References ({len(refs)})", border_style="grey50"))

    render_flow_diagram(console, result.get("flow_diagram"), result.get("flow_diagram_source"), flow_out)

    if result.get("semantic_error"):
        console.print(Panel(result["semantic_error"], title="Semantic Analysis", border_style="red"))
        return

    if eli5 and result.get("eli5_summary"):
        console.print(Panel(result["eli5_summary"], title="Summary (explain like I'm 5)", border_style="magenta"))
    elif result.get("summary"):
        console.print(Panel(result["summary"], title="Summary (plain English)", border_style="green"))

    if result.get("trigger_conditions"):
        console.print(Panel(result["trigger_conditions"], title="When it should trigger", border_style="blue"))

    ambiguities = result.get("ambiguities") or []
    if ambiguities:
        for i, a in enumerate(ambiguities, 1):
            body = Text()
            body.append("Excerpt: ", style="bold")
            body.append(f"\"{a.get('excerpt', '')}\"\n", style="italic red")
            body.append("Issue: ", style="bold")
            body.append(f"{a.get('issue', '')}\n")
            body.append("Suggested fix: ", style="bold")
            body.append(a.get("suggested_fix", ""), style="green")
            console.print(Panel(body, title=f"Ambiguity #{i}", border_style="red"))
    else:
        console.print(Panel("No ambiguous or conflicting wording flagged.", border_style="green"))


def render_bundle_summary(console: Console, rows: list[tuple[DiscoveredSkill, dict]]) -> None:
    stable = Table(show_header=True, header_style="bold", box=None)
    stable.add_column("Skill")
    stable.add_column("Scope", width=10)
    stable.add_column("Pass", width=6)
    stable.add_column("Fail", width=6)
    stable.add_column("Manual", width=8)
    stable.add_column("Highest finding", width=16)
    for discovered, result in rows:
        checklist = result.get("checklist") or []
        pass_n = sum(1 for c in checklist if c.get("status") == "pass")
        fail_n = sum(1 for c in checklist if c.get("status") == "fail")
        manual_n = sum(1 for c in checklist if c.get("status") == "manual_review")
        findings = result.get("security_findings") or []
        highest = findings[0].get("severity", "none") if findings else "none"
        style = SEC_SEVERITY_STYLE.get(highest, "grey50") if highest != "none" else "green"
        stable.add_row(
            Text(str(discovered.skill_dir)), Text(discovered.scope),
            Text(str(pass_n)), Text(str(fail_n)), Text(str(manual_n)),
            Text(highest, style=style),
        )
    console.print(Panel(
        stable, title=f"Directory scan summary ({len(rows)} skill(s) found)", border_style="blue",
    ))


def run_directory_mode(console: Console, root: Path, args: argparse.Namespace) -> int:
    discovered = discover_skill_dirs(root, scope_override=args.scope)
    if not discovered:
        console.print(f"[yellow]No SKILL.md files found under {root}[/yellow]")
        return 0

    if len(discovered) > 1 and args.semantic:
        console.print(
            f"[yellow]{len(discovered)} skills found; each skill's (secret-redacted) "
            "content will be sent to the configured LLM provider for semantic analysis. "
            "Re-run without --semantic to skip.[/yellow]"
        )

    fail_severities = FAIL_ON_LEVELS[args.fail_on]
    exit_code = 0
    summary_rows: list[tuple[DiscoveredSkill, dict]] = []
    json_results = []

    for d in discovered:
        try:
            analysis = run_bundle_analysis(
                d.skill_dir, scope=d.scope, skip_semantic=not args.semantic, provider=args.provider,
            )
        except (OSError, ValueError) as exc:
            console.print(f"[bold red]Error reading {d.path}:[/bold red] {exc}")
            exit_code = 1
            continue

        result = analysis.to_dict()
        has_errors = any(w.get("severity") == "error" for w in result.get("structural_warnings") or [])
        has_severe = any(
            f.get("severity") in fail_severities for f in result.get("security_findings") or []
        )
        if has_errors or has_severe:
            exit_code = 1

        if args.json:
            json_results.append({"skill_dir": str(d.skill_dir), "scope": d.scope, "result": result})
        else:
            render(console, str(d.path), result, eli5=args.eli5)
        summary_rows.append((d, result))

    if args.json:
        print(json.dumps(json_results, indent=2))
    else:
        render_bundle_summary(console, summary_rows)

    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillscope",
        description="Analyze a SKILL.md file: structural lint plus AI-powered plain-English explanation "
                    "and ambiguity detection.",
    )
    parser.add_argument("path", help="Path to a SKILL.md file, a directory to scan recursively, or '-' to read from stdin.")
    parser.add_argument("--no-semantic", action="store_true", help="Skip the Claude API call; structural checks only.")
    parser.add_argument(
        "--semantic", action="store_true",
        help="Directory mode only: enable semantic analysis for each discovered skill "
             "(sends each skill's content to the LLM). Off by default in directory mode, "
             "since a directory can contain many skills and this has a real API cost.",
    )
    parser.add_argument(
        "--scope", choices=["personal", "project", "plugin", "auto"], default="auto",
        help="Directory mode only: override the auto-detected scope heuristic "
             "(personal/project/plugin) for every discovered skill.",
    )
    parser.add_argument(
        "--provider", choices=["anthropic", "gemini", "azure"], default="anthropic",
        help="LLM provider for semantic analysis (default: anthropic). Reads "
             "ANTHROPIC_API_KEY / GEMINI_API_KEY / AZURE_OPENAI_API_KEY respectively; "
             "azure also needs AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT set.",
    )
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report.")
    parser.add_argument("--flow-out", metavar="PATH", help="Also write the Mermaid flow diagram source to this file (e.g. flow.mmd).")
    parser.add_argument("--eli5", action="store_true", help="Show the dead-simple 'explain like I'm 5' summary instead of the technical one.")
    parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "none"], default="high",
        help="Minimum security-finding severity that causes a non-zero exit code "
             "(default: high, matching prior behavior). 'none' disables this check; "
             "structural errors (e.g. missing name/description) still cause exit 1 "
             "regardless of this setting.",
    )
    args = parser.parse_args(argv)

    console = Console()

    if args.path != "-" and Path(args.path).is_dir():
        return run_directory_mode(console, Path(args.path), args)

    try:
        content = read_input(args.path)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] file not found: {args.path}")
        return 1
    except OSError as exc:
        console.print(f"[bold red]Error reading file:[/bold red] {exc}")
        return 1

    analysis = run_analysis(content, skip_semantic=args.no_semantic, provider=args.provider)
    result = analysis.to_dict()

    has_errors = any(w.get("severity") == "error" for w in result.get("structural_warnings") or [])
    fail_severities = FAIL_ON_LEVELS[args.fail_on]
    has_severe_security_findings = any(
        f.get("severity") in fail_severities for f in result.get("security_findings") or []
    )
    exit_code = 1 if (has_errors or has_severe_security_findings) else 0

    if args.json:
        print(json.dumps(result, indent=2))
        return exit_code

    render(console, args.path, result, flow_out=args.flow_out, eli5=args.eli5)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
