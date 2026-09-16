"""SkillScope CLI: analyze a SKILL.md file and print a plain-English, color-coded report."""

from __future__ import annotations

import argparse
import json
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core.pipeline import run_analysis

load_dotenv()

SEVERITY_STYLE = {"error": "bold red", "warning": "yellow", "info": "cyan"}
SEVERITY_LABEL = {"error": "STRUCTURAL ERROR", "warning": "STRUCTURAL WARNING", "info": "INFO"}

SEC_SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan"}
SEC_BORDER_STYLE = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillscope",
        description="Analyze a SKILL.md file: structural lint plus AI-powered plain-English explanation "
                    "and ambiguity detection.",
    )
    parser.add_argument("path", help="Path to a SKILL.md file, or '-' to read from stdin.")
    parser.add_argument("--no-semantic", action="store_true", help="Skip the Claude API call; structural checks only.")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report.")
    parser.add_argument("--flow-out", metavar="PATH", help="Also write the Mermaid flow diagram source to this file (e.g. flow.mmd).")
    parser.add_argument("--eli5", action="store_true", help="Show the dead-simple 'explain like I'm 5' summary instead of the technical one.")
    args = parser.parse_args(argv)

    console = Console()

    try:
        content = read_input(args.path)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] file not found: {args.path}")
        return 1
    except OSError as exc:
        console.print(f"[bold red]Error reading file:[/bold red] {exc}")
        return 1

    analysis = run_analysis(content, skip_semantic=args.no_semantic)
    result = analysis.to_dict()

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    render(console, args.path, result, flow_out=args.flow_out, eli5=args.eli5)

    has_errors = any(w.get("severity") == "error" for w in result.get("structural_warnings") or [])
    has_severe_security_findings = any(
        f.get("severity") in ("critical", "high") for f in result.get("security_findings") or []
    )
    return 1 if (has_errors or has_severe_security_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
