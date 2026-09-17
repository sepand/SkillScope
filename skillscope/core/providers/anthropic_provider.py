"""Anthropic Claude provider adapter.

This is the original logic that used to live inline in analyzer.py::analyze_semantic(),
moved here unchanged in behavior now that analyzer.py supports multiple providers. Not
mirrored into docs/pysrc/ - the static Pyodide demo calls the Anthropic API directly from
the browser via fetch() (see docs/index.html) rather than through this module, and never
imports core/providers/ at all.
"""

from __future__ import annotations

from .. import analyzer
from ..models import SemanticAnalysis, StructuralAnalysis


def call(content: str, structural: StructuralAnalysis, credential: str) -> SemanticAnalysis:
    import anthropic  # deferred - see core/CLAUDE.md on why analyzer.py's imports stay lazy

    client = anthropic.Anthropic(api_key=credential)
    response = client.messages.create(
        model=analyzer.MODEL,
        max_tokens=4096,
        system=analyzer.SYSTEM_PROMPT,
        tools=[analyzer.RESPONSE_TOOL],
        tool_choice={"type": "tool", "name": analyzer.TOOL_NAME},
        messages=[{"role": "user", "content": analyzer.build_user_prompt(content, structural)}],
    )
    tool_use = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
    if tool_use is None:
        return SemanticAnalysis(
            summary="", trigger_conditions="", ambiguities=[],
            error="Semantic analysis failed: the model did not return a tool call.",
        )
    return analyzer.build_semantic_analysis(tool_use.input)
