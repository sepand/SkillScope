"""Google Gemini provider adapter.

Uses `google-genai` - the current SDK; the older `google-generativeai` package is
deprecated and was not adopted here. Forces structured output via `tool_config` mode
"ANY" with `allowed_function_names` restricted to this tool's name - Gemini's equivalent
of Anthropic's `tool_choice={"type": "tool", ...}` in anthropic_provider.py.

Caveat: this was written from `google-genai`'s documented API shape, not exercised against
a live API in this environment (no GEMINI_API_KEY available here). If the SDK's surface has
moved on, analyzer.py's broad exception handling around this call() degrades the failure to
a SemanticAnalysis.error rather than crashing the caller - but the request/response
handling below deserves a real run with a live key before being treated as fully verified.

Not mirrored into docs/pysrc/ - never called from the browser demo.
"""

from __future__ import annotations

import os

from .. import analyzer
from ..models import SemanticAnalysis, StructuralAnalysis

_FUNCTION_DECLARATION = {
    "name": analyzer.TOOL_NAME,
    "description": analyzer.RESPONSE_TOOL["description"],
    "parameters": analyzer.RESPONSE_TOOL["input_schema"],
}

DEFAULT_MODEL = "gemini-2.5-pro"  # reasoning-tier model, not "flash" - matches the analysis
# depth of Anthropic's default (analyzer.py's MODEL) rather than the faster/lighter tier.


def call(content: str, structural: StructuralAnalysis, credential: str) -> SemanticAnalysis:
    from google import genai
    from google.genai import types

    model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
    client = genai.Client(api_key=credential)
    config = types.GenerateContentConfig(
        system_instruction=analyzer.SYSTEM_PROMPT,
        tools=[types.Tool(function_declarations=[_FUNCTION_DECLARATION])],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode="ANY", allowed_function_names=[analyzer.TOOL_NAME],
            )
        ),
    )
    response = client.models.generate_content(
        model=model,
        contents=analyzer.build_user_prompt(content, structural),
        config=config,
    )

    for candidate in getattr(response, "candidates", None) or []:
        for part in getattr(candidate.content, "parts", None) or []:
            function_call = getattr(part, "function_call", None)
            if function_call is not None:
                return analyzer.build_semantic_analysis(dict(function_call.args))

    return SemanticAnalysis(
        summary="", trigger_conditions="", ambiguities=[],
        error="Semantic analysis failed: Gemini did not return a function call.",
    )
