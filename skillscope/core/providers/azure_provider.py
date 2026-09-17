"""Azure AI Foundry / Azure OpenAI provider adapter.

Uses the standard `openai` package's `AzureOpenAI` client - the path Microsoft now
recommends over the deprecated standalone `azure-ai-inference` client. Forces structured
output via `tool_choice={"type": "function", "function": {"name": ...}}`, OpenAI's
equivalent of Anthropic's `tool_choice={"type": "tool", ...}`.

Needs both AZURE_OPENAI_API_KEY (the credential parameter below) and AZURE_OPENAI_ENDPOINT
(the Azure resource's endpoint URL - not a secret, read directly from the environment
rather than threaded through as a second credential). AZURE_OPENAI_DEPLOYMENT names the
deployed model in the user's Azure resource (Azure deployment names are user-chosen, not a
fixed model string like Anthropic's/Gemini's, so this can't be hardcoded).

Caveat: written from `openai`'s documented AzureOpenAI API shape, not exercised against a
live API in this environment (no Azure credentials available here) - analyzer.py's broad
exception handling degrades a shape mismatch to a SemanticAnalysis.error rather than
crashing the caller, but this deserves a real run with a live key before being treated as
fully verified.

Not mirrored into docs/pysrc/ - never called from the browser demo.
"""

from __future__ import annotations

import json
import os

from .. import analyzer
from ..models import SemanticAnalysis, StructuralAnalysis

_FUNCTION_TOOL = {
    "type": "function",
    "function": {
        "name": analyzer.TOOL_NAME,
        "description": analyzer.RESPONSE_TOOL["description"],
        "parameters": analyzer.RESPONSE_TOOL["input_schema"],
    },
}

DEFAULT_API_VERSION = "2024-10-21"


def call(content: str, structural: StructuralAnalysis, credential: str) -> SemanticAnalysis:
    from openai import AzureOpenAI

    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT")
    if not endpoint or not deployment:
        return SemanticAnalysis(
            summary="", trigger_conditions="", ambiguities=[],
            error="AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT must both be set "
                  "alongside AZURE_OPENAI_API_KEY to use the azure provider.",
        )

    client = AzureOpenAI(
        api_key=credential, azure_endpoint=endpoint,
        api_version=os.environ.get("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION),
    )
    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": analyzer.SYSTEM_PROMPT},
            {"role": "user", "content": analyzer.build_user_prompt(content, structural)},
        ],
        tools=[_FUNCTION_TOOL],
        tool_choice={"type": "function", "function": {"name": analyzer.TOOL_NAME}},
    )

    tool_calls = getattr(response.choices[0].message, "tool_calls", None) or []
    if not tool_calls:
        return SemanticAnalysis(
            summary="", trigger_conditions="", ambiguities=[],
            error="Semantic analysis failed: Azure OpenAI did not return a tool call.",
        )
    args = json.loads(tool_calls[0].function.arguments)
    return analyzer.build_semantic_analysis(args)
