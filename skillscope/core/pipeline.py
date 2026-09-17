"""Combines structural parsing and semantic analysis into one SkillAnalysis."""

from __future__ import annotations

from .analyzer import analyze_semantic
from .models import SkillAnalysis
from .parser import parse_skill
from .rules import redact_secrets


def run_analysis(content: str, skip_semantic: bool = False, api_key: str | None = None) -> SkillAnalysis:
    structural = parse_skill(content)

    semantic = None
    if not skip_semantic:
        # An empty file has nothing meaningful to send to the model.
        if structural.frontmatter_error == "empty_file":
            semantic = None
        else:
            # Redact any detected hardcoded secrets before this content leaves the
            # machine for semantic analysis - the scanner that flags a leaked credential
            # must not itself become the thing that leaks it to a third-party API. The
            # original raw_content below (shown to the user) is unaffected.
            outbound_content = redact_secrets(content, structural.security_findings)
            semantic = analyze_semantic(outbound_content, structural, api_key=api_key)

    return SkillAnalysis(raw_content=content, structural=structural, semantic=semantic)
