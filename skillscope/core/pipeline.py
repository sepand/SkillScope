"""Combines structural parsing and semantic analysis into one SkillAnalysis."""

from __future__ import annotations

from .analyzer import analyze_semantic
from .models import SkillAnalysis
from .parser import parse_skill


def run_analysis(content: str, skip_semantic: bool = False, api_key: str | None = None) -> SkillAnalysis:
    structural = parse_skill(content)

    semantic = None
    if not skip_semantic:
        # An empty file has nothing meaningful to send to the model.
        if structural.frontmatter_error == "empty_file":
            semantic = None
        else:
            semantic = analyze_semantic(content, structural, api_key=api_key)

    return SkillAnalysis(raw_content=content, structural=structural, semantic=semantic)
