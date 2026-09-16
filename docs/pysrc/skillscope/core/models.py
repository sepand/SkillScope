"""Data model shared by the structural parser, the semantic analyzer, and both frontends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class StructuralWarning:
    severity: str  # "error" | "warning" | "info"
    message: str
    field: Optional[str] = None

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "field": self.field}


@dataclass
class Reference:
    kind: str  # "tool" | "command" | "file_reference" | "url"
    value: str
    context: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "context": self.context}


@dataclass
class Section:
    heading: str
    level: int
    content: str

    def to_dict(self) -> dict:
        return {"heading": self.heading, "level": self.level, "content": self.content}


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class SecurityFinding:
    severity: str  # "critical" | "high" | "medium" | "low"
    category: str  # e.g. "remote_code_execution", "data_exfiltration", "prompt_injection",
    # "credential_access", "destructive_command", "obfuscation", "privilege_escalation", "other"
    excerpt: str
    issue: str
    source: str = "pattern"  # "pattern" (deterministic scan) | "ai" (semantic analysis)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "excerpt": self.excerpt,
            "issue": self.issue,
            "source": self.source,
        }


@dataclass
class StructuralAnalysis:
    frontmatter: dict[str, Any]
    frontmatter_error: Optional[str]
    body: str
    sections: list[Section] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    warnings: list[StructuralWarning] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    flow_diagram: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "frontmatter": self.frontmatter,
            "frontmatter_error": self.frontmatter_error,
            "sections": [s.to_dict() for s in self.sections],
            "references": [r.to_dict() for r in self.references],
            "warnings": [w.to_dict() for w in self.warnings],
            "security_findings": [f.to_dict() for f in self.security_findings],
            "flow_diagram": self.flow_diagram,
        }


@dataclass
class Ambiguity:
    excerpt: str
    issue: str
    suggested_fix: str

    def to_dict(self) -> dict:
        return {"excerpt": self.excerpt, "issue": self.issue, "suggested_fix": self.suggested_fix}


@dataclass
class SemanticAnalysis:
    summary: str
    trigger_conditions: str
    eli5_summary: str = ""
    ambiguities: list[Ambiguity] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    flow_diagram: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "eli5_summary": self.eli5_summary,
            "trigger_conditions": self.trigger_conditions,
            "ambiguities": [a.to_dict() for a in self.ambiguities],
            "security_findings": [f.to_dict() for f in self.security_findings],
            "flow_diagram": self.flow_diagram,
            "error": self.error,
        }


@dataclass
class SkillAnalysis:
    raw_content: str
    structural: StructuralAnalysis
    semantic: Optional[SemanticAnalysis]

    def to_dict(self) -> dict:
        """Matches the required output schema, plus extra structural detail.

        security_findings merges the deterministic pattern scan (always available) with
        the AI-flagged findings (only when semantic analysis ran), sorted most-severe
        first — this is meant to be rendered before anything else in either frontend.
        """
        semantic = self.semantic.to_dict() if self.semantic else {
            "summary": "",
            "eli5_summary": "",
            "trigger_conditions": "",
            "ambiguities": [],
            "security_findings": [],
            "flow_diagram": None,
            "error": "Semantic analysis was not run.",
        }
        security_findings = [f.to_dict() for f in self.structural.security_findings]
        security_findings.extend(semantic["security_findings"])
        security_findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 9))

        # Prefer the AI-generated diagram (it can show decision branches); fall back to
        # the deterministic linear one built from a numbered list when the model didn't
        # produce one (no API key, or it judged the skill has no discernible flow).
        flow_diagram = semantic["flow_diagram"] or self.structural.flow_diagram
        flow_diagram_source = "ai" if semantic["flow_diagram"] else ("pattern" if flow_diagram else None)

        return {
            "security_findings": security_findings,
            "flow_diagram": flow_diagram,
            "flow_diagram_source": flow_diagram_source,
            "summary": semantic["summary"],
            "eli5_summary": semantic["eli5_summary"],
            "trigger_conditions": semantic["trigger_conditions"],
            "ambiguities": semantic["ambiguities"],
            "structural_warnings": [w.to_dict() for w in self.structural.warnings],
            "semantic_error": semantic["error"],
            "frontmatter": self.structural.frontmatter,
            "frontmatter_error": self.structural.frontmatter_error,
            "sections": [s.to_dict() for s in self.structural.sections],
            "references": [r.to_dict() for r in self.structural.references],
        }
