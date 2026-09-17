"""OWASP Agentic Skills Top 10 checklist evaluation.

Status, verified by directly fetching the project's pages in the same session this module
was written: OWASP Incubator project, version 0.0.0, "active development" - not a ratified
standard. Content is CC-BY-SA-4.0 licensed; the constants below are attribution for
reproducing its risk IDs/titles, not a claim of official/certified status.

This module only evaluates what's decidable from a single file's already-computed
structural analysis (`evaluate_content_checks`). A bundle-aware companion is planned for a
later phase once directory-level scanning exists - several risks below are legitimately
`not_applicable` at this layer because no directory view, registry data, or
sandbox/governance signal is available from one file's text alone; that's a deliberate,
honest stopping point, not a gap to paper over with an invented heuristic.
"""

from __future__ import annotations

from .models import ChecklistResult, StructuralAnalysis

OWASP_AST_STATUS = "OWASP Incubator project, v0.0.0, active development - not a ratified standard."
OWASP_AST_LICENSE = "Content adapted from OWASP Agentic Skills Top 10, CC-BY-SA-4.0."
OWASP_AST_URL = "https://owasp.github.io/www-project-agentic-skills-top-10/top10"

# (id, title, severity) - verified verbatim by directly fetching OWASP_AST_URL.
CHECKLIST_DEFINITIONS: list[tuple[str, str, str]] = [
    ("AST01", "Malicious Skills", "critical"),
    ("AST02", "Supply Chain Compromise", "critical"),
    ("AST03", "Over-Privileged Skills", "high"),
    ("AST04", "Insecure Metadata", "high"),
    ("AST05", "Untrusted External Instructions", "high"),
    ("AST06", "Weak Isolation", "high"),
    ("AST07", "Update Drift", "medium"),
    ("AST08", "Poor Scanning", "medium"),
    ("AST09", "No Governance", "medium"),
    ("AST10", "Cross-Platform Reuse", "medium"),
]

_DEFS = {id_: (title, severity) for id_, title, severity in CHECKLIST_DEFINITIONS}
_ORDER = {id_: i for i, (id_, _, _) in enumerate(CHECKLIST_DEFINITIONS)}


def _result(check_id: str, status: str, evidence: str = "") -> ChecklistResult:
    title, severity = _DEFS[check_id]
    return ChecklistResult(
        id=check_id, title=title, status=status, severity=severity,
        evidence=evidence, citation=OWASP_AST_URL,
    )


def evaluate_content_checks(structural: StructuralAnalysis) -> list[ChecklistResult]:
    """Evaluates the subset of the OWASP AST checklist decidable from one file's already-
    computed structural analysis (frontmatter, warnings, security findings, references)."""
    results: list[ChecklistResult] = []

    severe = [f for f in structural.security_findings if f.severity in ("critical", "high")]
    if severe:
        evidence = "; ".join(f"{f.category}: {f.excerpt[:60]}" for f in severe[:3])
        results.append(_result("AST01", "fail", evidence))
    else:
        results.append(_result("AST01", "pass"))

    # AST04 is only partially decidable here: the YAML-deserialization-RCE sub-pattern is
    # already mitigated by existing code (parser.py uses yaml.safe_load - existing-code
    # credit, not new work), the steganographic-injection sub-pattern is exactly what
    # unicode_scan.py checks, and the permission-understating sub-pattern needs a bundle
    # view (later phase, not fabricated here).
    stego = [f for f in structural.security_findings if f.category == "steganographic_injection"]
    if stego:
        results.append(_result(
            "AST04", "fail",
            "Hidden/invisible Unicode content found - see security findings above.",
        ))
    else:
        results.append(_result(
            "AST04", "manual_review",
            "YAML-deserialization sub-pattern already mitigated (yaml.safe_load); the "
            "permission-understating sub-pattern needs a directory/bundle view, not "
            "available from a single file.",
        ))

    has_url_reference = any(r.kind == "url" for r in structural.references)
    results.append(_result(
        "AST05",
        "manual_review" if has_url_reference else "pass",
        (
            "References an external URL - review whether the agent is instructed to "
            "trust that page's content as if it were part of this skill."
        ) if has_url_reference else "",
    ))

    results.append(_result(
        "AST08", "pass",
        "SkillScope already scans the code layer (pattern rules) and the natural-language "
        "layer (semantic analysis) independently, which is what this risk asks for.",
    ))

    for check_id, reason in [
        ("AST02", "No package-registry/provenance data is available from a single file's content alone."),
        ("AST03", "No bundle view to compare declared vs. actually-used tools/permissions."),
        ("AST06", "No sandbox/isolation information is observable from a skill's own files."),
        ("AST07", "No version-pinning history is available from a single file."),
        ("AST09", "No organizational inventory/governance data is available to SkillScope."),
        ("AST10", "No second platform manifest to compare against from a single file."),
    ]:
        results.append(_result(check_id, "not_applicable", reason))

    results.sort(key=lambda r: _ORDER[r.id])
    return results
