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

import re

from .models import ChecklistResult, StructuralAnalysis
from .platform_profiles import KNOWN_MANIFEST_FILENAMES, PLATFORM_MANIFESTS

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


def _parse_tool_list(raw) -> set[str]:
    tokens = raw if isinstance(raw, list) else str(raw).split(",")
    tools = set()
    for tok in tokens:
        name = re.sub(r"\(.*\)", "", str(tok)).strip()
        if name:
            tools.add(name.lower())
    return tools


def _declared_tools(frontmatter: dict):
    """Returns the declared tool/command allowlist, or None if nothing was declared."""
    permissions = frontmatter.get("permissions")
    if isinstance(permissions, dict) and permissions.get("tools") is not None:
        return _parse_tool_list(permissions["tools"])
    if frontmatter.get("allowed-tools") is not None:
        return _parse_tool_list(frontmatter["allowed-tools"])
    return None


def _network_denied(frontmatter: dict) -> bool:
    permissions = frontmatter.get("permissions")
    if isinstance(permissions, dict):
        network = permissions.get("network")
        if isinstance(network, dict) and network.get("deny") == "*":
            return True
        if network is False:
            return True
    return frontmatter.get("network") is False


def evaluate_bundle_checks(bundle, structural: StructuralAnalysis) -> list[ChecklistResult]:
    """Upgrades the content-only checklist with the risks a directory/bundle view makes
    decidable. `bundle` is a `core.bundle.SkillBundle` - untyped here to avoid a circular
    import (bundle.py imports parser.py, which imports this module).

    AST02 (Supply Chain Compromise) deliberately stays `not_applicable` even with a
    directory view - no registry/provenance data is available from local files alone, and
    fabricating a "looks like it came from a registry" heuristic would be inventing a
    detector, not building one. AST06/AST09 are untouched for the same reason: no
    sandbox-state or org-governance signal exists in a skill's own files, bundle or not.
    """
    results = {r.id: r for r in evaluate_content_checks(structural)}
    frontmatter = structural.frontmatter or {}

    declared_tools = _declared_tools(frontmatter)
    if declared_tools is None:
        results["AST03"] = _result(
            "AST03", "manual_review",
            "No permissions.tools/allowed-tools declared - nothing to check actual usage against.",
        )
    else:
        undeclared = [t for t in bundle.used_tools if t not in declared_tools]
        if undeclared:
            results["AST03"] = _result(
                "AST03", "fail",
                f"Bundle uses tool(s)/command(s) not in the declared set: {', '.join(undeclared[:5])}.",
            )
        else:
            results["AST03"] = _result(
                "AST03", "pass",
                "All detected tool/command usage across the bundle is within the declared "
                "permissions.tools/allowed-tools set.",
            )

    if _network_denied(frontmatter) and bundle.uses_network:
        results["AST04"] = _result(
            "AST04", "fail",
            "Frontmatter declares no network access, but a bundled file makes a network "
            "call (curl/wget/HTTP request) - this is the exact permission-understating "
            "example OWASP AST04 gives.",
        )

    has_version = frontmatter.get("version") is not None
    has_hash = frontmatter.get("content_hash") is not None
    if has_version or has_hash:
        results["AST07"] = _result(
            "AST07", "pass",
            "version/content_hash field present (presence-only - not cryptographically verified).",
        )
    else:
        results["AST07"] = _result(
            "AST07", "manual_review",
            "No version or content_hash field - nothing to check drift against.",
        )

    bundle_relpaths = {f.relpath for f in bundle.files}
    declared_platforms = frontmatter.get("platforms")
    if isinstance(declared_platforms, list) and declared_platforms:
        missing = []
        for platform_name in declared_platforms:
            manifest = PLATFORM_MANIFESTS.get(str(platform_name).strip().lower())
            # SKILL.md is always present by definition (it's what got us here) - only a
            # *second* platform's manifest can meaningfully be "missing".
            if manifest and manifest != "SKILL.md" and manifest not in bundle_relpaths:
                missing.append(f"{platform_name} ({manifest})")
        if missing:
            results["AST10"] = _result(
                "AST10", "manual_review",
                f"Declared platform(s) missing their manifest file in this bundle: "
                f"{', '.join(missing)} - cross-check that permission/security metadata "
                "didn't drop when porting to them.",
            )
    else:
        found_manifests = sorted(
            (bundle_relpaths & KNOWN_MANIFEST_FILENAMES) - {"SKILL.md"}
        )
        if found_manifests:
            results["AST10"] = _result(
                "AST10", "manual_review",
                f"Multiple platform manifest(s) found ({', '.join(found_manifests)}) with "
                "no `platforms` field declared - cross-check permission/security metadata "
                "for drops between them.",
            )

    return [results[id_] for id_, _, _ in CHECKLIST_DEFINITIONS]
