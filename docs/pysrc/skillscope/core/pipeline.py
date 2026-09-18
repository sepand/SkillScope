"""Combines structural parsing and semantic analysis into one SkillAnalysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import analyze_semantic
from .bundle import SkillBundle, build_bundle
from .checklist import evaluate_bundle_checks
from .models import SEVERITY_RANK, ChecklistResult, SkillAnalysis
from .parser import parse_skill
from .rules import redact_secrets


def run_analysis(
    content: str, skip_semantic: bool = False, api_key: str | None = None, provider: str = "anthropic",
) -> SkillAnalysis:
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
            semantic = analyze_semantic(outbound_content, structural, api_key=api_key, provider=provider)

    return SkillAnalysis(raw_content=content, structural=structural, semantic=semantic)


@dataclass
class BundleSkillAnalysis:
    """The result of directory/bundle-mode analysis: the SKILL.md file's own full
    analysis, plus findings from every other file in the skill's directory, plus a
    checklist upgraded with the risks only a directory view can decide (see
    checklist.py::evaluate_bundle_checks)."""

    bundle: SkillBundle
    skill_analysis: SkillAnalysis
    checklist: list[ChecklistResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = self.skill_analysis.to_dict()
        result["checklist"] = [c.to_dict() for c in self.checklist]
        result["security_findings"] = sorted(
            result["security_findings"] + [f.to_dict() for f in self.bundle.findings],
            key=lambda f: SEVERITY_RANK.get(f["severity"], 9),
        )
        result["bundle"] = {
            "root": self.bundle.root,
            "scope": self.bundle.scope,
            "files": [
                {"relpath": f.relpath, "size_bytes": f.size_bytes, "is_text": f.is_text}
                for f in self.bundle.files
            ],
        }
        return result


def run_bundle_analysis(
    skill_dir: Path, scope: str = "unknown", skip_semantic: bool = True,
    api_key: str | None = None, provider: str = "anthropic",
) -> BundleSkillAnalysis:
    """Analyzes an entire skill directory: the SKILL.md file gets the full single-file
    treatment (structural + optional semantic analysis) via run_analysis(); every other
    file in the directory is scanned for the same content-layer patterns via build_bundle()
    (deduplicated - build_bundle skips re-scanning SKILL.md itself). `skip_semantic`
    defaults to True here, unlike run_analysis() - directory mode can discover many skills
    at once, and silently sending every one of them to a paid third-party API by default
    would be a cost and consent problem the caller (cli.py) makes an explicit, informed
    choice about instead.

    Defense in depth: refuses to read a symlinked SKILL.md even though discover_skill_dirs()
    already never surfaces one (see core/safe_fs.py) - a caller invoking this function
    directly with an unvalidated skill_dir should get the same protection."""
    skill_dir = Path(skill_dir)
    skill_md_path = skill_dir / "SKILL.md"
    if skill_md_path.is_symlink():
        raise ValueError(
            f"{skill_md_path} is a symlink - refusing to follow it outside the scanned "
            "directory. This tool never reads through symlinks in a scanned skill."
        )
    content = skill_md_path.read_text(encoding="utf-8")
    skill_analysis = run_analysis(content, skip_semantic=skip_semantic, api_key=api_key, provider=provider)
    bundle = build_bundle(skill_dir, scope=scope)
    checklist = evaluate_bundle_checks(bundle, skill_analysis.structural)
    return BundleSkillAnalysis(bundle=bundle, skill_analysis=skill_analysis, checklist=checklist)
