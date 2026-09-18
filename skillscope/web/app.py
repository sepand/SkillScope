"""SkillScope web app: paste or upload a SKILL.md, get the same analysis as the CLI.

The Anthropic API key lives only on the server (read from the ANTHROPIC_API_KEY
environment variable) — the browser never sees it, which is why this is a small
Flask app rather than a pure client-side HTML file.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from ..core.analyzer import PROVIDER_ENV_VARS
from ..core.discovery import discover_skill_dirs
from ..core.frontmatter_fix import build_corrected_skill_md
from ..core.parser import parse_skill
from ..core.pipeline import run_analysis, run_bundle_analysis

load_dotenv()

MAX_UPLOAD_BYTES = 512 * 1024  # single-file mode's own limit, enforced manually below
MAX_FOLDER_UPLOAD_BYTES = 8 * 1024 * 1024  # folder mode's overall request-size cap
MAX_FOLDER_FILES = 200  # cheap guard against a folder upload used as a DoS vector

# Rejected as path components in an uploaded folder's relative paths, alongside `.`/`..`/
# absolute/NUL-byte checks in _sanitize_relpath() below - Windows reserved device names,
# case-insensitively, with or without an extension (e.g. "NUL", "nul.txt").
_RESERVED_WINDOWS_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


def _sanitize_relpath(raw_path: str) -> str | None:
    """Validates a client-supplied relative path (from File.webkitRelativePath, carried as
    the upload's filename - see /api/analyze-folder) before it's used to build a real
    filesystem path under a temp directory. Returns the normalized relpath, or None if the
    whole request should be rejected. This is a write-side mirror of core/safe_fs.py's
    "never trust a client-supplied path" philosophy - everything safe_fs.py does today is
    read-only, so this is new, not a relaxation of an existing check."""
    if not raw_path or "\x00" in raw_path or "\\" in raw_path or ":" in raw_path:
        return None
    parts = raw_path.split("/")
    clean_parts = []
    for part in parts:
        if not part or part in (".", ".."):
            return None
        if part.upper().split(".")[0] in _RESERVED_WINDOWS_NAMES:
            return None
        clean_parts.append(part)
    if not clean_parts:
        return None
    return "/".join(clean_parts)


def create_app() -> Flask:
    app = Flask(__name__)
    # Global cap on any request body, raised to accommodate /api/analyze-folder's
    # multi-file uploads - /api/analyze keeps single-file mode's tighter 512KB limit via
    # its own manual check below (MAX_UPLOAD_BYTES), so this raise doesn't loosen that.
    app.config["MAX_CONTENT_LENGTH"] = MAX_FOLDER_UPLOAD_BYTES

    @app.get("/")
    def index():
        provider_configured = {
            provider: bool(os.environ.get(env_var)) for provider, env_var in PROVIDER_ENV_VARS.items()
        }
        return render_template(
            "index.html",
            api_key_configured=provider_configured["anthropic"],
            provider_configured=provider_configured,
        )

    @app.post("/api/analyze")
    def api_analyze():
        content = None

        if "file" in request.files and request.files["file"].filename:
            f = request.files["file"]
            raw = f.read(MAX_UPLOAD_BYTES + 1)
            if len(raw) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "File too large (max 512KB)."}), 400
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                return jsonify({"error": "File is not valid UTF-8 text."}), 400
        else:
            data = request.get_json(silent=True) or {}
            content = data.get("content", "")

        if content is None or not content.strip():
            return jsonify({"error": "No content provided. Paste a SKILL.md or upload a file."}), 400

        json_body = request.get_json(silent=True) or {}
        skip_semantic = bool(request.args.get("structural_only")) or bool(json_body.get("structural_only"))

        provider = json_body.get("provider") or request.args.get("provider") or "anthropic"
        # provider comes straight from an untrusted request body - request.args values are
        # always strings, but a JSON body can hand us any type (e.g. {"provider": {}}),
        # and `in` against a dict raises TypeError for an unhashable value rather than
        # just returning False. Reject non-strings before the membership check so a
        # malformed request gets a clean 400, not an unhandled exception.
        if not isinstance(provider, str) or provider not in PROVIDER_ENV_VARS:
            return jsonify({"error": f"Unknown provider '{provider}'. Valid options: {', '.join(PROVIDER_ENV_VARS)}."}), 400

        analysis = run_analysis(content, skip_semantic=skip_semantic, provider=provider)
        result = analysis.to_dict()
        result["source_content"] = content
        return jsonify(result)

    @app.post("/api/frontmatter-fix")
    def api_frontmatter_fix():
        data = request.get_json(silent=True) or {}
        content = data.get("content", "")
        if not isinstance(content, str) or not content.strip():
            return jsonify({"error": "No content provided."}), 400

        structural = parse_skill(content)
        result = build_corrected_skill_md(content, structural.frontmatter, structural.warnings)
        return jsonify(result.to_dict())

    @app.post("/api/analyze-folder")
    def api_analyze_folder():
        uploaded = request.files.getlist("files")
        if not uploaded:
            return jsonify({"error": "No files provided. Select a folder to upload."}), 400
        if len(uploaded) > MAX_FOLDER_FILES:
            return jsonify({"error": f"Too many files ({len(uploaded)}); max {MAX_FOLDER_FILES}."}), 400

        provider = request.form.get("provider") or "anthropic"
        if not isinstance(provider, str) or provider not in PROVIDER_ENV_VARS:
            return jsonify({"error": f"Unknown provider '{provider}'. Valid options: {', '.join(PROVIDER_ENV_VARS)}."}), 400
        run_semantic = request.form.get("semantic") == "true"

        temp_root = Path(tempfile.mkdtemp(prefix="skillscope-folder-")).resolve()
        try:
            for f in uploaded:
                relpath = _sanitize_relpath(f.filename)
                if relpath is None:
                    return jsonify({"error": f"Rejected unsafe path in upload: {f.filename!r}."}), 400

                dest = (temp_root / relpath).resolve()
                # Defense in depth beyond _sanitize_relpath()'s component-level checks -
                # the same resolved-path containment check core/safe_fs.py documents for
                # reads, applied here to a write.
                if not dest.is_relative_to(temp_root):
                    return jsonify({"error": f"Rejected unsafe path in upload: {f.filename!r}."}), 400

                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    f.save(dest)
                except OSError:
                    # Two uploaded paths can collide at a file/directory boundary (e.g.
                    # "a" and "a/SKILL.md" both pass the checks above individually) -
                    # mkdir/save then raise FileExistsError or PermissionError, which is
                    # reachable directly via this route (not just the folder-picker UI)
                    # and would otherwise be an unhandled exception on the documented
                    # debug=True run path. A malformed upload gets a clean 400 instead.
                    return jsonify({
                        "error": f"Could not write uploaded path {f.filename!r} - it conflicts "
                                 "with another entry in this upload (e.g. a name used as both a "
                                 "file and a folder)."
                    }), 400

            discovered = discover_skill_dirs(temp_root)
            if not discovered:
                return jsonify({"error": "No SKILL.md found in the uploaded folder."}), 400

            skills = []
            for d in discovered:
                analysis = run_bundle_analysis(
                    d.skill_dir, scope=d.scope, skip_semantic=not run_semantic, provider=provider,
                )
                result = analysis.to_dict()
                result["skill_relpath"] = str(d.path.relative_to(temp_root)).replace("\\", "/")
                result["scope"] = d.scope
                result["source_content"] = analysis.skill_analysis.raw_content
                skills.append(result)

            return jsonify({"skills": skills, "count": len(skills)})
        finally:
            # Nothing from an upload persists on the server past this one request.
            shutil.rmtree(temp_root, ignore_errors=True)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
