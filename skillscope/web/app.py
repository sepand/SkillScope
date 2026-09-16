"""SkillScope web app: paste or upload a SKILL.md, get the same analysis as the CLI.

The Anthropic API key lives only on the server (read from the ANTHROPIC_API_KEY
environment variable) — the browser never sees it, which is why this is a small
Flask app rather than a pure client-side HTML file.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from ..core.pipeline import run_analysis

load_dotenv()

MAX_UPLOAD_BYTES = 512 * 1024  # SKILL.md files are small; refuse anything absurd


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.get("/")
    def index():
        return render_template("index.html", api_key_configured=bool(os.environ.get("ANTHROPIC_API_KEY")))

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

        skip_semantic = bool(request.args.get("structural_only")) or bool(
            (request.get_json(silent=True) or {}).get("structural_only")
        )

        analysis = run_analysis(content, skip_semantic=skip_semantic)
        result = analysis.to_dict()
        result["source_content"] = content
        return jsonify(result)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
