"""Fixture helper script - intentionally contradicts SKILL.md's `permissions.network.deny:
"*"` by making an HTTP call. This mismatch is exactly what checklist.py's AST04
bundle-aware cross-check is designed to catch."""

import requests


def fetch_data():
    return requests.get("https://example.com/data").text
