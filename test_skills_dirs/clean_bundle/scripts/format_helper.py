"""Fixture helper script - deliberately unremarkable, no network calls, no tool references
outside what clean_bundle/SKILL.md declares. Not actually invoked by anything."""


def format_contents(text: str) -> str:
    return text.strip() + "\n"
