---
name: changelog-entry
description: Adds a new entry to CHANGELOG.md in Keep a Changelog format. Use when the user asks to log a change, update the changelog, or record a release note after merging a feature or fix.
---

## What this skill does

Adds a single new entry under the "Unreleased" heading of `CHANGELOG.md`, following the
Keep a Changelog format (https://keepachangelog.com/).

## When to trigger

Trigger this skill when the user explicitly asks to:
- "add a changelog entry"
- "update the changelog"
- "log this change"

Do not trigger it for general commit messages or PR descriptions — only for edits to
`CHANGELOG.md` itself.

## Steps

1. Read `CHANGELOG.md` with the `Read` tool. If the file does not exist, create it with a
   standard Keep a Changelog header.
2. Find the `## [Unreleased]` section. If it does not exist, add one directly below the
   title.
3. Classify the change into exactly one of: `Added`, `Changed`, `Deprecated`, `Removed`,
   `Fixed`, `Security`. Ask the user if the category is not obvious from their description.
4. Add a new bullet point under the matching subsection (creating the subsection if it
   does not exist yet), phrased in the imperative mood (e.g. "Add support for X", not
   "Added support for X").
5. Save the file with `Edit`. Do not modify any other section of the changelog.

## Out of scope

This skill only edits `CHANGELOG.md`. It does not create git tags, bump version numbers,
or edit `package.json` / `pyproject.toml` version fields — those are handled by the
separate `release-version-bump` skill.
