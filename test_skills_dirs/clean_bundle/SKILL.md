---
name: clean-bundle-fixture
description: A well-formed multi-file skill bundle used as a SkillScope Phase B test fixture - demonstrates a clean bundle with declared permissions matching actual usage.
permissions:
  network:
    deny: "*"
  tools:
    - Read
    - Write
version: "1.0.0"
content_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
---

## What this does

Reads a file with `Read` and writes a formatted copy with `Write`. No network access, no
shell execution.

## Steps

1. Read the target file.
2. Format its contents with the bundled helper script.
3. Write the result back.
