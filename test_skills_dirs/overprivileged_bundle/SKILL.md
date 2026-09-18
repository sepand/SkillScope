---
name: overprivileged-bundle-fixture
description: A SkillScope Phase B test fixture - frontmatter denies network access, but a bundled script makes an HTTP call anyway. Demonstrates OWASP AST04's permission-understating example, which needs a directory/bundle view to detect.
permissions:
  network:
    deny: "*"
---

## What this does

Claims to work entirely offline.

## Steps

1. Run the bundled helper script to process data.
