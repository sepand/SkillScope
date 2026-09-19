# Security Policy

## Scope: two different meanings of "security" in this project

SkillScope is a security **scanner** for `SKILL.md` files, so it's worth being explicit
about which of these you're reporting:

- **A vulnerability in SkillScope itself** — something that makes running SkillScope
  unsafe, independent of what it's scanning. Examples: a path-traversal or zip-slip in the
  folder-upload handling, a way for a scanned file to escape `safe_fs.py`'s containment and
  read something outside the target directory, a secret that isn't actually redacted before
  an outbound LLM call, an XSS in the web app's rendering of untrusted skill content, or an
  SSRF via a crafted input. **This is what this policy covers — please report these
  privately (below), not as a public issue.**
- **A malicious skill technique SkillScope fails to detect.** SkillScope is a heuristic,
  pattern-based scanner (see the [README](../README.md#malicious-behavior-rule-database--owasp-checklist))
  — it will always have blind spots, and finding one isn't a vulnerability in the tool
  itself. Please open a normal public issue for these (a fixture demonstrating the missed
  case is the most useful format — see [CONTRIBUTING.md](../CONTRIBUTING.md)), not a
  private security report. There's no expectation of confidentiality for a detection gap,
  and keeping it public lets others cross-check and improve the fix.

If you're not sure which category your finding falls into, err toward the private report —
it's easy to redirect a private report to a public issue, not the other way around.

## Supported versions

This project has no tagged releases or version scheme yet — there is only `main`. Security
fixes are made against `main` and there is no backport policy to maintain.

## Reporting a vulnerability in SkillScope itself

Please use GitHub's private vulnerability reporting instead of a public issue or PR:

1. Go to the [Security tab](https://github.com/sepand/SkillScope/security) of this repository.
2. Click **"Report a vulnerability"**.
3. Include what you'd include in any good bug report: the affected file/function, a
   concrete reproduction (ideally a minimal `SKILL.md` or input that triggers it), and what
   you'd expect to happen instead.

This opens a private GitHub Security Advisory visible only to you and the maintainer(s),
with its own discussion thread, so a fix can be developed and coordinated before any public
disclosure.

## What to expect

This is a small, maintainer-run open-source project, not a project with a dedicated
security team or a bug-bounty program — please calibrate expectations accordingly. There is
no fixed SLA, but reports will get a response and, if confirmed, a fix will be prioritized
over other open work. Coordinated disclosure is appreciated: please give a reasonable
window to land and release a fix before any public write-up.

## Dependency vulnerabilities

Dependency-level vulnerabilities (a CVE in a pinned package, not in this project's own
code) are already handled automatically via [Dependabot](dependabot.yml) and GitHub's
secret-scanning/push-protection, both enabled on this repository. You're welcome to report
one directly too if you'd like, but it's likely already been flagged.
