# Skill Packs

A **skill pack** is a single `SKILL.md` file that teaches K.O.D.A. a
specific operational pattern — "how to run Sherlock for OSINT username
recon", "how to triage an open-port drift alert", etc. No code required.

## Where K.O.D.A. looks

Search order, first wins:

1. `./skills/` — project-local (checked into the repo for team engagements)
2. `~/.koda/skills/` — per-user packs
3. `$KODA_SKILLS_PATH` — colon-separated (OS-path style)

Packs are registered at import time into `DEFAULT_REGISTRY` and become
available to the NLU router and the LLM via the system prompt.

## Frontmatter

Every `SKILL.md` starts with YAML frontmatter:

```yaml
---
name: sherlock
description: OSINT username search across 400+ platforms
mode: red              # red | blue | purple
phase: recon           # recon | enumeration | exploitation | post | ir | audit | harden | hunt | report
attack_techniques:     # ATT&CK IDs (optional but helpful for NLU + audit tagging)
  - T1589              # Gather Victim Identity Information
  - T1593              # Search Open Websites/Domains
tools_required:        # binaries / tools the skill needs
  - sherlock
  - username
---
```

Required keys: `name`, `description`, `mode`, `phase`. Everything else
is optional.

## Body

Under the frontmatter, write the **operator-voice prompt fragment** —
what the LLM should know when this skill is in play. Terse, direct,
second-person. Think "how a senior operator would brief a junior one",
not "documentation."

Example:

```markdown
When asked to recon a username, use sherlock. Always confirm the
username is in scope per the engagement ROE before starting.

Steps:
1. `sherlock <username> --print-found` — fastest read
2. For a specific platform set, use `--site-list` with the platforms
   you care about
3. Record every hit in the evidence store with the platform name and
   the profile URL
4. If sherlock returns zero hits, try the username with common suffixes
   (01, _real, .official) before concluding
```

## Test your pack

```bash
koda doctor    # shows skill load errors if your frontmatter is malformed
```

See `skills/sherlock/SKILL.md` in the repo for a full reference.

## Contributing a skill pack

We welcome skill pack PRs — they're the easiest way to contribute, and
they directly expand what K.O.D.A. can do.

- Drop your pack into `skills/<name>/SKILL.md`
- Include the ATT&CK technique IDs if applicable
- Write the body in operator voice
- Open a PR — no code review needed, just docs/content review

See [CONTRIBUTING.md](https://github.com/PabloTheThinker/K.O.D.A./blob/main/CONTRIBUTING.md)
for the PR flow.
