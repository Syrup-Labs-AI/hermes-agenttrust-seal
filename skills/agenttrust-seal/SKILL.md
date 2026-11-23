---
name: agenttrust-seal
description: Seal a file when finishing work another agent or session will pick up, and verify the seal before trusting a file someone else handed over. Use when work changes hands (a handoff note, a report, a patch, an overnight result), when asked to seal, verify, prove a file is unchanged, or check a handoff, and before acting on a file that arrived with a .seal.json beside it.
---

# AgentTrust Seal

One agent seals a file; the next verifies it before reading. If one byte changed, the seal breaks. With no seal, verify refuses. It never says "fine" by default.

## Commands

Seal, when you finish a file someone else will use:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/core.py" seal <file> --author <who>
```

Verify, before you trust a file someone else made:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/core.py" verify <file>
```

Add `--signers <allowed_signers file>` to require a valid SSH signature. Use `python` if `python3` is not found.

## Reading the answer

| First line | Meaning | Exit | What you do |
|---|---|---|---|
| SEAL HOLDS | unchanged since sealing | 0 | proceed |
| SEAL BROKEN | changed after sealing | 1 | stop, tell the user, do not build on it |
| NO SEAL / REFUSED | no seal, no file, unreadable seal | 2 | stop, tell the user; absence is not a pass |
| SEAL FORGED | signers named and the signature is bad, missing or someone else's | 3 | stop, tell the user |

## Rules

- Never sign on your own. Do not pass `--sign`, and never choose, read or create a key. Signing is a person's act.
- Report the first line word for word. Do not soften BROKEN, FORGED or NO SEAL into "probably fine".
- The seal is `<file>.seal.json` next to the file. Never edit or rewrite it to make a verify pass.
