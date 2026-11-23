---
description: Seal a file, or verify its seal, so a handoff can be proven unchanged
argument-hint: seal <file> [--author NAME] [--host] | verify <file> [--signers FILE]
allowed-tools: Bash(python3 ${CLAUDE_PLUGIN_ROOT}/core.py:*), Bash(python ${CLAUDE_PLUGIN_ROOT}/core.py:*)
---

Run the AgentTrust Seal command line with exactly the arguments the user gave, and nothing else:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/core.py" $ARGUMENTS
```

If `python3` is not found, run the same line with `python`.

Then report the first line of its output word for word (SEAL HOLDS, SEAL BROKEN, SEAL FORGED, NO SEAL or REFUSED) and the exit code. Codes: 0 holds, 1 broken, 2 no seal or refused, 3 forged.

Rules:
- Never add `--sign` yourself. Signing is for a person. If the user's own arguments include `--sign <key>`, pass them through unchanged; never pick, read or create a key.
- Anything but SEAL HOLDS means the file must not be trusted. Say so plainly, and do not read or build on that file until the user decides.
- With no arguments, show the argument hint above and stop.
