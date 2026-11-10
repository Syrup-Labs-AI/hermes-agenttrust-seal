# Baton

A Hermes plugin that proves a handoff was not changed.

One agent finishes a file and seals it. The next agent verifies the seal before trusting the file. If one byte changed, the seal breaks. If there is no seal, verify refuses. It never says "fine" by default.

## What it adds

- Slash command: `/baton seal <file> [author]` and `/baton verify <file>`
- Tool: `baton` (action `seal` or `verify`, plus `path`, optional `author`), so an agent can call it by itself

A seal is a small file next to the original: `<file>.seal.json`. It holds the sha256, size, author, UTC time, git commit if any, and host. The format matches the shell tool `baton-seal`, so either one can verify the other's seals.

Results:

| Verify says | Meaning | Code |
|---|---|---|
| SEAL HOLDS | File is unchanged since sealing | 0 |
| SEAL BROKEN | File changed after sealing | 1 |
| NO SEAL / REFUSED | No seal, no file, or unreadable seal | 2 |

Local only. No network, no keys, no background work.

## Check it first (no install)

Where: a terminal on the machine with this folder.

```bash
python3 baton/selftest.py
```

You should see one line starting `SELFTEST PASS`. Any `SELFTEST FAIL` line means stop.

```bash
hermes plugins validate baton
```

You should see `Validation passed.`

## Install

Where: a terminal on the machine that runs Hermes. When: after the check above passes. This changes your live Hermes, so do it on purpose.

1. Copy the folder in:
   ```bash
   cp -r baton ~/.hermes/plugins/baton
   ```
2. Turn it on (plugins are off until you opt in):
   ```bash
   hermes plugins enable baton
   ```
3. Restart Hermes so it loads the plugin. For the gateway or dashboard, relaunch that process.
4. In a Hermes chat, type `/baton` and you should see the usage line.

## Use it

```
/baton seal handoff.md alan
/baton verify handoff.md
```

Then edit `handoff.md` and run verify again. It says `SEAL BROKEN`.

## Remove

```bash
hermes plugins disable baton
rm -r ~/.hermes/plugins/baton
```

## Files

- `plugin.yaml` manifest (declares the `baton` tool)
- `__init__.py` registers the tool and the slash command
- `core.py` seal and verify logic, standard library only
- `selftest.py` proves hold, tamper caught, missing seal refused
