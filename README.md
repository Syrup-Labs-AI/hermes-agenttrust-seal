# AgentTrust Seal

A Hermes plugin that proves a handoff was not changed.

One agent finishes a file and seals it. The next agent verifies the seal before trusting the file. If one byte changed, the seal breaks. If there is no seal, verify refuses. It never says "fine" by default.

## Who it is for, and why

Agents report success all the time, and nothing checks it. When one agent hands a file to the next (research notes to a writer, a patch to a reviewer, an overnight report to the morning run), the second agent trusts whatever is sitting there.

- Who: anyone running more than one Hermes agent, a scheduled job, or a handoff between sessions or machines.
- When: at the moment work changes hands. The finishing agent seals; the receiving agent verifies before it reads.
- What you get: one of four answers (SEAL HOLDS, SEAL BROKEN, SEAL FORGED, NO SEAL) and a code an agent can act on, so a changed or half-written file stops the chain instead of being built on.
- Where: in a Hermes chat or the desktop app with `/agenttrust-seal`, as the `agenttrust_seal` tool an agent calls by itself, or from a terminal with `python core.py`.

This is the first small, free piece of AgentTrust: proof for what AI agents say they did.

## What it adds

- Slash command: `/agenttrust-seal seal <file> [author] [--host] [--sign <key>]` and `/agenttrust-seal verify <file> [--signers <file>]`. Put the flags last.
- Tool: `agenttrust_seal` (action `seal` or `verify`, plus `path`, optional `author`, `include_host`, `sign_key`, `signers`), so an agent can call it by itself.
- Command line: `python core.py seal <file> [--author NAME] [--host] [--sign KEY]` and `python core.py verify <file> [--signers FILE]`. The exit code is the code in the table below.
- Optional guard: a `pre_tool_call` hook that refuses a `read_file` of a file whose seal is BROKEN or FORGED. Off unless you turn it on (see "Guard").

A seal is a small file next to the original: `<file>.seal.json`. It holds the sha256, size, author, UTC time and git commit if any. It holds the hostname only if you ask (`--host`, or `include_host: true`), and a signature only if you sign. The format matches the shell tool `baton-seal`, so either one can verify the other's seals. Seals made by earlier versions, which always carried a `host` field, still verify.

Results:

| Verify says | Meaning | Code |
|---|---|---|
| SEAL HOLDS | File is unchanged since sealing | 0 |
| SEAL BROKEN | File changed after sealing | 1 |
| NO SEAL / REFUSED | No seal, no file, unreadable seal, or a signature that could not be checked | 2 |
| SEAL FORGED | You named signers, and the seal's signature is bad, by someone else, or missing | 3 |

Local only. No network, no background work.

## Signed seals (optional)

An unsigned seal proves the file matches the seal. It does not prove who made the seal: anyone who can rewrite both files can make a new seal that holds. A signed seal closes that gap.

```
/agenttrust-seal seal handoff.md alan --sign ~/.ssh/id_ed25519
/agenttrust-seal verify handoff.md --signers ~/.ssh/allowed_signers
```

- Sealing with `--sign` runs `ssh-keygen -Y sign -n agenttrust-seal` over the file's sha256 with the key you name, and stores the signature in the seal.
- Verifying with `--signers` runs `ssh-keygen -Y verify` against the allowed-signers file you name. That file is the standard OpenSSH one: one line per trusted person, `name key-type public-key`.
- Once you name signers, a signature is required. A seal with a bad signature, a signature by a key that is not in the file, or no signature at all is SEAL FORGED, code 3.
- Without `--signers`, nothing changes from earlier versions. A signed seal still verifies by hash, and the answer says the signature was not checked.
- The plugin never creates a key, never opens your key file, and never reads a key from an environment variable. It passes the path to `ssh-keygen`. A key with a passphrase needs an agent or will fail, and a failed signing seals nothing.
- If `ssh-keygen` is not installed: sealing still works and says plainly that the seal is UNSIGNED; verifying with `--signers` refuses (code 2), it does not pass.

## Guard (optional, off by default)

Verifying is something an agent has to remember to do. The guard does it for the agent.

Set this before Hermes starts:

```bash
export AGENTTRUST_SEAL_GUARD=1
# optional: also require a valid signature on every sealed file
export AGENTTRUST_SEAL_SIGNERS=~/.ssh/allowed_signers
```

With the guard on, the plugin registers a Hermes `pre_tool_call` hook. When an agent calls `read_file` on a file that has a seal, the seal is checked first. BROKEN or FORGED blocks the read and tells the agent why. Everything else is let through: a file with no seal, a seal that holds, a missing file, any other tool.

## Check it first (no install)

Where: a terminal, inside your clone of this repo.

```bash
python3 selftest.py
```

You should see one line starting `SELFTEST PASS`. Any `SELFTEST FAIL` line means stop.

```bash
hermes plugins validate .
```

You should see `Validation passed.`

## Install

Where: a terminal on the machine that runs Hermes. This changes your live Hermes, so do it on purpose.

1. Clone the repo straight into the plugins folder. The plugin's files sit at the root of the repo, so the clone is the plugin:
   ```bash
   git clone https://github.com/Syrup-Labs-AI/hermes-agenttrust-seal ~/.hermes/plugins/agenttrust-seal
   ```
2. Check it where it landed:
   ```bash
   python3 ~/.hermes/plugins/agenttrust-seal/selftest.py
   ```
3. Turn it on (plugins are off until you opt in):
   ```bash
   hermes plugins enable agenttrust-seal
   ```
4. Restart Hermes so it loads the plugin. For the gateway or dashboard, relaunch that process.
5. In a Hermes chat, type `/agenttrust-seal` and you should see the usage line.

## Use it

```
/agenttrust-seal seal handoff.md alan
/agenttrust-seal verify handoff.md
```

Then edit `handoff.md` and run verify again. It says `SEAL BROKEN`.

## Remove

```bash
hermes plugins disable agenttrust-seal
rm -r ~/.hermes/plugins/agenttrust-seal
```

## Files

- `plugin.yaml` manifest (declares the `agenttrust_seal` tool and the `pre_tool_call` hook)
- `__init__.py` registers the tool, the slash command and, when opted in, the guard
- `core.py` seal, sign and verify logic, standard library only; also the command line
- `selftest.py` proves hold, tamper caught, missing seal refused, hostname off by default, forged seal caught, guard blocks only when opted in
- `.github/workflows/test.yml` runs the selftest on Linux, Windows and macOS

## Disclosure

What this plugin does on your machine, in full:

- Network calls: none.
- Credentials: none stored, none read by the plugin. If you sign, you name a private key path and the plugin passes that path to `ssh-keygen`; it does not open the key itself, and it never looks for a key on its own.
- Environment variables: none required. Two are read if you set them: `AGENTTRUST_SEAL_GUARD` (turns the guard on) and `AGENTTRUST_SEAL_SIGNERS` (path of an allowed-signers file for the guard; public keys only).
- Background processes: none. It runs when the tool, the slash command or the command line is called, and, with the guard on, once before each `read_file` call.
- Shell commands: `git rev-parse --short HEAD` in the file's folder when sealing, to record the commit if the folder is a git checkout (empty if not, or if git is missing). `ssh-keygen -Y sign` only when you seal with a key. `ssh-keygen -Y find-principals` and `ssh-keygen -Y verify` only when you verify with signers.
- Files written: `<file>.seal.json`, next to the file being sealed. It holds the sha256, size, author name, UTC time and the short git commit if any; the signature if you signed; this machine's hostname only if you asked for it. When checking a signature, one temporary file holding the signature (public data) is written to the system temp folder and deleted.
- Files read: the file you name, its seal, and the signers file you name.

## Limits

- By default the seal detects a change; it does not prevent one. The optional guard stops a Hermes agent's `read_file` of a broken or forged file. It does not cover other ways to read a file (a `cat` in the terminal tool, another program), it does not stop anyone writing to the file, and it only judges files that have a seal.
- An unsigned seal records a name, not a signature, so it does not prove who sealed the file, and anyone who can rewrite both the file and its seal can make a new seal that holds. A signed seal checked with `--signers` closes this: a re-made seal is SEAL FORGED unless it is signed by a key in your signers file.
- A signature is only as good as the key. Anyone holding a private key listed in your signers file can make a seal that holds.
- The signature covers the file's sha256. The author name, time, commit and hostname in the seal are notes, not signed facts.
- Signing needs `ssh-keygen` with `-Y` support (OpenSSH 8.2 or later).
- The guard relies on Hermes honouring a `block` from a plugin's `pre_tool_call` hook.

## Not checked

What the selftest and CI do not prove:

- The guard is tested by calling the hook the way the Hermes docs describe (`tool_name`, `args`, a `{"action": "block", ...}` return). It has not been run inside a live Hermes session by the automated tests.
- Keys with a passphrase, hardware keys and keys held in an ssh agent are not tested. The test key is a throwaway ed25519 key with no passphrase, made and deleted inside the test's temp folder.
- Interop with the shell tool `baton-seal` is checked only on a machine that has it; CI does not.
- CI runs `hermes plugins validate` against Hermes installed from the upstream release tags, because PyPI's `hermes-agent` stops below this plugin's floor. See the workflow for the exact versions.

## Tested on

Hermes Agent 0.22.2 (Linux) and 0.22.7 (Windows) for the tool and slash command. The selftest runs in CI on Linux, Windows and macOS, Python 3.10 to 3.13. Paths with spaces work, quoted or not.
