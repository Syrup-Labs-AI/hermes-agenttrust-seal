"""AgentTrust Seal: a Hermes plugin that seals a file and verifies the seal.

Registers one tool (`agenttrust_seal`) and one slash command (`/agenttrust-seal`), both thin wrappers over core.py.
Opt-in only: when AGENTTRUST_SEAL_GUARD is set, also registers a `pre_tool_call` hook that refuses a
`read_file` of a file whose seal is BROKEN or FORGED.
"""
import json
import os
import re
import sys

# Hermes imports this folder as a package; the selftest loads it by path. Support both.
try:
    from . import core
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import core

SCHEMA = {
    "name": "agenttrust_seal",
    "description": (
        "Seal or verify a file so a handoff can be proven unchanged. "
        "action=seal writes <path>.seal.json (sha256, author, UTC time). "
        "action=verify returns holds=true only if the file still matches its seal. "
        "A missing file or missing seal is refused, never treated as a pass. "
        "Optional: signers makes verify require a valid signature (code 3, SEAL FORGED, if it is "
        "bad or absent). This tool cannot sign: seals it makes are unsigned."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["seal", "verify"], "description": "seal or verify"},
            "path": {"type": "string", "description": "Path of the file to seal or verify"},
            "author": {"type": "string", "description": "Who is sealing (seal only). Default: agent"},
            "include_host": {"type": "boolean",
                             "description": "seal only. Write this machine's hostname into the seal. Default: false"},
            "signers": {"type": "string",
                        "description": "verify only. Path of an OpenSSH allowed-signers file; a valid signature is then required"},
        },
        "required": ["action", "path"],
    },
}


def run(action, path, author="agent", include_host=False, sign_key=None, signers=None):
    """Shared by the tool and the slash command. Returns a dict with code, message, holds."""
    if action == "seal":
        code, msg, rec = core.seal(path, author or "agent", include_host=_truthy(include_host), sign_key=sign_key or None)
        return {"success": code == 0, "code": code, "message": msg, "seal": rec,
                "signed": bool(rec and rec.get("signature"))}
    if action == "verify":
        code, msg = core.verify(path, signers=signers or None)
        return {"success": code != 2, "code": code, "holds": code == 0, "forged": code == 3, "message": msg}
    return {"success": False, "code": 2, "message": f"REFUSED: unknown action {action!r}"}


def _truthy(value):
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


SIGN_REFUSAL = ("REFUSED: the agenttrust_seal tool cannot sign, because the model chooses its arguments. "
                "Nothing was sealed. A person signs with /agenttrust-seal seal <file> --sign <key> or the command line.")


def _tool(params, **kwargs):
    """The tool an agent calls. It seals unsigned and verifies; it never signs, whatever it is passed."""
    del kwargs
    if any(k in params for k in ("sign_key", "sign", "key")):
        return json.dumps({"success": False, "code": 2, "message": SIGN_REFUSAL, "seal": None, "signed": False})
    return json.dumps(run(params.get("action", ""), params.get("path", ""), params.get("author", "agent"),
                          include_host=params.get("include_host", False), signers=params.get("signers")))


_VALUE_FLAG = r"(?:^|\s)--%s\s+(?:\"([^\"]*)\"|'([^']*)'|(.+?))(?=\s+--|\s*$)"


def _pop_flags(raw):
    """Pull --host, --sign <key> and --signers <file> out of the argument text. Flags go last."""
    flags = {"host": False, "sign": None, "signers": None}
    for name in ("signers", "sign"):
        m = re.search(_VALUE_FLAG % name, raw)
        if m:
            flags[name] = next(g for g in m.groups() if g is not None).strip()
            raw = raw[:m.start()] + raw[m.end():]
    m = re.search(r"(?:^|\s)--host(?=\s|$)", raw)
    if m:
        flags["host"] = True
        raw = raw[:m.start()] + raw[m.end():]
    return raw.strip(), flags


def _split_args(raw_args):
    """Return (action, path, author). Paths may contain spaces, quoted or not."""
    raw = (raw_args or "").strip()
    action, _, rest = raw.partition(" ")
    rest = rest.strip()
    author = "agent"
    if not rest:
        return action, "", author
    if rest[0] in "\"'":
        end = rest.find(rest[0], 1)
        if end > 0:
            path, tail = rest[1:end], rest[end + 1:].strip()
            return action, path, (tail or author) if action == "seal" else author
    if action != "seal" or os.path.exists(rest):
        return action, rest, author
    head, _, last = rest.rpartition(" ")
    if head and os.path.exists(head):
        return action, head, last
    return action, rest, author


USAGE = ("Usage: /agenttrust-seal seal <file> [author] [--host] [--sign <ssh-private-key>] | "
         "/agenttrust-seal verify <file> [--signers <allowed-signers-file>]")


def _slash(raw_args):
    raw, flags = _pop_flags(raw_args or "")
    action, path, author = _split_args(raw)
    if action == "seal" and path:
        return run("seal", path, author, include_host=flags["host"], sign_key=flags["sign"])["message"]
    if action == "verify" and path:
        return run("verify", path, signers=flags["signers"])["message"]
    return USAGE


# The guard. Off unless AGENTTRUST_SEAL_GUARD is set when Hermes starts.
GUARD_ENV = "AGENTTRUST_SEAL_GUARD"
GUARD_SIGNERS_ENV = "AGENTTRUST_SEAL_SIGNERS"  # optional path of an allowed-signers file (public keys only)
GUARDED_TOOLS = {"read_file": "path"}


def guard_enabled():
    return _truthy(os.environ.get(GUARD_ENV, ""))


def _guard(tool_name="", args=None, **_):
    """pre_tool_call hook. Blocks a read only when the file has a seal and that seal is BROKEN or FORGED.

    An unsealed file, a missing file, or a seal that cannot be judged is let through: the guard
    refuses on evidence, never on absence.
    """
    key = GUARDED_TOOLS.get(tool_name)
    if not key or not isinstance(args, dict):
        return None
    try:
        path = args.get(key)
        if not isinstance(path, str) or not path:
            return None
        path = os.path.expanduser(path)
        if not os.path.isfile(path) or not os.path.isfile(path + core.SEAL_SUFFIX):
            return None
        code, msg = core.verify(path, signers=os.environ.get(GUARD_SIGNERS_ENV) or None)
    except Exception:  # a guard that cannot judge must not wedge the agent
        return None
    if code in (1, 3):
        return {"action": "block", "message": f"{msg}. AgentTrust Seal guard refused this read."}
    return None


def register(ctx):
    ctx.register_tool(name="agenttrust_seal", toolset="agenttrust_seal", schema=SCHEMA, handler=_tool)
    ctx.register_command("agenttrust-seal", handler=_slash, description="Seal a file or verify its seal",
                         args_hint="seal <file> [author] [--host] [--sign <key>] | verify <file> [--signers <file>]")
    if guard_enabled() and hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_tool_call", _guard)
