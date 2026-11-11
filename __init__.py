"""AgentTrust Seal: a Hermes plugin that seals a file and verifies the seal.

Registers one tool (`agenttrust_seal`) and one slash command (`/agenttrust-seal`), both thin wrappers over core.py.
"""
import json
import os
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
        "A missing file or missing seal is refused, never treated as a pass."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["seal", "verify"], "description": "seal or verify"},
            "path": {"type": "string", "description": "Path of the file to seal or verify"},
            "author": {"type": "string", "description": "Who is sealing (seal only). Default: agent"},
        },
        "required": ["action", "path"],
    },
}


def run(action, path, author="agent"):
    """Shared by the tool and the slash command. Returns a dict with code, message, holds."""
    if action == "seal":
        code, msg, rec = core.seal(path, author or "agent")
        return {"success": code == 0, "code": code, "message": msg, "seal": rec}
    if action == "verify":
        code, msg = core.verify(path)
        return {"success": code != 2, "code": code, "holds": code == 0, "message": msg}
    return {"success": False, "code": 2, "message": f"REFUSED: unknown action {action!r}"}


def _tool(params, **kwargs):
    del kwargs
    return json.dumps(run(params.get("action", ""), params.get("path", ""), params.get("author", "agent")))


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


def _slash(raw_args):
    action, path, author = _split_args(raw_args)
    if action in ("seal", "verify") and path:
        return run(action, path, author)["message"]
    return "Usage: /agenttrust-seal seal <file> [author] | /agenttrust-seal verify <file>"


def register(ctx):
    ctx.register_tool(name="agenttrust_seal", toolset="agenttrust_seal", schema=SCHEMA, handler=_tool)
    ctx.register_command("agenttrust-seal", handler=_slash, description="Seal a file or verify its seal",
                         args_hint="seal <file> [author] | verify <file>")
