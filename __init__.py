"""Baton: a Hermes plugin that seals a file and verifies the seal.

Registers one tool (`baton`) and one slash command (`/baton`), both thin wrappers over core.py.
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
    "name": "baton",
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


def _slash(raw_args):
    parts = (raw_args or "").split()
    if len(parts) >= 2 and parts[0] in ("seal", "verify"):
        author = parts[2] if parts[0] == "seal" and len(parts) > 2 else "agent"
        return run(parts[0], parts[1], author)["message"]
    return "Usage: /baton seal <file> [author] | /baton verify <file>"


def register(ctx):
    ctx.register_tool(name="baton", toolset="baton", schema=SCHEMA, handler=_tool)
    ctx.register_command("baton", handler=_slash, description="Seal a file or verify its seal",
                         args_hint="seal <file> [author] | verify <file>")
