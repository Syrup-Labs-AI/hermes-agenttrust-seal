"""Baton core: seal a file and verify the seal. Pure stdlib, no Hermes imports.

Seal format matches the companion shell tool baton-seal, so either tool verifies the other's seals.
Verify codes: 0 SEAL HOLDS, 1 SEAL BROKEN, 2 refused (no file, no seal, or unreadable seal).
"""
import hashlib
import json
import os
import socket
import subprocess
from datetime import datetime, timezone

SEAL_SUFFIX = ".seal.json"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit(path):
    try:
        out = subprocess.run(["git", "-C", os.path.dirname(os.path.abspath(path)), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def seal(path, author="agent"):
    """Write <path>.seal.json. Returns (code, message, seal_dict_or_None)."""
    if not os.path.isfile(path):
        return 2, f"REFUSED: no such file {path}", None
    rec = {
        "file": os.path.basename(path),
        "sha256": _sha256(path),
        "bytes": os.path.getsize(path),
        "author": author,
        "sealed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git_commit(path),
        "host": socket.gethostname(),
    }
    with open(path + SEAL_SUFFIX, "w") as f:
        json.dump(rec, f)
        f.write("\n")
    return 0, f"SEALED {path}  sha256 {rec['sha256'][:16]}...  by {author}  {rec['sealed_at']}", rec


def verify(path):
    """Check <path> against <path>.seal.json. Returns (code, message)."""
    if not os.path.isfile(path):
        return 2, f"REFUSED: no such file {path}"
    sp = path + SEAL_SUFFIX
    if not os.path.isfile(sp):
        return 2, f"NO SEAL: {sp} missing"
    try:
        with open(sp) as f:
            want = json.load(f)["sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        return 2, f"NO SEAL: {sp} is unreadable or has no sha256"
    if want == _sha256(path):
        return 0, f"SEAL HOLDS: {path} unchanged since sealing"
    return 1, f"SEAL BROKEN: {path} was changed after sealing"
