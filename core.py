"""AgentTrust Seal core: seal a file and verify the seal. Pure stdlib, no Hermes imports.

Seal format matches the companion shell tool baton-seal, so either tool verifies the other's seals.
Verify codes: 0 SEAL HOLDS, 1 SEAL BROKEN, 2 refused (no file, no seal, unreadable seal, or a
signature that could not be checked), 3 SEAL FORGED (a signature was required and is bad, absent,
or made for a different record or file name).

The signature covers the whole seal record (namespace, file name, sha256, size, author, time, commit,
and host if present), not only the sha256, so a signed seal cannot be edited or moved to another file.

Signing is optional and uses the ssh-keygen already on the machine. This module never creates a key,
never opens a key file, and never reads a key from the environment: it hands the path you name to
ssh-keygen and stores the signature ssh-keygen prints.

Command line: python core.py seal <file> [--author NAME] [--host] [--sign KEY]
              python core.py verify <file> [--signers ALLOWED_SIGNERS]
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SEAL_SUFFIX = ".seal.json"
SIG_NAMESPACE = "agenttrust-seal"


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


def _ssh_keygen():
    """Path of ssh-keygen, or None when the machine has none."""
    return shutil.which("ssh-keygen")


def _payload(rec):
    """The exact bytes a signature covers: every field of the seal record except the signature itself."""
    body = {k: v for k, v in rec.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sign(payload, key_path):
    """Sign the payload bytes with ssh-keygen. Returns (signature_text, error_text)."""
    exe = _ssh_keygen()
    if not exe:
        return "", "ssh-keygen was not found on this machine"
    try:
        out = subprocess.run([exe, "-Y", "sign", "-f", key_path, "-n", SIG_NAMESPACE],
                             input=payload, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return "", str(e)
    sig = out.stdout.decode("ascii", "replace").replace("\r\n", "\n").strip()
    if out.returncode != 0 or "BEGIN SSH SIGNATURE" not in sig:
        err = out.stderr.decode("utf-8", "replace").strip().splitlines()
        return "", (err[-1] if err else f"ssh-keygen exit {out.returncode}")
    return sig + "\n", ""


def _check_signature(payload, signature, signers):
    """Returns (ok, principal_or_reason). ok is True only when ssh-keygen accepts the signature."""
    exe = _ssh_keygen()
    if not exe:
        return False, "ssh-keygen was not found on this machine"
    tmp = tempfile.mkdtemp(prefix="agenttrust-seal-")
    try:
        sigfile = os.path.join(tmp, "seal.sig")
        with open(sigfile, "w", newline="\n") as f:
            f.write(signature if signature.endswith("\n") else signature + "\n")
        found = subprocess.run([exe, "-Y", "find-principals", "-s", sigfile, "-f", signers],
                               capture_output=True, timeout=30)
        names = found.stdout.decode("utf-8", "replace").split()
        if found.returncode != 0 or not names:
            return False, "the signing key is not in the signers file"
        for name in names:
            ok = subprocess.run([exe, "-Y", "verify", "-f", signers, "-I", name, "-n", SIG_NAMESPACE,
                                 "-s", sigfile], input=payload, capture_output=True, timeout=30)
            if ok.returncode == 0:
                return True, name
        return False, "the signature does not match this seal record"
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def seal(path, author="agent", include_host=False, sign_key=None):
    """Write <path>.seal.json. Returns (code, message, seal_dict_or_None).

    include_host: off by default. Only when true is this machine's hostname written into the seal.
    sign_key: path of an existing SSH private key. When given, the seal carries a signature.
    """
    if not os.path.isfile(path):
        return 2, f"REFUSED: no such file {path}", None
    rec = {
        "file": os.path.basename(path),
        "sha256": _sha256(path),
        "bytes": os.path.getsize(path),
        "author": author,
        "sealed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git_commit(path),
    }
    if include_host:
        rec["host"] = socket.gethostname()
    signed = ""
    if sign_key:
        sign_key = os.path.expanduser(sign_key)
        if not os.path.isfile(sign_key):
            return 2, f"REFUSED: no such key file {sign_key} (nothing was sealed; this tool never creates keys)", None
        if not _ssh_keygen():
            signed = "  UNSIGNED: ssh-keygen was not found on this machine, so the seal carries no signature"
        else:
            rec["signature_namespace"] = SIG_NAMESPACE
            sig, err = _sign(_payload(rec), sign_key)
            if not sig:
                return 2, f"REFUSED: signing failed, nothing was sealed ({err})", None
            rec["signature"] = sig
            signed = "  SIGNED"
    with open(path + SEAL_SUFFIX, "w") as f:
        json.dump(rec, f)
        f.write("\n")
    return 0, f"SEALED {path}  sha256 {rec['sha256'][:16]}...  by {author}  {rec['sealed_at']}{signed}", rec


def verify(path, signers=None):
    """Check <path> against <path>.seal.json. Returns (code, message).

    signers: path of an OpenSSH allowed-signers file. When given, the seal must carry a signature
    that one of those signers made, or the answer is SEAL FORGED (3).
    """
    if not os.path.isfile(path):
        return 2, f"REFUSED: no such file {path}"
    sp = path + SEAL_SUFFIX
    if not os.path.isfile(sp):
        return 2, f"NO SEAL: {sp} missing"
    try:
        with open(sp) as f:
            rec = json.load(f)
        want = rec["sha256"]
        signature = rec.get("signature", "")
        payload = _payload(rec)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return 2, f"NO SEAL: {sp} is unreadable or has no sha256"
    note = ""
    if signers:
        signers = os.path.expanduser(signers)
        if not os.path.isfile(signers):
            return 2, f"REFUSED: no such signers file {signers}"
        if not isinstance(want, str) or not isinstance(signature, str) or not signature.strip():
            return 3, f"SEAL FORGED: {path} has a seal with no signature, and a signature was required"
        if not _ssh_keygen():
            return 2, "REFUSED: ssh-keygen was not found on this machine, so the signature cannot be checked"
        ok, detail = _check_signature(payload, signature, signers)
        if not ok:
            return 3, f"SEAL FORGED: {path} has a seal whose signature fails ({detail})"
        if rec.get("signature_namespace") != SIG_NAMESPACE or rec.get("file") != os.path.basename(path):
            return 3, (f"SEAL FORGED: {path} carries a signed seal made for another file "
                       f"({rec.get('file')!r}), so it does not vouch for this one")
        note = f"; signed by {detail}, sealed {rec.get('sealed_at')} by {rec.get('author')}"
    elif signature:
        note = "; the seal is signed but the signature was NOT checked (name a signers file to check it)"
    if want == _sha256(path):
        return 0, f"SEAL HOLDS: {path} unchanged since sealing{note}"
    return 1, f"SEAL BROKEN: {path} was changed after sealing{note}"


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="agenttrust-seal", description="Seal a file or verify its seal.")
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("seal")
    s.add_argument("path")
    s.add_argument("--author", default="agent")
    s.add_argument("--host", action="store_true", help="write this machine's hostname into the seal")
    s.add_argument("--sign", metavar="KEY", help="path of an existing SSH private key to sign with")
    v = sub.add_parser("verify")
    v.add_argument("path")
    v.add_argument("--signers", metavar="FILE", help="OpenSSH allowed-signers file; requires a valid signature")
    a = p.parse_args(argv)
    if a.action == "seal":
        code, msg, _ = seal(a.path, a.author, include_host=a.host, sign_key=a.sign)
    else:
        code, msg = verify(a.path, signers=a.signers)
    print(msg)
    return code


if __name__ == "__main__":
    sys.exit(main())
