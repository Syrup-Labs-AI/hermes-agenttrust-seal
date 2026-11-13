#!/usr/bin/env python3
"""AgentTrust Seal selftest: seal-holds, tamper-caught, missing-seal-refused, hostname off by default,
signed seals and SEAL FORGED, the opt-in read guard, plus register() wiring.
Run: python3 selftest.py   (exit 0 and a SELFTEST PASS line, or exit 1 with the failing check)
Signing checks use a throwaway key made inside this test's temp folder and deleted with it.
Set AGENTTRUST_SEAL_REQUIRE_SSH=1 to fail, not skip, when ssh-keygen is absent.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("baton_plugin", os.path.join(HERE, "__init__.py"),
                                              submodule_search_locations=[HERE])
baton = importlib.util.module_from_spec(spec)
sys.modules["baton_plugin"] = baton
spec.loader.exec_module(baton)


def fail(msg):
    print(f"SELFTEST FAIL: {msg}")
    sys.exit(1)


class FakeCtx:
    def __init__(self):
        self.tools, self.commands, self.hooks = {}, {}, {}

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = handler

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)


tmp = tempfile.mkdtemp()
try:
    f = os.path.join(tmp, "handoff.md")
    with open(f, "w") as fh:
        fh.write("state: green\n")

    # 1. seal holds, through the tool an agent would call
    ctx = FakeCtx()
    baton.register(ctx)
    s = json.loads(ctx.tools["agenttrust_seal"]({"action": "seal", "path": f, "author": "selftest"}))
    v = json.loads(ctx.tools["agenttrust_seal"]({"action": "verify", "path": f}))
    if not (s["success"] and v["holds"] and v["code"] == 0):
        fail(f"clean seal did not hold: {s} {v}")

    # 2. tamper caught, through the slash command
    with open(f, "a") as fh:
        fh.write("state: red\n")
    out = ctx.commands["agenttrust-seal"](f"verify {f}")
    if not out.startswith("SEAL BROKEN"):
        fail(f"tamper not caught: {out}")
    if json.loads(ctx.tools["agenttrust_seal"]({"action": "verify", "path": f}))["holds"]:
        fail("tamper reported as holding")

    # 2b. a path with a space works through the slash command, with and without an author
    sp = os.path.join(tmp, "my folder")
    os.makedirs(sp, exist_ok=True)
    q = os.path.join(sp, "hand off.md")
    with open(q, "w") as fh:
        fh.write("spaced" + chr(10))
    if not ctx.commands["agenttrust-seal"](f"seal {q} selftest").startswith("SEALED"):
        fail("seal refused a path with a space")
    if not ctx.commands["agenttrust-seal"](f'verify "{q}"').startswith("SEAL HOLDS"):
        fail("verify refused a quoted path with a space")
    if not ctx.commands["agenttrust-seal"](f"verify {q}").startswith("SEAL HOLDS"):
        fail("verify refused an unquoted path with a space")

    # 3. missing seal refused (also missing file, corrupt seal)
    g = os.path.join(tmp, "never-sealed.md")
    with open(g, "w") as fh:
        fh.write("x")
    r = json.loads(ctx.tools["agenttrust_seal"]({"action": "verify", "path": g}))
    if r["code"] != 2 or r["holds"]:
        fail(f"missing seal not refused: {r}")
    if baton.core.verify(os.path.join(tmp, "ghost.md"))[0] != 2:
        fail("missing file not refused")
    with open(g + ".seal.json", "w") as fh:
        fh.write("not json")
    if baton.core.verify(g)[0] != 2:
        fail("corrupt seal not refused")

    # 4. interop: a seal written here verifies under the shell baton-seal (skipped if absent)
    shell = shutil.which("baton-seal") or ""
    note = "interop skipped (no baton-seal here)"
    if shell and os.path.exists(shell):
        h = os.path.join(tmp, "interop.md")
        with open(h, "w") as fh:
            fh.write("hello")
        baton.core.seal(h, "selftest")
        rc = subprocess.run([shell, "verify", h], capture_output=True).returncode
        if rc != 0:
            fail(f"shell baton-seal rejected a Python seal (rc {rc})")
        note = "Python seal verified by shell baton-seal"

    def tool(**kw):
        return json.loads(ctx.tools["agenttrust_seal"](kw))

    slash = ctx.commands["agenttrust-seal"]

    def operator_seal(p, author="agent", sign_key=None):
        """What the slash command and the command line reach; the tool never passes a key here."""
        return baton.run("seal", p, author, sign_key=sign_key)

    def fresh(name, text="state: green\n"):
        p = os.path.join(tmp, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def seal_of(p):
        with open(p + ".seal.json") as fh:
            return json.load(fh)

    # 5. hostname: off by default, on only when asked, and an old seal that has one still verifies
    h1 = fresh("nohost.md")
    r = tool(action="seal", path=h1)
    if "host" in r["seal"] or "host" in seal_of(h1):
        fail("hostname written without being asked")
    slash(f"seal {h1} selftest")
    if "host" in seal_of(h1):
        fail("slash command wrote the hostname without --host")
    if tool(action="seal", path=h1, include_host=True)["seal"].get("host") != baton.core.socket.gethostname():
        fail("include_host=true did not record the hostname")
    slash(f"seal {h1} selftest --host")
    if "host" not in seal_of(h1) or seal_of(h1)["author"] != "selftest":
        fail("slash --host did not record the hostname, or lost the author")
    old = seal_of(h1)
    old["host"] = "some-old-machine"
    with open(h1 + ".seal.json", "w") as fh:
        json.dump(old, fh)
    if tool(action="verify", path=h1)["code"] != 0:
        fail("an old seal with a host field no longer verifies")

    # 6. ssh-keygen missing: sealing falls back to unsigned and says so; a required signature is refused, not passed
    real_keygen = baton.core._ssh_keygen
    fakekey = fresh("not-a-real-key", "placeholder, never read by the plugin\n")
    u = fresh("nokeygen.md")
    baton.core._ssh_keygen = lambda: None
    try:
        r = operator_seal(u, sign_key=fakekey)
        if r["code"] != 0 or r["signed"] or "signature" in seal_of(u) or "UNSIGNED" not in r["message"] \
                or "ssh-keygen" not in r["message"]:
            fail(f"missing ssh-keygen did not fall back to a clearly unsigned seal: {r}")
        if baton.core._sign(b"0" * 64, fakekey)[0] or baton.core._check_signature(b"0" * 64, "x", fakekey)[0]:
            fail("signing helpers did not return early without ssh-keygen")
        rec = seal_of(u)
        rec["signature"] = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
        with open(u + ".seal.json", "w") as fh:
            json.dump(rec, fh)
        r = tool(action="verify", path=u, signers=fakekey)
        if r["code"] != 2 or r["holds"] or "ssh-keygen" not in r["message"]:
            fail(f"a signature that cannot be checked was not refused: {r}")
    finally:
        baton.core._ssh_keygen = real_keygen
    if operator_seal(u, sign_key=os.path.join(tmp, "no-such-key"))["code"] != 2:
        fail("a missing key file was not refused")

    # 7. signed seals, with a throwaway key that lives and dies in this temp folder
    keygen = baton.core._ssh_keygen()
    if not keygen:
        if os.environ.get("AGENTTRUST_SEAL_REQUIRE_SSH"):
            fail("ssh-keygen is required here and was not found")
        sign_note = "signing skipped (no ssh-keygen here)"
    else:
        def newkey(name):
            k = os.path.join(tmp, name)
            made = subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", k], capture_output=True)
            if made.returncode != 0:
                fail(f"could not make the throwaway test key: {made.stderr.decode(errors='replace')}")
            with open(k + ".pub") as fh:
                return k, " ".join(fh.read().split()[:2])
        key, pub = newkey("throwaway")
        other, other_pub = newkey("stranger")
        signers = os.path.join(tmp, "allowed signers")
        with open(signers, "w", newline="\n") as fh:
            fh.write(f"selftest@example {pub}\n")
        wrong = os.path.join(tmp, "wrong_signers")
        with open(wrong, "w", newline="\n") as fh:
            fh.write(f"stranger@example {other_pub}\n")

        d = fresh("signed.md")
        r = operator_seal(d, author="selftest", sign_key=key)
        if not (r["code"] == 0 and r["signed"] and "BEGIN SSH SIGNATURE" in seal_of(d).get("signature", "")):
            fail(f"seal with a key did not store a signature: {r['message']}")
        r = tool(action="verify", path=d, signers=signers)
        if r["code"] != 0 or "selftest@example" not in r["message"]:
            fail(f"a good signature did not hold: {r}")
        r = tool(action="verify", path=d)
        if r["code"] != 0 or "NOT checked" not in r["message"]:
            fail(f"a signed seal verified without signers should hold and say the signature was not checked: {r}")
        if tool(action="verify", path=d, signers=wrong)["code"] != 3:
            fail("a signature by a key outside the signers file was not FORGED")
        if tool(action="verify", path=d, signers=os.path.join(tmp, "no-signers"))["code"] != 2:
            fail("a missing signers file was not refused")
        good = seal_of(d)

        # the attack the unsigned seal cannot catch: change the file, then re-seal it
        with open(d, "a") as fh:
            fh.write("state: red\n")
        if tool(action="verify", path=d, signers=signers)["code"] != 1:
            fail("a changed file under a good signature was not BROKEN")
        tool(action="seal", path=d, author="selftest")
        if tool(action="verify", path=d)["code"] != 0:
            fail("an unsigned re-seal should hold when no signature is asked for (unchanged behaviour)")
        r = tool(action="verify", path=d, signers=signers)
        if r["code"] != 3 or not r["forged"] or not r["message"].startswith("SEAL FORGED"):
            fail(f"an unsigned re-seal passed where a signature was required: {r}")
        resealed = seal_of(d)
        resealed["signature"] = good["signature"]  # old signature pasted onto the new record
        resealed["signature_namespace"] = good["signature_namespace"]
        with open(d + ".seal.json", "w") as fh:
            json.dump(resealed, fh)
        if tool(action="verify", path=d, signers=signers)["code"] != 3:
            fail("a signature copied from another seal was not FORGED")
        operator_seal(d, sign_key=other)
        if tool(action="verify", path=d, signers=signers)["code"] != 3:
            fail("a re-seal signed by a stranger's key was not FORGED")

        # the signature binds the whole record: no field can be edited, and the seal cannot move to another file
        m = fresh("bound.md")
        operator_seal(m, author="selftest", sign_key=key)
        signed_rec = seal_of(m)
        for field, value in (("author", "someone-else"), ("sealed_at", "2099-01-01T00:00:00Z"),
                             ("bytes", 1), ("git_commit", "deadbee"), ("host", "added-later")):
            edited = dict(signed_rec, **{field: value})
            with open(m + ".seal.json", "w") as fh:
                json.dump(edited, fh)
            r = tool(action="verify", path=m, signers=signers)
            if r["code"] != 3:
                fail(f"editing {field} in a signed seal was not FORGED: {r}")
        twin = fresh("other-name.md")  # same bytes, different file: the old signed seal is replayed onto it
        with open(twin + ".seal.json", "w") as fh:
            json.dump(signed_rec, fh)
        if tool(action="verify", path=twin)["code"] != 0:
            fail("an unsigned-style check of a copied seal should still hold by hash (unchanged behaviour)")
        r = tool(action="verify", path=twin, signers=signers)
        if r["code"] != 3 or "another file" not in r["message"]:
            fail(f"a signed seal replayed onto another file was not FORGED: {r}")
        with open(m + ".seal.json", "w") as fh:
            json.dump(signed_rec, fh)
        r = tool(action="verify", path=m, signers=signers)
        if r["code"] != 0 or signed_rec["sealed_at"] not in r["message"]:
            fail(f"the untouched signed seal no longer holds, or hides its signed time: {r}")

        # the tool an agent calls can never sign, whatever arguments the model sends
        t = fresh("agent-tries.md")
        r = tool(action="seal", path=t, sign_key=key)
        if r["code"] != 2 or r.get("signed") or os.path.exists(t + ".seal.json"):
            fail(f"the agent-facing tool accepted a signing key: {r}")
        if "sign_key" in baton.SCHEMA["parameters"]["properties"]:
            fail("the tool schema still offers sign_key to the model")
        if tool(action="seal", path=t)["signed"] or "signature" in seal_of(t):
            fail("the tool made a signed seal")

        # slash command and command line, with a signers path that has a space in it
        e = fresh("cli.md")
        if "SIGNED" not in slash(f"seal {e} selftest --sign {key}"):
            fail("slash --sign did not sign")
        if not slash(f"verify {e} --signers {signers}").startswith("SEAL HOLDS"):
            fail("slash --signers did not verify (unquoted path with a space)")
        if not slash(f'verify "{e}" --signers "{wrong}"').startswith("SEAL FORGED"):
            fail("slash --signers with the wrong signers was not FORGED")
        cli = [sys.executable, os.path.join(HERE, "core.py")]
        if subprocess.run(cli + ["verify", e, "--signers", signers], capture_output=True).returncode != 0:
            fail("command line verify of a good signature did not exit 0")
        rc = subprocess.run(cli + ["verify", e, "--signers", wrong], capture_output=True)
        if rc.returncode != 3 or not rc.stdout.decode().startswith("SEAL FORGED"):
            fail(f"command line did not exit 3 with SEAL FORGED (exit {rc.returncode})")
        sign_note = "signs and catches a forged seal (exit 3)"

    # 8. the read guard: absent unless opted in; when on, refuses a read of a BROKEN file and nothing else
    saved = {k: os.environ.pop(k, None) for k in (baton.GUARD_ENV, baton.GUARD_SIGNERS_ENV)}
    try:
        plain = FakeCtx()
        baton.register(plain)
        if plain.hooks:
            fail("a hook was registered without the opt-in")
        os.environ[baton.GUARD_ENV] = "1"
        gctx = FakeCtx()
        baton.register(gctx)
        if len(gctx.hooks.get("pre_tool_call", [])) != 1:
            fail("opt-in did not register exactly one pre_tool_call hook")
        guard = gctx.hooks["pre_tool_call"][0]
        ok_file, bad_file, bare = fresh("guard-ok.md"), fresh("guard-bad.md"), fresh("guard-unsealed.md")
        tool(action="seal", path=ok_file)
        tool(action="seal", path=bad_file)
        with open(bad_file, "a") as fh:
            fh.write("changed\n")
        blocked = guard(tool_name="read_file", args={"path": bad_file}, task_id="t")
        if not (isinstance(blocked, dict) and blocked.get("action") == "block"
                and "SEAL BROKEN" in blocked.get("message", "")):
            fail(f"guard did not block a read of a BROKEN file: {blocked}")
        for label, call in (("a holding file", ("read_file", {"path": ok_file})),
                            ("an unsealed file", ("read_file", {"path": bare})),
                            ("a missing file", ("read_file", {"path": os.path.join(tmp, "ghost.md")})),
                            ("another tool", ("terminal", {"command": "cat " + bad_file})),
                            ("odd arguments", ("read_file", {"path": None}))):
            if guard(tool_name=call[0], args=call[1], task_id="t") is not None:
                fail(f"guard interfered with {label}")
        if keygen:
            os.environ[baton.GUARD_SIGNERS_ENV] = signers
            got = guard(tool_name="read_file", args={"path": ok_file}, task_id="t")
            if not (got and got["action"] == "block" and "SEAL FORGED" in got["message"]):
                fail(f"guard with signers did not block an unsigned seal as FORGED: {got}")
            operator_seal(ok_file, sign_key=key)
            if guard(tool_name="read_file", args={"path": ok_file}, task_id="t") is not None:
                fail("guard with signers blocked a properly signed file")
    finally:
        for k, val in saved.items():
            os.environ.pop(k, None)
            if val is not None:
                os.environ[k] = val
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"SELFTEST PASS (8/8 + wiring): holds a clean file, catches a tamper, refuses a missing seal, handles paths with spaces, "
      f"leaves the hostname out unless asked, falls back to unsigned without ssh-keygen, {sign_note}, "
      f"guard blocks a broken read only when opted in; {note}")
