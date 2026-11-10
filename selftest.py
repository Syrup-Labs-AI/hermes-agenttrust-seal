#!/usr/bin/env python3
"""Baton selftest: seal-holds, tamper-caught, missing-seal-refused, plus register() wiring.
Run: python3 selftest.py   (exit 0 and a SELFTEST PASS line, or exit 1 with the failing check)
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
        self.tools, self.commands = {}, {}

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = handler

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler


tmp = tempfile.mkdtemp()
try:
    f = os.path.join(tmp, "handoff.md")
    with open(f, "w") as fh:
        fh.write("state: green\n")

    # 1. seal holds, through the tool an agent would call
    ctx = FakeCtx()
    baton.register(ctx)
    s = json.loads(ctx.tools["baton"]({"action": "seal", "path": f, "author": "selftest"}))
    v = json.loads(ctx.tools["baton"]({"action": "verify", "path": f}))
    if not (s["success"] and v["holds"] and v["code"] == 0):
        fail(f"clean seal did not hold: {s} {v}")

    # 2. tamper caught, through the slash command
    with open(f, "a") as fh:
        fh.write("state: red\n")
    out = ctx.commands["baton"](f"verify {f}")
    if not out.startswith("SEAL BROKEN"):
        fail(f"tamper not caught: {out}")
    if json.loads(ctx.tools["baton"]({"action": "verify", "path": f}))["holds"]:
        fail("tamper reported as holding")

    # 3. missing seal refused (also missing file, corrupt seal)
    g = os.path.join(tmp, "never-sealed.md")
    with open(g, "w") as fh:
        fh.write("x")
    r = json.loads(ctx.tools["baton"]({"action": "verify", "path": g}))
    if r["code"] != 2 or r["holds"]:
        fail(f"missing seal not refused: {r}")
    if baton.core.verify(os.path.join(tmp, "ghost.md"))[0] != 2:
        fail("missing file not refused")
    with open(g + ".seal.json", "w") as fh:
        fh.write("not json")
    if baton.core.verify(g)[0] != 2:
        fail("corrupt seal not refused")

    # 4. interop: a seal written here verifies under the shell baton-seal (skipped if absent)
    shell = "/home/hermes/bin/baton-seal"
    note = "interop skipped (no baton-seal here)"
    if os.path.exists(shell):
        h = os.path.join(tmp, "interop.md")
        with open(h, "w") as fh:
            fh.write("hello")
        baton.core.seal(h, "selftest")
        rc = subprocess.run([shell, "verify", h], capture_output=True).returncode
        if rc != 0:
            fail(f"shell baton-seal rejected a Python seal (rc {rc})")
        note = "Python seal verified by shell baton-seal"
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"SELFTEST PASS (3/3 + wiring): holds a clean file, catches a tamper, refuses a missing seal; {note}")
