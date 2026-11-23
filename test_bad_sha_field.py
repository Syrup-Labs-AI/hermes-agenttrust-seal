"""RED/GREEN test: the README says an unreadable seal is NO SEAL (code 2). A seal whose sha256 field is
not a hash is unreadable, so verify must refuse it and must not claim the file was changed (code 1)."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
d = tempfile.mkdtemp()
f = os.path.join(d, "handoff.md")
open(f, "w").write("x\n")
for bad in (None, "", 123, "not-a-hash", "g" * 64):
    with open(f + core.SEAL_SUFFIX, "w") as s:
        json.dump({"file": "handoff.md", "sha256": bad}, s)
    code, msg = core.verify(f)
    assert code == 2 and msg.startswith("NO SEAL"), f"sha256={bad!r}: expected code 2 NO SEAL, got {code} {msg!r}"
code, msg, rec = core.seal(f, "tdd")
assert code == 0, msg
rec["sha256"] = rec["sha256"].upper()
with open(f + core.SEAL_SUFFIX, "w") as s:
    json.dump(rec, s)
code, msg = core.verify(f)
assert code == 0, f"the same hash in capital letters must still hold, got {code} {msg!r}"
open(f, "a").write("changed\n")
code, msg = core.verify(f)
assert code == 1, f"a changed file must still be SEAL BROKEN, got {code} {msg!r}"
print("PASS: a seal with no usable sha256 is refused (code 2); a real change is still SEAL BROKEN")
