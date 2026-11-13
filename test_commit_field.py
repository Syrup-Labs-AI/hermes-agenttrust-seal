"""RED/GREEN test: the README promises the commit field is left empty when the file is not in a git checkout."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
d = tempfile.mkdtemp()
f = os.path.join(d, "outside-git.md")
open(f, "w").write("x\n")
code, msg, rec = core.seal(f, "tdd")
assert code == 0, msg
assert rec["git_commit"] == "", f"expected empty commit field outside git, got {rec['git_commit']!r}"
print("PASS: commit field empty outside git")
