from pathlib import Path
import re

s = Path("index.html").read_text(errors="ignore")

def fail(msg): raise SystemExit("FAIL: " + msg)

if "<!-- START PUPPY_GRID -->" not in s or "<!-- END PUPPY_GRID -->" not in s:
    fail("missing PUPPY_GRID markers")
if "<!-- START CONTACT -->" not in s or "<!-- END CONTACT -->" not in s:
    fail("missing CONTACT markers")

bad = re.findall(r'Daisy|Instagram|\(Sold\)', s, flags=re.I)
if bad:
    fail("forbidden text present: " + ", ".join(sorted(set(bad))))

ids = re.findall(r'\bid="(ap_[^"]+)"', s)
dupes = sorted({i for i in ids if ids.count(i) > 1})
if dupes:
    fail("duplicate ap_ ids: " + ", ".join(dupes))

grids = len(re.findall(r'\bap-grid\b', s))
if grids > 1:
    fail(f"multiple ap-grid blocks: {grids}")

print("PASS ✅")
