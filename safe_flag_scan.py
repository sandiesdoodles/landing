#!/usr/bin/env python3
"""
safe_flag_scan.py
SAFE, OFFLINE scan of your already-downloaded HTML/JS for:
- admin/role gates (is_admin, roles, permissions)
- puzzle-ish keywords (sumlist, matrix, whale, choiceisanillusion, U2FsdGVk)
- API endpoint references (what the front-end *mentions*, not what you should "hit")
No network requests. No auth bypass. Just reading local files + printing hits.
"""

import argparse
import os
import re
from pathlib import Path
from collections import defaultdict

def iter_text_files(root: Path):
    # Focus on what you have in phase1_probe_out + assets/*.js
    globs = [
        "assets/**/*.js",
        "*.html",
        "*.txt",
        "*.js",
        "*.json",
    ]
    seen = set()
    for g in globs:
        for p in root.glob(g):
            if p.is_file() and p not in seen:
                seen.add(p)
                yield p

def read_lines(p: Path):
    try:
        data = p.read_bytes()
        # decode leniently (bundles can be ugly)
        text = data.decode("utf-8", errors="replace")
        return text.splitlines()
    except Exception as e:
        return [f"[read error: {e}]"]

def find_matches(lines, pattern: re.Pattern):
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            yield i, line

def print_context(lines, lineno, ctx=2):
    start = max(1, lineno - ctx)
    end = min(len(lines), lineno + ctx)
    for n in range(start, end + 1):
        prefix = ">>" if n == lineno else "  "
        print(f"{prefix} {n:6d}: {lines[n-1][:400]}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="Folder to scan (e.g. phase1_probe_out)")
    ap.add_argument("--ctx", type=int, default=2, help="Context lines around a hit")
    ap.add_argument("--maxhits", type=int, default=80, help="Max hits to print per category")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"[!] Root not found: {root}")

    categories = {
        # "admin door" smell
        "ADMIN_ROLE_GATES": re.compile(
            r"(is_admin|adminOnly|superuser|role[s]?|permission[s]?|canAdmin|acl|rbac|"
            r"gate::|authorize|policy|ability|isAdmin|hasRole|hasPermission|"
            r"\/admin\/|api\/v1\/admin\/)",
            re.I
        ),
        # cookie/session/CSRF gates
        "COOKIE_SESSION_CSRF": re.compile(
            r"(csrf|xsrf|laravel_session|set-cookie|cookie|withCredentials|X-XSRF-TOKEN|X-CSRF-TOKEN)",
            re.I
        ),
        # puzzle-shaped words you care about
        "PUZZLE_KEYWORDS": re.compile(
            r"(matrixsumlist|sum.?list|matrix|prime|whale|choiceisanillusion|dessert|"
            r"U2FsdGVk|Salted__|faed|abba|dbbi|looking\s*glass|white\s*rabbit|io\b|494f|0x49)",
            re.I
        ),
        # api endpoints referenced in code
        "API_PATHS": re.compile(r"(\/api\/[A-Za-z0-9._\/-]+)"),
        # base64-ish blobs / long encoded strings
        "ENCODED_BLOBS": re.compile(r"([A-Za-z0-9+/]{80,}={0,2})"),
    }

    file_scores = defaultdict(lambda: defaultdict(int))
    hits_by_cat = defaultdict(list)  # (file, lineno)

    # First pass: count hits, record line numbers
    for p in iter_text_files(root):
        lines = read_lines(p)
        for cat, pat in categories.items():
            if cat == "API_PATHS":
                # count each endpoint reference
                for i, line in enumerate(lines, start=1):
                    m = pat.search(line)
                    if m:
                        file_scores[p][cat] += len(pat.findall(line))
                        if len(hits_by_cat[cat]) < 5000:
                            hits_by_cat[cat].append((p, i, line))
            else:
                for i, line in find_matches(lines, pat):
                    file_scores[p][cat] += 1
                    if len(hits_by_cat[cat]) < 5000:
                        hits_by_cat[cat].append((p, i, line))

    # Summary table
    print(f"\n=== SAFE FLAG SCAN ===")
    print(f"Root: {root}")
    print(f"Files scanned: {len(file_scores)}\n")

    # Show top files per category
    for cat in ("PUZZLE_KEYWORDS", "ADMIN_ROLE_GATES", "COOKIE_SESSION_CSRF"):
        ranked = sorted(
            ((p, sc.get(cat, 0)) for p, sc in file_scores.items()),
            key=lambda x: x[1],
            reverse=True
        )
        ranked = [(p, c) for p, c in ranked if c > 0][:10]
        print(f"--- TOP FILES: {cat} ---")
        if not ranked:
            print("  (no hits)")
        else:
            for p, c in ranked:
                rel = p.relative_to(root) if str(p).startswith(str(root)) else p
                print(f"  {c:5d}  {rel}")
        print()

    # Print detailed hits (with context)
    def dump_cat(cat_name):
        items = hits_by_cat.get(cat_name, [])
        if not items:
            print(f"=== {cat_name}: no hits ===\n")
            return

        print(f"=== {cat_name}: showing up to {args.maxhits} hits (with context) ===")
        shown = 0
        last_file = None
        cached_lines = None

        for p, lineno, line in items:
            if shown >= args.maxhits:
                break
            if p != last_file:
                cached_lines = read_lines(p)
                last_file = p
                rel = p.relative_to(root) if str(p).startswith(str(root)) else p
                print(f"\n--- FILE: {rel} ---")

            print_context(cached_lines, lineno, ctx=args.ctx)
            shown += 1

        print("\n")

    # Show puzzle + admin gate hits first
    dump_cat("PUZZLE_KEYWORDS")
    dump_cat("ADMIN_ROLE_GATES")

    # Extract unique API endpoints mentioned (front-end references only)
    api_refs = set()
    for p, i, line in hits_by_cat.get("API_PATHS", []):
        for ep in categories["API_PATHS"].findall(line):
            api_refs.add(ep)

    print("=== API ENDPOINT REFERENCES (unique, from code mentions) ===")
    for ep in sorted(api_refs)[:250]:
        print(ep)
    if len(api_refs) > 250:
        print(f"... ({len(api_refs)-250} more)")
    print()

    # Lightweight verdict
    admin_hits = sum(sc.get("ADMIN_ROLE_GATES", 0) for sc in file_scores.values())
    puzzle_hits = sum(sc.get("PUZZLE_KEYWORDS", 0) for sc in file_scores.values())
    print("=== QUICK VERDICT (from your local files only) ===")
    if admin_hits and puzzle_hits:
        print("- Admin/role terms exist AND puzzle terms exist in the front-end bundle.")
        print("  Next: look for lines where they intersect (same file, nearby lines).")
    elif admin_hits and not puzzle_hits:
        print("- Admin/role terms exist, but puzzle keywords did NOT show up in the scanned files.")
        print("  Likely: admin API is unrelated to the puzzle layer (normal platform code).")
    elif puzzle_hits and not admin_hits:
        print("- Puzzle keywords exist without admin/role gates nearby.")
        print("  Likely: puzzle layer is cookie/flag/page-gated, not admin-gated.")
    else:
        print("- No strong admin-gate or puzzle keywords found in the scanned files.")
        print("  Next: ensure you downloaded assets/*.js correctly and scanned the redirect page (choice.html).")

if __name__ == "__main__":
    main()
