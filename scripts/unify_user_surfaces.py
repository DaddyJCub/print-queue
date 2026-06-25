"""Unify the primary card/panel surface on user-facing (pwa_base) pages to the
canonical dashboard token. Visual-only: only background/border utility classes
change; no structural, id, handler, form, or link changes.

Run: python scripts/unify_user_surfaces.py [--apply]
"""
import re, glob, os, sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "app", "templates")
SKIP = {"pwa_base.html"}  # base shell itself

# Order matters: most-specific (bg+border) first, then bg-only catch-alls.
SUBS = [
    ("bg-zinc-900/60 border border-zinc-800/60", "bg-zinc-800/40 border border-zinc-700/50"),
    ("bg-zinc-900/60 border border-zinc-800", "bg-zinc-800/40 border border-zinc-700/50"),
    ("bg-zinc-900/50 border border-zinc-800", "bg-zinc-800/40 border border-zinc-700/50"),
    ("bg-zinc-900/60", "bg-zinc-800/40"),
    ("bg-zinc-900/50", "bg-zinc-800/40"),
]

apply = "--apply" in sys.argv
total = 0
for path in sorted(glob.glob(os.path.join(ROOT, "*.html"))):
    name = os.path.basename(path)
    if name in SKIP or name.startswith("admin_"):
        continue
    src = open(path, encoding="utf-8").read()
    if 'extends "pwa_base.html"' not in src:
        continue
    new = src
    n = 0
    for old, rep in SUBS:
        c = new.count(old)
        if c:
            new = new.replace(old, rep)
            n += c
    if n:
        total += n
        if apply:
            open(path, "w", encoding="utf-8", newline="\n").write(new)
        print(f"{'WROTE' if apply else 'WOULD'}  {name:30s} {n} surface(s)")
print(f"--- total surface replacements: {total}")
