#!/usr/bin/env python3
"""links.py — link check for a zheng checkout: relative links must resolve inside the
checkout; wiki-links must resolve to a page of the checkout or of the cyber
graph (a sibling repo under --graph: a repo name, a path, a page basename or
a frontmatter alias). Usage: links.py <zheng-dir> --graph ~/cyber"""
import os, re, sys, unicodedata
root = os.path.abspath(sys.argv[1]); graph = os.path.expanduser(sys.argv[3] if len(sys.argv) > 3 else "~/cyber")
SKIP = {".git", "target", ".worktrees", "node_modules", ".stands"}
def norm(s): return unicodedata.normalize("NFC", s).strip().lower().replace("_", " ").replace("-", " ")
def walk(base, maxdepth=None):
    for d, dirs, files in os.walk(base):
        dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith(".") or x == ".claude"]
        if maxdepth is not None and d[len(base):].count(os.sep) >= maxdepth: dirs[:] = []
        for f in files:
            if f.endswith(".md"): yield os.path.join(d, f)
names, aliases, paths = set(), set(), set()
repos = {x for x in os.listdir(graph) if os.path.isdir(os.path.join(graph, x)) and not x.startswith(".")}
for f in walk(graph):
    rel = os.path.relpath(f, graph)[:-3]
    paths.add(norm(rel)); b = os.path.basename(rel)
    names.add(norm(b))
    if b.lower() == "readme": names.add(norm(os.path.basename(os.path.dirname(rel)))); paths.add(norm(os.path.dirname(rel)))
    try:
        head = open(f, encoding="utf-8", errors="replace").read(2000)
    except OSError: continue
    m = re.search(r"^alias:\s*(.+)$", head, re.M)
    if m and head.startswith("---"):
        for a in m.group(1).split(","): aliases.add(norm(a))
for r in repos: names.add(norm(r))
# the checkout itself, under its repo name
for f in walk(root):
    rel = os.path.relpath(f, root)[:-3]
    paths.add(norm("zheng/" + rel)); names.add(norm(os.path.basename(rel)))
    if os.path.basename(rel).lower() == "readme": paths.add(norm("zheng/" + os.path.dirname(rel)))
bad = 0; total = 0
code = re.compile(r"```.*?```", re.S); inline = re.compile(r"`[^`\n]*`")
for f in sorted(walk(root)):
    text = inline.sub("", code.sub("", open(f, encoding="utf-8").read()))
    for m in re.finditer(r"\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]*)?\]\]", text):
        total += 1; t = m.group(1).strip(); n = norm(t)
        ok = n in names or n in aliases or n in paths or norm(os.path.basename(t)) in names and "/" not in t
        if not ok and "/" in t:
            ok = n in paths or norm(t.split("/", 1)[1]) in paths
        if not ok: bad += 1; print(f"wiki  {os.path.relpath(f, root)}: [[{t}]]")
    for m in re.finditer(r"\]\(([^)\s]+)\)", text):
        u = m.group(1)
        if re.match(r"^[a-z]+:", u) or u.startswith("#") or u.startswith("mailto:"): continue
        total += 1; p = os.path.normpath(os.path.join(os.path.dirname(f), u.split("#")[0]))
        if not os.path.exists(p): bad += 1; print(f"rel   {os.path.relpath(f, root)}: ({u})")
print(f"links checked: {total}, unresolved: {bad}")
sys.exit(1 if bad else 0)
