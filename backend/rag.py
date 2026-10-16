import re, math, pathlib
from collections import Counter
DOCS = []
def load(folder="docs"):
    DOCS.clear()
    for p in pathlib.Path(folder).glob("*.md"):
        for i, ch in enumerate(re.split(r"\n\s*\n", p.read_text(encoding="utf-8"))):
            if ch.strip(): DOCS.append((f"{p.name}#{i}", ch.strip()))
def tok(s): return re.findall(r"[a-z0-9]+", s.lower())
def search(q, k=3):
    n = len(DOCS) or 1; df = Counter(t for _, d in DOCS for t in set(tok(d))); qs = tok(q); res = []
    for name, d in DOCS:
        c = Counter(tok(d)); s = sum(c[t]*math.log(1+n/(1+df[t])) for t in qs if t in c)
        if s > 0: res.append((s, name, d))
    return [{"source": n_, "text": d} for _, n_, d in sorted(res, reverse=True)[:k]]
