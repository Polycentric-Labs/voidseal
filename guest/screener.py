#!/usr/bin/env python3
"""Offline sensitivity screener. Reads a dir, emits per-file verdicts JSON.
Fail-closed: anything not provably SAFE is UNCERTAIN (or SENSITIVE on a detector hit)."""
import argparse, json, re, pathlib

SENSITIVE = [
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), 'aws_key'),
    (re.compile(r'(?i)\b(secret|api[_-]?key|password|token)\s*[=:]\s*\S+'), 'credential'),
    (re.compile(r'(?i)\b(routing|account)\b.*\b\d{6,}\b'), 'financial'),
    (re.compile(r'(?i)\b(diagnosis|prescription|rx|icd-?10)\b'), 'health'),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'ssn'),
]

def screen_text(t):
    hits = [tag for rx, tag in SENSITIVE if rx.search(t)]
    return hits

def is_prose(t):
    # crude prose heuristic (spaCy refinement in Task 0.4): enough sentences + alpha ratio
    words = re.findall(r"[A-Za-z']+", t)
    if len(words) < 60: return False
    alpha = sum(c.isalpha() or c.isspace() for c in t) / max(len(t),1)
    sentences = t.count('.') + t.count('!') + t.count('?')
    return alpha > 0.85 and sentences >= 3

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--mode', choices=['aggressive','moderate'], default='aggressive')
    a = ap.parse_args()
    verdicts = []
    for p in sorted(pathlib.Path(a.inp).rglob('*')):
        if not p.is_file(): continue
        try: t = p.read_text(encoding='utf-8', errors='replace')
        except Exception: t = ''
        hits = screen_text(t)
        if hits:
            v = 'SENSITIVE'
        elif is_prose(t):
            v = 'SAFE'
        else:
            v = 'UNCERTAIN'   # fail-closed: never SAFE-by-omission
        verdicts.append({'name': p.name, 'verdict': v, 'detectors': hits})
    pathlib.Path(a.out).write_text(json.dumps(verdicts, indent=1), encoding='utf-8')

if __name__ == '__main__':
    main()
