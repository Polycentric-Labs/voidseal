#!/usr/bin/env python3
"""Offline sensitivity screener. Reads a dir, emits per-file verdicts JSON.
Fail-closed: anything not provably SAFE is UNCERTAIN (or SENSITIVE on a detector hit).

SACRED INVARIANT (Task 0.4) — the heavy detectors below may ONLY make a verdict
STRICTER, NEVER promote one toward SAFE:
  * The always-on regex floor (the SENSITIVE list, incl. the dep-free email detector)
    and the crude prose heuristic (_is_prose_crude) are AUTHORITATIVE.
  * Presidio (PII NER) can only APPEND a hit -> only moves SAFE/UNCERTAIN -> SENSITIVE.
  * spaCy's POS refinement can only DEMOTE a crude-True prose verdict to non-prose
    (would-be-SAFE -> UNCERTAIN). It can never turn a crude-False into prose.
  * When EITHER heavy dep is ABSENT or ERRORS, the screener falls back to EXACTLY the
    regex + crude-prose behavior. A missing/failing heavy dep must NEVER cause a file to
    become SAFE that the dep-free floor would not have called SAFE. Fail-closed, always.
"""
import argparse, json, re, pathlib

SENSITIVE = [
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), 'aws_key'),
    (re.compile(r'(?i)(?<![A-Za-z])(secret|api[_-]?key|password|token)(?![A-Za-z])\s*[=:]\s*\S+'), 'credential'),
    (re.compile(r'(?i)\b(routing|account)\b.*\b\d{6,}\b'), 'financial'),
    (re.compile(r'(?i)\b(diagnosis|prescription|rx|icd-?10)\b'), 'health'),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'ssn'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), 'email'),
]

# Lazy Presidio (PII NER). On ANY failure -> None (dep-free fallback). Adds hits only (stricter).
try:
    from presidio_analyzer import AnalyzerEngine
    _ANALYZER = AnalyzerEngine()
except Exception:
    _ANALYZER = None

# Lazy spaCy POS model. On ANY failure -> None (crude-heuristic fallback). Tightens is_prose only.
try:
    import spacy
    _NLP = spacy.load('en_core_web_sm')
except Exception:
    _NLP = None

def screen_text(t):
    hits = [tag for rx, tag in SENSITIVE if rx.search(t)]
    if _ANALYZER is not None:
        try:
            if any(r.score >= 0.5 for r in _ANALYZER.analyze(text=t, language='en')):
                hits.append('presidio_pii')
        except Exception:
            pass  # Presidio failure must NEVER promote toward SAFE; the regex floor is authoritative.
    return hits

def _is_prose_crude(t):
    # crude prose heuristic (the FLOOR): enough sentences + alpha ratio
    words = re.findall(r"[A-Za-z']+", t)
    if len(words) < 60: return False
    alpha = sum(c.isalpha() or c.isspace() for c in t) / max(len(t),1)
    sentences = t.count('.') + t.count('!') + t.count('?')
    return alpha > 0.85 and sentences >= 3

def is_prose(t):
    if not _is_prose_crude(t):
        return False                      # crude already says non-prose -> stays non-prose
    if _NLP is None:
        return True                       # dep-free fallback = current behavior
    try:
        doc = _NLP(t)
        # Narrative prose has verbs and sentence structure; a list/table/numbered dump does not.
        # Require a minimum VERB ratio (tuned conservatively). Too few verbs -> NOT prose (stricter).
        tokens = [tok for tok in doc if tok.is_alpha]
        if not tokens:
            return False
        verb_ratio = sum(1 for tok in doc if tok.pos_ in ('VERB','AUX')) / max(len(tokens),1)
        return verb_ratio >= 0.05         # conservative; only DEMOTES a crude-true to non-prose
    except Exception:
        return True                       # spaCy failure -> keep the crude verdict (do NOT loosen)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', required=True)
    # NOTE: per-file verdicts are MODE-INDEPENDENT today; --mode is consumed by the GATE's
    # release/hold partition policy (SensitivityGate.ps1, a later task), not by the screener.
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
        # assumes a FLAT input dir (the gate's staging is flat by design); if nested inputs are
        # ever screened, switch p.name to a path relative to --in to avoid same-name collisions.
        verdicts.append({'name': p.name, 'verdict': v, 'detectors': hits})
    pathlib.Path(a.out).write_text(json.dumps(verdicts, indent=1), encoding='utf-8')

if __name__ == '__main__':
    main()
