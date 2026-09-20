#!/usr/bin/env python3
"""Offline sensitivity screener. Reads a dir, emits per-file verdicts JSON.
Fail-closed: anything not provably SAFE is HELD (or ERROR if it can't even be assessed).

REGENERATOR REFRAME (C2.1, 2026-07-02): the screener emits an ENUM-ONLY verdict object.
Every field is drawn from a FIXED small closed enum so the schema-derived per-run leakage
bound is `Sigma log2(|enum_i|)`, computed from the schema alone, independent of classifier
accuracy. LOCKED design (Allen, 2026-07-01) — MINIMAL schema, supersedes the plan's richer
proposed `category{10}`/`confidence{3}` fields (dropped entirely; they widen the bound):

    verdict    in {SAFE, HELD, ERROR}
    error_code in {NONE, EXTRACT_FAIL, OFF_SCHEMA, DETECTOR_ERROR, UNSUPPORTED}
    flags      subset of a FIXED, bounded closed vocabulary of detector-category flags

  * `verdict=SAFE` only when the full positive conjunction holds (see `_verdict_for`).
  * `verdict=HELD` covers what used to be SENSITIVE (a detector hit) AND what used to be
    UNCERTAIN (readable but not supported-language prose) — both are "evaluated, not
    released"; the WHY lives in `flags`/`error_code`, never in a free-form field.
  * `verdict=ERROR` is reserved for content the screener could not even assess (e.g. not
    known-extractable / not UTF-8-clean) — a stricter bucket than HELD: the artifact itself
    is untrustworthy to evaluate, so it is fail-closed refused rather than "evaluated safe".
  * `OFF_SCHEMA` is RESERVED for the host-side gate's schema validation (C2.4) — the
    producer (this file) never emits it; it exists in the closed set so the vocabulary is
    shared end-to-end between producer and gate.
  * `flags` is a bitset-as-list over the FIXED tag vocabulary (M3). An unmappable/unknown
    detector tag is NEVER silently dropped or passed through as free-form text — see the
    SACRED INVARIANT note below.

SACRED INVARIANT (Task 0.4) — the heavy detectors below may ONLY make a verdict
STRICTER, NEVER promote one toward SAFE:
  * The always-on regex floor (the SENSITIVE list, incl. the dep-free email detector)
    and the crude prose heuristic (_is_prose_crude) are AUTHORITATIVE.
  * Presidio (PII NER) can only APPEND a hit -> only moves SAFE/HELD -> HELD (stricter).
  * spaCy's POS refinement can only DEMOTE a crude-True prose verdict to non-prose
    (would-be-SAFE -> HELD). It can never turn a crude-False into prose.
  * When EITHER heavy dep is ABSENT or ERRORS, the screener falls back to EXACTLY the
    regex + crude-prose behavior. A missing/failing heavy dep must NEVER cause a file to
    become SAFE that the dep-free floor would not have called SAFE. Fail-closed, always.
  * An UNMAPPABLE/unknown detector tag (one not in the fixed `_FLAG_VOCAB`) must NEVER be
    silently dropped and must NEVER become a new free-form value — it forces `verdict=HELD`
    with the `other` flag, so the flag alphabet stays fixed even as detectors evolve.
  * (C2.3) Detectors run over the RAW text AND an NFKC-normalized, zero-width/bidi-stripped
    view (Trojan-Source / homoglyph evasion hardening); a hit in EITHER view counts — this is
    a UNION, so it can only ADD hits relative to raw-only screening, never remove one. The
    `is_prose` SAFE clause still evaluates the raw text only; normalization only feeds the
    detector clause, never the release oracle, so it can never be used to "clean up" a file
    into passing prose.
"""
import argparse, hashlib, json, math, re, pathlib, unicodedata
from collections import Counter

# ---------------------------------------------------------------------------
# C2.1 — the FIXED enum schema (single source of truth; later C2 tasks / M3 assert
# against these constants). Keep this MINIMAL: every added enum value widens the
# published leakage bound `Sigma log2(|enum_i|)` — do not add fields or values here
# without deliberately reconsidering that bound.
# ---------------------------------------------------------------------------
VERDICT_ENUM = ('SAFE', 'HELD', 'ERROR')
ERROR_CODE_ENUM = ('NONE', 'EXTRACT_FAIL', 'OFF_SCHEMA', 'DETECTOR_ERROR', 'UNSUPPORTED')

# tag (as produced by screen_text()) -> canonical flag in the FIXED vocabulary.
_TAG_TO_FLAG = {
    'aws_key': 'aws_key',
    'credential': 'credential',
    'financial': 'financial',
    'health': 'health',
    'ssn': 'ssn',
    'email': 'email',
    'presidio_pii': 'pii',
    'secret_entropy': 'secret',
    'pem_key': 'secret',
    'jwt': 'secret',
    'high_entropy': 'entropy',
}
FLAG_VOCAB = tuple(sorted(set(_TAG_TO_FLAG.values()) | {'entropy', 'other'}))

SENSITIVE = [
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), 'aws_key'),
    (re.compile(r'(?i)(?<![A-Za-z])(secret|api[_-]?key|password|token)(?![A-Za-z])\s*[=:]\s*\S+'), 'credential'),
    (re.compile(r'(?i)\b(routing|account)\b.*\b\d{6,}\b'), 'financial'),
    (re.compile(r'(?i)\b(diagnosis|prescription|rx|icd-?10)\b'), 'health'),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'ssn'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), 'email'),
]

# C2.7 -- entropy + PEM/JWT secret floor (residual hardening, stricter-only). Presidio has no entropy
# detection and the `credential` regex above only matches an explicit `key=`/`token:`-style assignment,
# so a bare high-entropy secret sitting in otherwise-clean prose (no recognizable keyword) is missed by
# every existing detector. This adds a THIRD, independent clause:
#   (a) a PEM key block (`-----BEGIN ... PRIVATE KEY-----`)              -> 'pem_key'  -> flag 'secret'
#   (b) a JWT's three-dot-separated base64url shape (`eyJ....eyJ....sig`) -> 'jwt'      -> flag 'secret'
#   (c) any contiguous run of >=32 chars from the base64/hex/token alphabet whose Shannon entropy is
#       >= 4.0 bits/char                                                  -> 'high_entropy' -> flag 'entropy'
# Threshold rationale (tuned + documented per the plan; measured empirically, not just theorized):
# a random base64/hex/token-alphabet secret (>=32 chars drawn near-uniformly from a ~64-70 symbol
# alphabet, max ~6 bits/char) measures 5.0-5.7 bits/char in practice. The closest false-positive-shaped
# near-miss is a long HYPHENATED ENGLISH SLUG/URL-path (plenty of chars from this same alphabet --
# letters, digits, hyphen -- and long enough to clear the 32-char run length), which is dictionary-word
# -like (skewed per-character distribution) and measured 3.9-4.3 bits/char across seven varied slug
# fixtures during tuning (max observed 4.29). An initial 4.0 threshold (the plan's suggested starting
# point) let the worst slug fixture through as a false positive; **4.5 bits/char** was chosen instead --
# it sits clearly above the measured slug ceiling (4.29) with margin, and clearly below real-secret
# entropy (5.0+) and a JWT segment's entropy (4.36-5.07), so it does not weaken PEM/JWT detection (those
# also have their own dedicated regex clause below, independent of entropy). See
# tests/guest/test_screener.py's C2.7 section for the prose no-false-positive guard this threshold must
# keep passing.
_PEM = re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
_HI_ENTROPY_RUN = re.compile(r'[A-Za-z0-9+/_-]{32,}')
_ENTROPY_THRESHOLD = 4.5  # bits/char; see rationale comment above

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def _secret_hits(t):
    """PEM/JWT/high-entropy detector clause. Returns a list of tags (possibly empty); NEVER raises --
    any internal failure here must fail closed, so callers wrap this in the same try/except as the rest
    of screen_text() (a detector-stage exception must never promote toward SAFE)."""
    tags = []
    if _PEM.search(t):
        tags.append('pem_key')
    if _JWT.search(t):
        tags.append('jwt')
    for m in _HI_ENTROPY_RUN.finditer(t):
        if _shannon_entropy(m.group(0)) >= _ENTROPY_THRESHOLD:
            tags.append('high_entropy')
            break
    return tags

# C2.3 -- Trojan-Source / homoglyph evasion hardening. Zero-width chars (word joiners) and bidi
# control chars (the "Trojan Source" override/isolate characters) are stripped, then the text is
# NFKC-normalized (folds compatibility variants -- e.g. fullwidth Latin letters -- to their
# canonical ASCII form). This is a STRICTLY-TIGHTENING addition: screen_text() below unions hits
# from the raw text with hits from this normalized view, so it can only ADD detector hits relative
# to the pre-C2.3 raw-only floor, never remove one (SACRED invariant).
_ZERO_WIDTH_AND_BIDI = dict.fromkeys([
    0x200B, 0x200C, 0x200D, 0xFEFF,                     # zero-width space/non-joiner/joiner, BOM
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,             # bidi embedding/override controls
    0x2066, 0x2067, 0x2068, 0x2069,                     # bidi isolate controls
], None)

def _normalize(t: str) -> str:
    return unicodedata.normalize('NFKC', t.translate(_ZERO_WIDTH_AND_BIDI))

# Conditional Presidio init: constructed at import if installed, else None (regex floor stands).
# Adds hits only (stricter) -> only moves a verdict toward HELD, never toward SAFE.
try:
    from presidio_analyzer import AnalyzerEngine
    _ANALYZER = AnalyzerEngine()
except Exception:
    _ANALYZER = None

# Conditional spaCy init: model loaded at import if available, else None (crude floor stands).
# Tightens is_prose only (can demote a crude-True to non-prose, never the reverse).
try:
    import spacy
    _NLP = spacy.load('en_core_web_sm')
except Exception:
    _NLP = None

def screen_text(t):
    hits = [tag for rx, tag in SENSITIVE if rx.search(t)]
    hits.extend(_secret_hits(t))  # C2.7 -- PEM/JWT/entropy clause; append-only, never gates the others.
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
        verb_ratio = sum(1 for tok in tokens if tok.pos_ in ('VERB','AUX')) / max(len(tokens),1)
        return verb_ratio >= 0.05         # conservative; only DEMOTES a crude-true to non-prose
    except Exception:
        return True                       # spaCy failure -> keep the crude verdict (do NOT loosen)

def _extract_text(raw: bytes):
    """Strict UTF-8 decode. Returns (text, extractable, error_code).

    `extractable=False` means the bytes are NOT known-good text (contain a byte
    sequence that is not valid UTF-8) -- the artifact cannot be trusted as text at
    all, so it must never be SAFE. We still return a best-effort decode (errors=
    'replace') so the fixed-vocabulary detectors can still scan it for a HELD hit,
    but the positive conjunction below refuses SAFE whenever extractable is False.
    """
    try:
        return raw.decode('utf-8'), True, 'NONE'
    except UnicodeDecodeError:
        return raw.decode('utf-8', 'replace'), False, 'EXTRACT_FAIL'

def _verdict_for(raw: bytes):
    """The C2.1 positive-conjunction SAFE oracle + enum-only verdict assignment.

    A file is SAFE only if EVERY clause holds:
      (i)   known-extractable   -- strict UTF-8 decode succeeds (else ERROR/EXTRACT_FAIL)
      (ii)  complete extraction -- folded into (i) for this minimal producer (no partial-
            read path exists yet; a future truncation source would set error_code here)
      (iii) supported language  -- the crude-prose + spaCy gate (`is_prose`); a gating
            PRECONDITION, NOT the release oracle itself
      (iv)  clean detectors     -- no hit from screen_text() (regex floor + optional
            Presidio tighten-only append)

    Any detector hit -> HELD (floor authoritative, regardless of (i)-(iii)).
    An UNMAPPABLE detector tag (not in _TAG_TO_FLAG) is STILL a hit -> HELD with the
    'other' flag -- it is never silently dropped and never becomes a new free-form value
    (SACRED invariant: the flag alphabet stays fixed).
    Not extractable -> ERROR/EXTRACT_FAIL (fail-closed: cannot even assess the content).
    Readable but not supported-language prose, with no detector hit -> HELD/UNSUPPORTED
    (fail-closed: never SAFE-by-omission).
    """
    text, extractable, extract_err = _extract_text(raw)
    try:
        # C2.3 -- screen BOTH the raw text and the NFKC-normalized, zero-width/bidi-stripped view;
        # a hit in EITHER view counts (union). This can only ADD hits relative to raw-only screening
        # (Trojan-Source / homoglyph evasion hardening) -- it never removes a raw hit, and the
        # is_prose SAFE clause below still runs over the raw text only (unchanged).
        hits = sorted(set(screen_text(text)) | set(screen_text(_normalize(text))))
    except Exception:
        # A detector-stage exception must NEVER promote toward SAFE (SACRED invariant) --
        # fail closed to HELD with a dedicated error_code.
        return 'HELD', 'DETECTOR_ERROR', ['other']

    flags = sorted({_TAG_TO_FLAG.get(tag, 'other') for tag in hits})

    if not extractable:
        # Not known-extractable: refuse to assess as text at all. A detector hit on the
        # best-effort decode does not change this -- ERROR is the fail-closed floor here,
        # not HELD, because we cannot vouch the screened text reflects the real bytes.
        return 'ERROR', extract_err, flags

    if hits:
        return 'HELD', 'NONE', flags

    if is_prose(text):
        return 'SAFE', 'NONE', []

    return 'HELD', 'UNSUPPORTED', []   # fail-closed: never SAFE-by-omission

def _run(a):
    verdicts = []
    for p in sorted(pathlib.Path(a.inp).rglob('*')):
        if not p.is_file(): continue
        try:
            raw = p.read_bytes()
        except Exception:
            raw = b''
        verdict, error_code, flags = _verdict_for(raw)
        # assumes a FLAT input dir (the gate's staging is flat by design); if nested inputs are
        # ever screened, switch p.name to a path relative to --in to avoid same-name collisions.
        verdicts.append({
            'name': p.name,
            'sha256': hashlib.sha256(raw).hexdigest(),
            'verdict': verdict,
            'error_code': error_code,
            'flags': flags,
        })
    pathlib.Path(a.out).write_text(json.dumps(verdicts, indent=1), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', required=True)
    # NOTE: per-file verdicts are MODE-INDEPENDENT today; --mode is consumed by the GATE's
    # release/hold partition policy (SensitivityGate.ps1, a later task), not by the screener.
    ap.add_argument('--mode', choices=['aggressive','moderate'], default='aggressive')
    a = ap.parse_args()
    _run(a)

if __name__ == '__main__':
    main()
