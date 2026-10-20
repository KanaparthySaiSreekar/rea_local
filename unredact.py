#!/usr/bin/env python3
"""
Auto-unredaction — the reverse of redact.py.

Expands Claude's placeholder-space text (APPPKG1, Cls_7, STR_3, TERM_2, ...) back
to your REAL names, LOCALLY, using redaction_map.json. Use it so instructions
Claude gives you in placeholders become real identifiers before the local model
(which works on the real code) acts on them. Real names never left your machine;
this only restores them on your side.

Usage:
  python unredact.py --map redaction_map.json < claude_instructions.txt > local_instructions.txt
Importable:
  from unredact import load_reverse, expand
  text = expand(claude_text, load_reverse("redaction_map.json"))
"""
import argparse, json, re, sys


def load_reverse(map_path):
    m = json.load(open(map_path, encoding="utf-8"))
    rev = m.get("reverse")
    if rev is None:  # fall back to inverting the forward map
        rev = {}
        for d in (m.get("forward") or m).values():
            if isinstance(d, dict):
                for original, alias in d.items():
                    rev[alias] = original
    return rev


def expand(text, rev):
    if not text or not rev:
        return text
    # longest alias first + word boundaries so Cls_1 never matches inside Cls_12
    aliases = sorted(rev, key=len, reverse=True)
    pat = re.compile(r"\b(" + "|".join(re.escape(a) for a in aliases) + r")\b")
    return pat.sub(lambda m: rev[m.group(1)], text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default="redaction_map.json")
    a = ap.parse_args()
    sys.stdout.write(expand(sys.stdin.read(), load_reverse(a.map)))


if __name__ == "__main__":
    main()
