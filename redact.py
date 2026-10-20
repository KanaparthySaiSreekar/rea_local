#!/usr/bin/env python3
"""
Local privacy redactor for the hybrid pipeline.

Scrubs your app's OWN identifiers and ALL string-literal contents from decompiled
code (or any text) BEFORE it is shared with Claude, while keeping framework/library
symbols and control flow so the logic stays intact and reviewable.

Guarantee is enforced by code, not by asking a model nicely. Deterministic and
reversible via a LOCAL map (redaction_map.json) that never leaves the machine.

What it redacts:
  - your app package (e.g. de.danoeh.antennapod)         -> APPPKG1
  - your app's own class simple-names (from REA inventory) -> Cls_N
  - every double-quoted string literal's contents          -> "STR_N"
What it KEEPS (so logic stays intact):
  - android.*, androidx.*, java.*, kotlin.*, and all third-party library symbols
  - all control flow, operators, and method call structure

Library usage:
  from redact import Redactor
  r = Redactor(app_package="com.foo.bar", app_classes={"MainActivity", ...})
  safe = r.redact(decompiled_text)          # text safe to share with Claude
  r.save_map("redaction_map.json")          # keep this LOCAL
CLI:
  python redact.py --app-package com.foo.bar --app-classes-file classes.txt \
      --map redaction_map.json < input.txt > safe.txt
"""
import argparse, json, re, sys

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')


class Redactor:
    def __init__(self, app_package="", app_classes=None, terms=None, terms_ignore_case=True):
        self.app_package = app_package or ""
        self.app_classes = {c for c in (app_classes or set()) if c}
        self.terms = [t for t in (terms or []) if t]
        self.terms_ignore_case = terms_ignore_case
        self.map = {"pkg": {}, "class": {}, "string": {}, "term": {}}
        self._names_re = None
        if self.app_classes:
            # longest-first so e.g. FeedItemFilter matches before FeedItem
            alt = "|".join(re.escape(n) for n in sorted(self.app_classes, key=len, reverse=True))
            self._names_re = re.compile(r"\b(" + alt + r")\b")
        self._pkg_re = re.compile(r"\b" + re.escape(self.app_package) + r"\b") if self.app_package else None
        # custom terms (company / project / game / codenames): literal SUBSTRING match so they
        # are caught inside dotted packages, permission strings, and variants like "foo2".
        # Longest-first; case-insensitive by default.
        self._terms_re = None
        if self.terms:
            alt = "|".join(re.escape(t) for t in sorted(set(self.terms), key=len, reverse=True))
            self._terms_re = re.compile(alt, re.IGNORECASE if terms_ignore_case else 0)

    def _alias(self, kind, original, prefix):
        d = self.map[kind]
        if original not in d:
            d[original] = f"{prefix}{len(d) + 1}"
        return d[original]

    def redact(self, text):
        if not text:
            return text
        # 1) string-literal CONTENTS (strings carry most app secrets / PII / URLs)
        def _s(m):
            inner = m.group(0)[1:-1]
            return '"' + (self._alias("string", inner, "STR_") if inner else "") + '"'
        text = _STRING_RE.sub(_s, text)
        # 2) custom terms (names you asked to hide), substring, before structural passes
        if self._terms_re:
            def _t(m):
                key = m.group(0).lower() if self.terms_ignore_case else m.group(0)
                d = self.map["term"]
                if key not in d:
                    d[key] = f"TERM_{len(d) + 1}"
                return d[key]
            text = self._terms_re.sub(_t, text)
        # 3) app package prefix
        if self._pkg_re:
            text = self._pkg_re.sub(self._alias("pkg", self.app_package, "APPPKG"), text)
        # 4) app-owned class simple-names
        if self._names_re:
            text = self._names_re.sub(lambda m: self._alias("class", m.group(1), "Cls_"), text)
        return text

    def reverse(self):
        """alias -> original, for de-obfuscating Claude's advice locally."""
        out = {}
        for kind in self.map:
            for original, alias in self.map[kind].items():
                out[alias] = original
        return out

    def save_map(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"forward": self.map, "reverse": self.reverse()}, f, indent=2)


def parse_terms(terms_csv, terms_file):
    terms = [t.strip() for t in (terms_csv or "").split(",") if t.strip()]
    if terms_file:
        terms += [l.strip() for l in open(terms_file, encoding="utf-8") if l.strip() and not l.startswith("#")]
    return terms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-package", default="")
    ap.add_argument("--app-classes-file", help="newline-separated app class simple names")
    ap.add_argument("--terms", default="", help="comma-separated custom terms to redact (company/project/game names)")
    ap.add_argument("--terms-file", help="newline-separated custom terms to redact (# lines ignored)")
    ap.add_argument("--map", default="redaction_map.json")
    a = ap.parse_args()
    classes = set()
    if a.app_classes_file:
        classes = {l.strip() for l in open(a.app_classes_file, encoding="utf-8") if l.strip()}
    r = Redactor(a.app_package, classes, terms=parse_terms(a.terms, a.terms_file))
    sys.stdout.write(r.redact(sys.stdin.read()))
    r.save_map(a.map)


if __name__ == "__main__":
    main()
