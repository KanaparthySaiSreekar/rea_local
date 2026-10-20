#!/usr/bin/env python3
"""
Hybrid local RE pipeline for APKs.

Roles:
  - REA (in WSL)       : deterministic decompilation / manifest decode = ground truth.
  - local model (Ollama): triage/summarize each decompiled method = fast, local, fallible.
  - the PLAN            : which components/methods to look at (this script, or you/Claude).

Nothing leaves the machine. With --redact, the pipeline also emits a "Claude-safe"
view where your app's identifiers and string contents are replaced by placeholders,
so you can ask Claude for help without sharing proprietary names/code. The real
mapping stays local in redaction_map.json.

Stdlib only + local redact.py. Run from Windows PowerShell, Python 3.12:
  python hybrid_re.py --apk /home/<you>/app.apk --max-methods 8 --out report.md --redact
"""
import argparse, json, subprocess, sys, time, urllib.request, xml.etree.ElementTree as ET
from redact import Redactor, parse_terms

WSL_DISTRO = "Ubuntu-22.04"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")


def _q(s):
    # single-quote anything that isn't a plain safe token (handles spaces, (), commas, &, ; etc.)
    s = str(s)
    if s and all(c in _SAFE for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def rea(args, timeout=1800):
    inner = "rea " + " ".join(_q(a) for a in args) + " --format json"
    cmd = ["wsl.exe", "-d", WSL_DISTRO, "--exec", "bash", "-lc", inner]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"rea {args[0]} failed (exit {p.returncode}): {p.stderr.strip()[:400]}")
    return json.loads(p.stdout)


def ollama(prompt, model, base_url, timeout=600):
    body = json.dumps({
        "model": model, "stream": False,
        "messages": [
            {"role": "system", "content": "You are a concise application-security reviewer. "
             "You read decompiled Android (JADX) methods and report only what the code shows."},
            {"role": "user", "content": prompt},
        ],
        "options": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"].strip()


def fqcn(name, package):
    if not name:
        return name
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


def exported_components(manifest_xml, package):
    root = ET.fromstring(manifest_xml)
    app = root.find("application")
    entry = {"activity": ["onCreate"], "service": ["onStartCommand", "onCreate", "onBind"],
             "receiver": ["onReceive"], "provider": ["onCreate", "query"]}
    out = []
    for kind in entry:
        for el in app.findall(kind):
            if el.get(f"{ANDROID_NS}exported") == "true":
                out.append((kind, fqcn(el.get(f"{ANDROID_NS}name"), package), entry[kind]))
    return out


def app_class_simple_names(apk, package):
    """App's own class simple-names (+ inner-class names) from REA, for redaction."""
    try:
        matches = (rea(["search-android-classes", apk, package]).get("normalized_result") or {}).get("matches") or []
    except Exception:
        return set()
    names = set()
    for fq in matches:
        for part in fq.rsplit(".", 1)[-1].split("$"):
            if len(part) >= 3:
                names.add(part)
    return names


def decompile(apk, cls, method):
    try:
        ev = rea(["inspect-android-method", apk, cls, method])
    except Exception:
        return None, None
    nr = ev.get("normalized_result") or {}
    return ((nr.get("source") or {}).get("text") or None), ev.get("evidence_id")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True, help="APK path as WSL sees it")
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--ollama", default="http://localhost:11434/v1")
    ap.add_argument("--max-methods", type=int, default=4)
    ap.add_argument("--out", default="hybrid-report.md")
    ap.add_argument("--redact", action="store_true",
                    help="also emit a Claude-safe redacted view + local redaction_map.json")
    ap.add_argument("--app-package", default=None, help="override app package (default: from manifest)")
    ap.add_argument("--redact-terms", default="", help="comma-separated extra terms to redact (company/project/game names)")
    ap.add_argument("--redact-terms-file", default=None, help="newline-separated extra terms to redact")
    ap.add_argument("--redaction-map", default="redaction_map.json")
    a = ap.parse_args()

    print(f"[plan] decoding manifest + package inventory of {a.apk}", flush=True)
    res = rea(["decode-android-resources", a.apk, "--no-strings"])["normalized_result"]
    meta, manifest = res["metadata"], res["manifest"]
    pkg = meta["package_name"]
    pkgres = rea(["inspect-android-package", a.apk])["normalized_result"]
    classes = pkgres.get("class_count") or (pkgres.get("summary") or {}).get("class_count")

    app_class = fqcn(ET.fromstring(manifest).find("application").get(f"{ANDROID_NS}name"), pkg)
    comps = exported_components(manifest, pkg)
    cleartext = 'usesCleartextTraffic="true"' in manifest
    allow_backup = 'allowBackup="true"' in manifest

    redactor = None
    if a.redact:
        app_pkg = a.app_package or pkg
        print(f"[redact] gathering app-owned class names under {app_pkg} ...", flush=True)
        red_classes = app_class_simple_names(a.apk, app_pkg)
        redactor = Redactor(app_package=app_pkg, app_classes=red_classes,
                            terms=parse_terms(a.redact_terms, a.redact_terms_file))
        print(f"[redact] {len(red_classes)} app class names will be scrubbed before sharing", flush=True)

    targets = [("application", app_class, ["onCreate"])] + comps
    print(f"[plan] package={pkg} classes={classes} exported components={len(comps)} "
          f"cleartext={cleartext} allowBackup={allow_backup}", flush=True)

    findings, done = [], 0
    for kind, cls, methods in targets:
        if done >= a.max_methods:
            break
        for m in methods:
            if done >= a.max_methods:
                break
            print(f"[rea] decompiling {cls}.{m} ...", flush=True)
            body, ev = decompile(a.apk, cls, m)
            if not body:
                continue
            print(f"[local-model] triaging {cls}.{m} ({len(body)} chars) ...", flush=True)
            t0 = time.time()
            summary = ollama(
                f"Decompiled method {cls}.{m} (component kind: {kind}, exported entry point).\n"
                f"In 2-3 sentences: what does it do, and flag any security-relevant behavior "
                f"(intent/extra handling, file or network IO, crypto, dynamic loading, injection "
                f"risks). Code:\n```java\n{body}\n```",
                a.model, a.ollama)
            f = {"kind": kind, "class": cls, "method": m, "evidence_id": ev,
                 "chars": len(body), "secs": round(time.time() - t0, 1), "summary": summary}
            if redactor:
                f["red_class"] = redactor.redact(cls)
                f["red_body"] = redactor.redact(body)
                f["red_summary"] = redactor.redact(summary)
            findings.append(f)
            done += 1

    md = [f"# Hybrid RE report — {pkg}", "",
          f"- APK (WSL path): `{a.apk}`",
          f"- package: `{pkg}`  version: {meta['version_name']}  "
          f"minSdk: {meta['min_sdk_version']}  targetSdk: {meta['target_sdk_version']}",
          f"- classes: {classes}  exported components: {len(comps)}",
          f"- manifest flags: usesCleartextTraffic={cleartext}  allowBackup={allow_backup}",
          f"- model: {a.model} (local)   REA: deterministic (evidence IDs below)"]
    if redactor:
        md.append(f"- redaction: ON — Claude-safe view below; real names only in `{a.redaction_map}` (local)")
    md += ["", "## Local triage (full fidelity — stays on your machine)", ""]
    for f in findings:
        md += [f"### {f['class']}.{f['method']}  _({f['kind']}, {f['secs']}s)_",
               f"REA evidence: `{f['evidence_id']}`  ({f['chars']} chars decompiled)", "",
               f["summary"], ""]

    if redactor:
        md += ["---", "", "## Claude-safe view (redacted — OK to share with Claude)", "",
               "_Your app's identifiers and string contents are placeholders; the real mapping "
               f"is in `{a.redaction_map}` and never leaves this machine._", ""]
        for f in findings:
            md += [f"### {f['red_class']}.{f['method']}", "",
                   "```java", f["red_body"].strip()[:1500], "```", "",
                   "Triage (redacted): " + f["red_summary"], ""]
        redactor.save_map(a.redaction_map)
        print(f"[redact] wrote local map -> {a.redaction_map}", flush=True)

    open(a.out, "w", encoding="utf-8").write("\n".join(md))
    print(f"\n[done] {len(findings)} methods triaged -> {a.out}", flush=True)


if __name__ == "__main__":
    main()
