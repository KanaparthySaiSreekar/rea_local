#!/usr/bin/env python3
"""
Multi-version APK/APKM timeline analyzer — hybrid, local, privacy-preserving.

What it does
  - Handles .apk AND container formats (.apkm / .xapk / .apks / .zip of splits):
    extracts and analyzes the code-bearing base APK.
  - Orders every artifact in a folder oldest -> newest by versionCode.
  - For each version records: package, versionCode/Name, exported components,
    permissions, manifest flags, and the app's own class inventory.
  - Diffs each version vs the previous: permissions +/-, exported components +/-,
    flag flips, classes +/-, and (with --track-methods) methods +/- on the
    attack-surface (exported) classes.
  - With --triage, runs the local model over exposed entry methods and records
    vulnerability notes into a cumulative findings ledger.
  - Redaction uses ONE STABLE map across ALL versions, so Claude sees consistent
    placeholders and the over-time diffs stay meaningful. Real names never leave
    this machine (redaction_map.json).

Design notes
  - Runs on Windows (Python 3.12). Keep the APK folder on the Windows side
    (e.g. C:\\...\\apks\\myapp\\); the script converts paths to /mnt/c/... for REA
    in WSL and uses localhost Ollama. This avoids the WSL<->Windows networking and
    filesystem friction.
  - REA is the deterministic ground truth; the local model only triages text.

Usage (Windows PowerShell):
  python apk_timeline.py --dir C:\\path\\apks\\myapp --redact --track-methods \
      --triage --max-triage 4 --out-dir C:\\path\\apks\\myapp\\out
"""
import argparse, glob, io, json, os, re, subprocess, sys, time, urllib.request
import xml.etree.ElementTree as ET
import zipfile
from redact import Redactor, parse_terms

WSL_DISTRO = "Ubuntu-22.04"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
CONTAINER_EXT = (".apkm", ".xapk", ".apks", ".zip")


def win_to_wsl(p):
    p = os.path.abspath(p)
    return f"/mnt/{p[0].lower()}{p[2:].replace(chr(92), '/')}"


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
        raise RuntimeError(f"rea {args[0]} failed (exit {p.returncode}): {p.stderr.strip()[:300]}")
    return json.loads(p.stdout)


def ollama(prompt, model, base_url, timeout=600):
    body = json.dumps({
        "model": model, "stream": False,
        "messages": [
            {"role": "system", "content": "You are a concise application-security reviewer. "
             "Report only what the decompiled code shows; do not guess."},
            {"role": "user", "content": prompt}],
        "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"].strip()


def resolve_base_apk(path, workdir):
    """Return (windows_apk_path, note). For containers, extract the code-bearing base APK."""
    if path.lower().endswith(".apk"):
        return path, ""
    os.makedirs(workdir, exist_ok=True)
    with zipfile.ZipFile(path) as z:
        apks = [n for n in z.namelist() if n.lower().endswith(".apk")]
        code = []
        for n in apks:
            try:
                with z.open(n) as f:
                    inner = zipfile.ZipFile(io.BytesIO(f.read()))
                    if any(e.lower().endswith(".dex") for e in inner.namelist()):
                        code.append((n, z.getinfo(n).file_size))
            except Exception:
                pass
        base = next((n for n, _ in code if os.path.basename(n).lower() == "base.apk"), None)
        if not base and code:
            base = max(code, key=lambda x: x[1])[0]
        if not base and apks:
            base = apks[0]
        if not base:
            raise RuntimeError(f"no APK inside container {os.path.basename(path)}")
        out = os.path.join(workdir, "base.apk")
        with z.open(base) as src, open(out, "wb") as dst:
            dst.write(src.read())
        extra = [os.path.basename(n) for n, _ in code if n != base]
        note = f"extracted {base} from {os.path.basename(path)}"
        if extra:
            note += f"; other code-bearing splits NOT analyzed: {extra}"
        return out, note


def parse_manifest(manifest, package):
    root = ET.fromstring(manifest)
    app = root.find("application")
    perms = sorted({e.get(f"{ANDROID_NS}name") for e in root.findall("uses-permission")
                    if e.get(f"{ANDROID_NS}name")})
    entry = {"activity": ["onCreate"], "service": ["onStartCommand", "onCreate", "onBind"],
             "receiver": ["onReceive"], "provider": ["onCreate", "query"]}
    exported = []
    for kind in entry:
        for el in app.findall(kind):
            if el.get(f"{ANDROID_NS}exported") == "true":
                name = el.get(f"{ANDROID_NS}name") or ""
                fq = package + name if name.startswith(".") else (name if "." in name else f"{package}.{name}")
                exported.append({"kind": kind, "class": fq, "methods": entry[kind]})
    flags = {"usesCleartextTraffic": 'usesCleartextTraffic="true"' in manifest,
             "allowBackup": 'allowBackup="true"' in manifest,
             "debuggable": 'debuggable="true"' in manifest}
    return perms, exported, flags


def analyze_version(apk_wsl, track_methods, max_exported):
    res = rea(["decode-android-resources", apk_wsl, "--no-strings"])["normalized_result"]
    meta, manifest = res["metadata"], res["manifest"]
    pkg = meta["package_name"]
    perms, exported, flags = parse_manifest(manifest, pkg)
    inv = rea(["search-android-classes", apk_wsl, pkg])["normalized_result"]
    app_classes = sorted(c for c in (inv.get("matches") or []) if c.startswith(pkg))
    methods = {}
    if track_methods:
        for comp in exported[:max_exported]:
            try:
                r = rea(["inspect-android-class", apk_wsl, comp["class"]])["normalized_result"]
                methods[comp["class"]] = sorted(
                    f"{m.get('name')}{m.get('dex_descriptor', '')}" for m in (r.get("methods") or []))
            except Exception:
                pass
    return {"package": pkg, "versionCode": int(meta["version_code"]), "versionName": meta["version_name"],
            "minSdk": meta["min_sdk_version"], "targetSdk": meta["target_sdk_version"],
            "perms": perms, "exported": exported, "flags": flags,
            "app_classes": app_classes, "exported_methods": methods}


def diff(a, b):
    ea = {c["class"] for c in a["exported"]}
    eb = {c["class"] for c in b["exported"]}
    ca, cb = set(a["app_classes"]), set(b["app_classes"])
    d = {"from": a["versionName"], "to": b["versionName"],
         "perms_added": sorted(set(b["perms"]) - set(a["perms"])),
         "perms_removed": sorted(set(a["perms"]) - set(b["perms"])),
         "exported_added": sorted(eb - ea), "exported_removed": sorted(ea - eb),
         "flags_changed": {k: [a["flags"][k], b["flags"][k]] for k in b["flags"] if a["flags"].get(k) != b["flags"].get(k)},
         "classes_added": sorted(cb - ca), "classes_removed": sorted(ca - cb),
         "method_changes": {}}
    for cls in a["exported_methods"].keys() & b["exported_methods"].keys():
        ma, mb = set(a["exported_methods"][cls]), set(b["exported_methods"][cls])
        if ma != mb:
            d["method_changes"][cls] = {"added": sorted(mb - ma), "removed": sorted(ma - mb)}
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="Windows folder of .apk/.apkm artifacts (one app)")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--ollama", default="http://localhost:11434/v1")
    ap.add_argument("--redact", action="store_true")
    ap.add_argument("--redact-terms", default="", help="comma-separated extra terms to redact (company/project/game names)")
    ap.add_argument("--redact-terms-file", default=None, help="newline-separated extra terms to redact")
    ap.add_argument("--track-methods", action="store_true", help="diff methods of exported classes (slower: 1 JADX call each)")
    ap.add_argument("--max-exported", type=int, default=6, help="cap exported classes for method tracking")
    ap.add_argument("--triage", action="store_true", help="local-model vuln triage of exposed entry methods")
    ap.add_argument("--max-triage", type=int, default=4)
    a = ap.parse_args()
    out = a.out_dir or os.path.join(a.dir, "timeline-out")
    os.makedirs(out, exist_ok=True)

    artifacts = sorted(sum([glob.glob(os.path.join(a.dir, "*" + e)) for e in (".apk",) + CONTAINER_EXT], []))
    print(f"[plan] {len(artifacts)} artifact(s) in {a.dir}", flush=True)
    versions = []
    for art in artifacts:
        wd = os.path.join(out, "extract", os.path.splitext(os.path.basename(art))[0])
        apk_win, note = resolve_base_apk(art, wd)
        if note:
            print(f"[extract] {note}", flush=True)
        print(f"[rea] analyzing {os.path.basename(art)} ...", flush=True)
        v = analyze_version(win_to_wsl(apk_win), a.track_methods, a.max_exported)
        v["artifact"] = os.path.basename(art)
        v["format"] = "container" if art.lower().endswith(CONTAINER_EXT) else "apk"
        versions.append(v)
        print(f"[rea]   v{v['versionName']} (code {v['versionCode']}) "
              f"classes={len(v['app_classes'])} exported={len(v['exported'])}", flush=True)
    versions.sort(key=lambda v: v["versionCode"])

    transitions = [diff(versions[i - 1], versions[i]) for i in range(1, len(versions))]

    # stable redactor over the UNION of app classes across every version
    redactor = None
    if a.redact:
        union = set()
        for v in versions:
            for fq in v["app_classes"] + [c["class"] for c in v["exported"]]:
                for part in fq.rsplit(".", 1)[-1].split("$"):
                    if len(part) >= 3:
                        union.add(part)
        redactor = Redactor(app_package=versions[0]["package"], app_classes=union,
                            terms=parse_terms(a.redact_terms, a.redact_terms_file))

    # triage exposed entry methods of the LATEST version + newly-exported-in-any-transition
    triage = []
    if a.triage and versions:
        latest = versions[-1]
        apk_win, _ = resolve_base_apk(os.path.join(a.dir, latest["artifact"]),
                                      os.path.join(out, "extract", os.path.splitext(latest["artifact"])[0]))
        apk_wsl = win_to_wsl(apk_win)
        done = 0
        for comp in latest["exported"]:
            if done >= a.max_triage:
                break
            for m in comp["methods"]:
                if done >= a.max_triage:
                    break
                try:
                    ev = rea(["inspect-android-method", apk_wsl, comp["class"], m])
                except Exception:
                    continue
                body = ((ev.get("normalized_result") or {}).get("source") or {}).get("text")
                if not body:
                    continue
                print(f"[triage] {comp['class']}.{m} ...", flush=True)
                summary = ollama(
                    f"EXPORTED {comp['kind']} entry method {comp['class']}.{m}, reachable by other apps. "
                    f"In 2-3 sentences: what untrusted input it reads, where it flows (file/network/SQL/"
                    f"WebView/startActivity/dynamic load), and any missing validation. Code:\n```java\n{body}\n```",
                    a.model, a.ollama)
                rec = {"version": latest["versionName"], "class": comp["class"], "method": m,
                       "evidence_id": ev.get("evidence_id"), "summary": summary}
                if redactor:
                    rec["red_class"] = redactor.redact(comp["class"])
                    rec["red_summary"] = redactor.redact(summary)
                triage.append(rec)
                done += 1

    ledger = {"package": versions[0]["package"] if versions else None,
              "generated": time.strftime("%Y-%m-%d %H:%M"),
              "versions": [{k: v[k] for k in ("artifact", "format", "versionCode", "versionName",
                            "minSdk", "targetSdk", "flags", "perms", "exported", )} |
                           {"class_count": len(v["app_classes"])} for v in versions],
              "transitions": transitions, "triage": triage}
    json.dump(ledger, open(os.path.join(out, "findings-ledger.json"), "w", encoding="utf-8"), indent=2)

    def render(red):
        R = (lambda s: redactor.redact(s)) if (red and redactor) else (lambda s: s)
        L = [f"# APK timeline — {R(ledger['package'] or '')}",
             "_Redacted view — safe to share; real names in redaction_map.json (local)._" if red else
             "_Full local report — stays on your machine._", "",
             "## Versions (oldest → newest)", "",
             "| version | code | format | classes | exported | cleartext | backup |", "|---|---|---|---|---|---|---|"]
        for v in versions:
            L.append(f"| {v['versionName']} | {v['versionCode']} | {v['format']} | {len(v['app_classes'])} "
                     f"| {len(v['exported'])} | {v['flags']['usesCleartextTraffic']} | {v['flags']['allowBackup']} |")
        L += ["", "## What changed between versions", ""]
        for t in transitions:
            L += [f"### {t['from']} → {t['to']}"]
            if t["perms_added"]: L.append(f"- **permissions added:** {', '.join(t['perms_added'])}")
            if t["perms_removed"]: L.append(f"- permissions removed: {', '.join(t['perms_removed'])}")
            if t["exported_added"]: L.append(f"- **newly exported:** {', '.join(R(x) for x in t['exported_added'])}")
            if t["exported_removed"]: L.append(f"- no longer exported: {', '.join(R(x) for x in t['exported_removed'])}")
            if t["flags_changed"]: L.append(f"- **flags changed:** {t['flags_changed']}")
            if t["classes_added"]: L.append(f"- classes added: {len(t['classes_added'])} (e.g. {', '.join(R(x) for x in t['classes_added'][:5])})")
            if t["classes_removed"]: L.append(f"- classes removed: {len(t['classes_removed'])} (e.g. {', '.join(R(x) for x in t['classes_removed'][:5])})")
            for cls, mc in t["method_changes"].items():
                L.append(f"- methods on `{R(cls)}`: +{len(mc['added'])} / -{len(mc['removed'])}")
            if not any([t["perms_added"], t["perms_removed"], t["exported_added"], t["exported_removed"],
                        t["flags_changed"], t["classes_added"], t["classes_removed"], t["method_changes"]]):
                L.append("- no tracked changes")
            L.append("")
        if triage:
            L += ["## Vulnerability triage — latest version (exposed entry methods)", ""]
            for r in triage:
                cls = r.get("red_class") if red else r["class"]
                summ = r.get("red_summary") if red else r["summary"]
                L += [f"### {cls}.{r['method']}", f"REA evidence: `{r['evidence_id']}`", "", summ, ""]
        return "\n".join(L)

    open(os.path.join(out, "timeline-report.md"), "w", encoding="utf-8").write(render(False))
    if redactor:
        open(os.path.join(out, "timeline-report.claude-safe.md"), "w", encoding="utf-8").write(render(True))
        redactor.save_map(os.path.join(out, "redaction_map.json"))
    print(f"\n[done] {len(versions)} versions, {len(transitions)} transitions, {len(triage)} triaged -> {out}", flush=True)


if __name__ == "__main__":
    main()
