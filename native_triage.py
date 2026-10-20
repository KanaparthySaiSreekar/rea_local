#!/usr/bin/env python3
"""
Targeted native-function decompiler for libil2cpp.so (Unity/IL2CPP) — private + hybrid.

Avoids whole-binary Ghidra blowups: analyze the lib ONCE into a reusable snapshot, then
decompile only the functions you name. Targets are FILE OFFSETS from Il2CppDumper's
dump.cs ("// RVA: 0x..  Offset: 0x.." lines) fed to `rea decompile --file-offset`.
Output is redacted (string literals + your custom terms) so it's safe to share with Claude.

Runs on Windows (Python 3.12, stdlib + local redact.py); converts paths to /mnt/c for REA
in WSL and bakes a long Ghidra timeout into the one-time analysis.

Workflow:
  1) (your side) extract from the APK/APKM, locally:
       lib/arm64-v8a/libil2cpp.so
       assets/bin/Data/Managed/Metadata/global-metadata.dat
  2) (your side) recover symbols + offsets:
       Il2CppDumper libil2cpp.so global-metadata.dat out\      # -> out\dump.cs
     find the methods you care about; copy their "Offset:" values.
  3) python native_triage.py --so C:\...\libil2cpp.so --snapshot C:\...\il2cpp.snap \
         --offsets 0x1a2b3c,0x1d4e5f --redact-terms "codename1,codename2" --out native-report.md
     (or --offsets-file offsets.txt : one "0xADDR   # label" per line)
"""
import argparse, json, os, subprocess, sys
from redact import Redactor, parse_terms

WSL_DISTRO = "Ubuntu-22.04"
GHIDRA_TIMEOUT_MS = "2700000"   # 45 min for the one-time whole-lib analysis
_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")


def _q(s):
    s = str(s)
    return s if (s and all(c in _SAFE for c in s)) else "'" + s.replace("'", "'\\''") + "'"


def win_to_wsl(p):
    p = os.path.abspath(p)
    return f"/mnt/{p[0].lower()}{p[2:].replace(chr(92), '/')}"


def rea(args, timeout=3000):
    inner = (f"REA_GHIDRA_STARTUP_TIMEOUT_MS={GHIDRA_TIMEOUT_MS} rea "
             + " ".join(_q(a) for a in args) + " --format json")
    p = subprocess.run(["wsl.exe", "-d", WSL_DISTRO, "--exec", "bash", "-lc", inner],
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"rea {args[0]} failed (exit {p.returncode}): {p.stderr.strip()[:300]}")
    return json.loads(p.stdout)


def pseudocode(ev):
    nr = ev.get("normalized_result")
    if isinstance(nr, str):
        return nr
    if isinstance(nr, dict):
        for k in ("value", "text", "code"):
            if isinstance(nr.get(k), str):
                return nr[k]
    rr = ev.get("raw_result")
    if isinstance(rr, dict) and isinstance(rr.get("value"), str):
        return rr["value"]
    return json.dumps(nr or rr)[:2000]


def load_targets(offsets_csv, offsets_file):
    out = []
    for t in (offsets_csv or "").split(","):
        if t.strip():
            out.append((t.strip(), ""))
    if offsets_file:
        for line in open(offsets_file, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            off, _, lbl = line.partition("#")
            if off.strip():
                out.append((off.strip(), lbl.strip()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", required=True, help="Windows path to libil2cpp.so")
    ap.add_argument("--snapshot", required=True, help="snapshot path (created first run, reused after)")
    ap.add_argument("--offsets", default="", help="comma list of dump.cs 'Offset:' values (0x..)")
    ap.add_argument("--offsets-file", help="one '0xADDR  # label' per line")
    ap.add_argument("--provider", default="ghidra")
    ap.add_argument("--redact", action="store_true")
    ap.add_argument("--redact-terms", default="", help="comma-separated codenames to scrub")
    ap.add_argument("--redact-terms-file")
    ap.add_argument("--app-package", default="")
    ap.add_argument("--out", default="native-report.md")
    a = ap.parse_args()

    so_wsl, snap_wsl = win_to_wsl(a.so), win_to_wsl(a.snapshot)
    targets = load_targets(a.offsets, a.offsets_file)
    if not targets:
        sys.exit("no --offsets/--offsets-file given (use the 'Offset:' values from dump.cs)")

    if not os.path.exists(a.snapshot):
        print(f"[native] one-time whole-lib analysis of {os.path.basename(a.so)} -> snapshot "
              f"(slow: minutes to ~an hour on this hardware; only happens once) ...", flush=True)
        rea(["analyze", so_wsl, "--provider", a.provider, "--snapshot", snap_wsl], timeout=3000)
        print("[native] snapshot ready; later runs reuse it and are fast", flush=True)

    redactor = (Redactor(app_package=a.app_package, app_classes=set(),
                         terms=parse_terms(a.redact_terms, a.redact_terms_file))
                if a.redact else None)

    rows = []
    for off, lbl in targets:
        print(f"[decompile] {off} {lbl} ...", flush=True)
        try:
            ev = rea(["decompile", so_wsl, "--file-offset", off, "--provider", a.provider,
                      "--snapshot", snap_wsl])
            rows.append((off, lbl, ev.get("evidence_id"), pseudocode(ev)))
        except Exception as e:
            rows.append((off, lbl, None, f"(decompile failed: {e})"))

    md = [f"# Native triage — {os.path.basename(a.so)}", ""]
    if redactor:
        md.append("_Redacted (string literals + your terms scrubbed); real map stays local._")
        md.append("")
    for off, lbl, ev, code in rows:
        c = redactor.redact(code) if (redactor and code) else code
        md += [f"## {lbl or off}  (offset {off})",
               f"REA evidence: `{ev}`" if ev else "", "",
               "```c", (c or "").strip()[:4000], "```", ""]
    open(a.out, "w", encoding="utf-8").write("\n".join(md))
    if redactor:
        redactor.save_map(os.path.splitext(a.out)[0] + ".redaction_map.json")
    print(f"[done] {len(rows)} functions -> {a.out}", flush=True)


if __name__ == "__main__":
    main()
