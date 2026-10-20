# Final runbook — multi-version APK RE over time (local + private)

Analyze a whole history of your app (`.apk` and `.apkm`/`.xapk`/`.apks`), track how
classes, methods, permissions and exposed surface change version to version, triage
vulnerabilities per version, and keep a cumulative findings ledger — all on your
machine, with redaction so you can bring me in without sharing real names/code.

Tools in `C:\Users\kanap\Desktop\claudeWork\hermes-rea\`:
- `apk_timeline.py` — the version-timeline engine (this runbook).
- `hybrid_re.py` — single-version deep triage of one APK (drill-down).
- `redact.py` — deterministic local redactor (used by both; also standalone).

---

## 0. One-time setup (your own terminal)

```powershell
ollama list                                   # qwen3.5:4b and/or qwen3.5-4b-uncensored present
wsl -d Ubuntu-22.04 -- bash -lc "rea doctor"  # NOTE: rea only works inside `bash -lc`
```
`rea` lives on the PATH only in a **login shell**, so always wrap manual REA calls in
`bash -lc "..."`. (The Python scripts already do this internally.)

Pick the model once: `qwen3.5:4b` (stock) or `qwen3.5-4b-uncensored` (abliterated —
same quality here, won't refuse). Pass it with `--model` on any script.

---

## 1. Lay out your versions

Put every build in ONE Windows folder (keep them on the Windows side so the script can
read/extract them; it converts paths to `/mnt/c/...` for REA automatically):

```
C:\Users\kanap\Desktop\claudeWork\apks\myapp\
  myapp-1.0.0.apk
  myapp-1.2.0.apkm        <- container (base + splits); handled automatically
  myapp-2.0.0.apk
  ...
```
Mixed `.apk` and `.apkm`/`.xapk`/`.apks` is fine. For containers the engine extracts the
code-bearing **base APK** and notes any feature-split code it skipped. Ordering is by
`versionCode` from the manifest, not filename — so naming doesn't matter.

---

## 2. Run the timeline

```powershell
cd C:\Users\kanap\Desktop\claudeWork\hermes-rea
python apk_timeline.py --dir C:\Users\kanap\Desktop\claudeWork\apks\myapp `
    --redact --track-methods --triage --max-triage 6 --model qwen3.5-4b-uncensored
```
Flags:
- `--redact` — also write the Claude-safe redacted report + stable `redaction_map.json`.
- `--track-methods` — diff methods on exported (attack-surface) classes across versions
  (1 JADX call per exported class per version — slower; cap with `--max-exported N`).
- `--triage` — local-model vulnerability triage of the **latest** version's exposed entry
  methods (`--max-triage N` caps how many).
- Omit `--track-methods`/`--triage` for a fast first pass (manifest + class inventory diff only).

Outputs land in `<dir>\timeline-out\`:
| file | what | share? |
|---|---|---|
| `timeline-report.md` | full report, real names | **local only** |
| `timeline-report.claude-safe.md` | redacted report | **safe to paste to me** |
| `findings-ledger.json` | cumulative machine-readable record (versions, transitions, triage) | local only |
| `redaction_map.json` | stable alias → real-name map | **never leaves your machine** |

---

## 3. What it tracks over time

Per version: package, versionCode/Name, min/target SDK, exported components, permissions,
manifest flags (`cleartext`, `backup`, `debuggable`), app-owned class inventory, and
(with `--track-methods`) the method set of each exported class.

Per transition (vN-1 → vN): **permissions added/removed**, **components newly/no-longer
exported**, **flag flips**, **classes added/removed**, and **methods added/removed on
exported classes**. That's your "what changed in classes and methods over time" and
"new exposure introduced / vulnerability surface opened" view, version by version.

The redaction map is built **once over all versions** (stable aliases), so `Cls_42` means
the same real class in every version and the diffs stay meaningful in placeholder-space.

---

## 4. Privacy model (unchanged, enforced in code)

- The **local model reads the real decompiled code** on-device — full fidelity, nothing shared.
- Only the **`.claude-safe.md`** report is meant to reach me: your package, class names and
  all string-literal contents are placeholders (`APPPKG1`, `Cls_N`, `"STR_N"`); framework/
  library symbols and control flow stay so I can still reason.
- Known gap (your choice to leave as-is): method names, field names and `R.id.*` are NOT
  redacted — only classes/package/strings are.
- You translate my advice back with `redaction_map.json` locally. For anything you paste me
  by hand, pipe it through `redact.py` first:
  `type snippet.txt | python redact.py --app-package com.your.pkg --map redaction_map.json`

---

## 5. How to bring me in, and how I orchestrate

I'm the **planner/analyst over the timeline**; the local model is the **reader/triager**;
REA is the **ground truth**. The loop:

1. You run §2, then paste me the **`timeline-report.claude-safe.md`** (and optionally the
   redacted triage).
2. I read the version diffs and point at the risky moments — e.g. *"a receiver became
   exported at 1.2.0 and a new `WRITE_EXTERNAL_STORAGE` permission appeared the same
   release — decompile `Cls_14.onReceive` in 1.2.0 and 2.0.0 and compare."*
3. You run that locally:
   ```powershell
   python hybrid_re.py --apk /mnt/... --redact --max-methods 4   # deep triage one build
   # or a single method:
   wsl -d Ubuntu-22.04 -- bash -lc "rea inspect-android-method <apk> <Cls> <method> --format json"
   ```
4. You paste me the redacted method body + local-model triage.
5. I reason in placeholder-space (hypothesis, taint path, the specific bug class), tell you
   what to check or trace next, and keep the running hypothesis ledger. You confirm against
   your real source (you have it — your app) and map placeholders back.
6. Repeat, narrowing to confirmed findings tied to the version they appeared in.

What I provide: version-diff interpretation, picking targets, forming/testing vulnerability
hypotheses, reading redacted decompilation, suggesting REA traces (`xrefs`,
`trace_android_references`, call paths), and keeping the over-time findings story straight —
without ever seeing your real identifiers or code.

---

## 6. Prompts

**Local-model triage (per exposed entry method)** — the script uses this; reuse it manually too:
```
This is an EXPORTED <activity|service|receiver|provider> entry method reachable by other
apps. From the code only: 1) what untrusted input it reads (Intent extras, Uri, Bundle),
2) where that input flows (file, network, SQL, WebView, startActivity, dynamic load),
3) any missing validation or permission check. Be specific; do not guess.
Code:
```java
<decompiled method>
```
```

**Diff-focused (compare a method across two versions):**
```
Same method from two versions of an app. Describe precisely what changed in behavior
(not formatting), and whether the change adds or removes a security-relevant path.
OLD:
```java
<old redacted body>
```
NEW:
```java
<new redacted body>
```
```

**What you paste to me:**
```
Timeline says: <paste the relevant transition bullets from claude-safe report>
Target: <Cls_N>.<method> (exported <kind>), versions <x> and <y>
Redacted decompilation / triage:
<paste>
Question: is this a real/widening risk over these versions, and what do I trace next?
```

---

## 7. Android bug classes we check (per exposed method, across versions)
exported-component / intent hijack · `content://` path traversal in FileProviders ·
insecure deep-link handling · WebView `addJavascriptInterface` / `loadUrl` with untrusted
input · SQL built from extras · broadcast/receiver trust · PendingIntent mutability ·
world-readable or backup-exposed data · hardcoded/weak crypto · newly-exported surface or
new dangerous permission appearing in a release.

Discipline: REA output is "observed"; static ≠ runtime. Treat the local model's note as a
lead, confirm against the real decompiled code, and (since it's your app) against your source.

---

## 8. Interactive shell — `re_chat.py` (chat/CLI, the live hybrid)

A session over ONE APK where you type prompts and it drives the local model + REA,
with Claude reachable through redaction. Run it in your own terminal:

```powershell
cd C:\Users\kanap\Desktop\claudeWork\hermes-rea
python re_chat.py --apk C:\...\apks\myapp\app-release.apk --model qwen3.5-4b-uncensored
```

Commands:
| command | what |
|---|---|
| `/open <apk\|apkm>` | open a target (or pass `--apk` at launch) |
| `/manifest` | package, exported components, permissions, flags |
| `/classes <substr>` · `/methods <class\|Cls_N>` | search classes · list a class's methods |
| `/decompile <class\|Cls_N> <method> [idx]` | REA decompiles; starts a chat about it |
| `/decompileall [dir] [app\|all] [max]` | FULL local teardown: manifest + attack-surface JSON, every class → every method overload → one `.java` file (evidence ids in `index.json`), all `.so` from base AND container splits, automatic Il2CppDumper on `libil2cpp.so`+`global-metadata.dat`. Resumable (re-run skips existing files, Ctrl+C safe). Writes REAL names — folder is gitignored |
| *free text* or `/ask <q>` | ask the LOCAL model about the current method — conversational, builds on prior turns (your feedback loop) |
| `/claude [question]` | print a REDACTED block to paste into your Claude chat |
| `/plan <directive>` | run Claude's reply locally, de-aliasing `Cls_N`→real, e.g. `/plan decompile Cls_14 onReceive`, `/plan methods Cls_9`, `/plan note <text>` |
| `/note` · `/save [path]` · `/model <name>` · `/help` · `/quit` | log · persist (+ redaction_map.json) · switch model · help · exit |
| `--script <file>` | run commands from a file then exit (replay / batch; use this where stdin isn't interactive) |

The three-way loop:
1. `/decompile …` → the local model summarizes (it reads the REAL code on-device).
2. Chat with it: *"is this reachable from untrusted input?"* — it answers in context.
3. `/claude` → paste the redacted block into your Claude chat → Claude replies in
   placeholders, e.g. *"decompile `Cls_14.onReceive`, trace the Intent extra."*
4. `/plan decompile Cls_14 onReceive` → the shell turns `Cls_14` back into the real
   class locally and runs it. Loop closes; you never retype real names, Claude never
   sees them.

`/save` writes `re_session.json` (transcript + notes) and the stable `redaction_map.json`.
Use `/model qwen3.5-4b-uncensored` for the abliterated model, `qwen3.5:4b` for stock.
