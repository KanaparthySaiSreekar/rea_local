# hermes-rea — local, privacy-preserving APK reverse-engineering toolkit

A small toolkit for reverse-engineering and security-reviewing **your own** Android
apps entirely on your machine, for authorized security research. It splits the work by
what each part is good at and keeps your code private:

- **REA** (reverse-engineering engine, runs in WSL) — the deterministic ground truth:
  manifest decode, class/method inventory, decompilation.
- **A local LLM** (via [Ollama](https://ollama.com), e.g. `qwen3.5:4b`) — bulk triage and
  summarization of decompiled code, running on-device.
- **A redaction layer** — scrubs your identifiers and strings to stable placeholders
  *before* anything is shared with a remote assistant, reversible only via a local map.

Nothing proprietary leaves the machine: the local model reads the real decompiled code
on-device; only a redacted view is ever meant to be shared externally.

## Scripts
| file | what it does |
|---|---|
| `hybrid_re.py` | single APK: decode manifest, pick exported components, decompile entry methods, local-model triage, redacted report |
| `apk_timeline.py` | multi-version: handles `.apk` and containers (`.apkm`/`.xapk`/`.apks`), orders by versionCode, diffs permissions/exported-surface/classes/methods over time, triages, keeps a findings ledger — one stable redaction map across versions |
| `redact.py` | deterministic redactor: app package + class names + string literals → `APPPKG1`/`Cls_N`/`STR_N`, plus custom `--terms` (company/project/game names) → `TERM_N` |
| `unredact.py` | reverse of `redact.py`: expand placeholder-space advice back to real names locally |
| `ask_local.py` | bridge: unredact an instruction, run it on the local model, re-redact the reply |
| `re_chat.py` | interactive per-method loop (`/manifest`, `/decompile`, `/claude`) |
| `multiagent_demo.py` | sequential local planner→worker demo over one model |
| `native_triage.py` | helper for the native (IL2CPP) lane |

## Guides
- `SETUP-AND-PLAYBOOK.md` — install/config, the APK review playbook, how the roles split.
- `TIMELINE-RUNBOOK.md` — multi-version over-time analysis, flags, outputs, prompts.
- `NATIVE-LANE.md` — analyzing Unity/IL2CPP `libil2cpp.so` with Il2CppDumper + Ghidra/REA.

## Requirements
- REA installed in WSL (invoked via `wsl.exe … bash -lc "rea …"`).
- Ollama on the host with a tool-capable model pulled.
- Python 3.12 (stdlib only — no pip dependencies).
- Optional native lane: Il2CppDumper + .NET 6 runtime.

## Privacy / scope
Intended for reverse-engineering and security-reviewing software **you own or are
authorized to test**. By design, this repo contains **only the tooling** — redaction
maps, reports, findings ledgers, target APKs, and any `terms.txt` are git-ignored and
never committed (see `.gitignore`). Keep them local.
