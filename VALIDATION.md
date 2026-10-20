# Validation record

Status of the toolkit as of 2026-10-20. Validation used **AntennaPod** (an open-source,
freely-redistributable podcast app) as a public test subject — no private app data is in
this repo.

## Scripts
All Python scripts pass a syntax/compile check (`python -m py_compile`):
`apk_timeline.py`, `hybrid_re.py`, `redact.py`, `unredact.py`, `ask_local.py`,
`re_chat.py`, `multiagent_demo.py`, `native_triage.py`.

## Hybrid pipeline (`hybrid_re.py`)
Validated end-to-end on AntennaPod 3.12.3: decoded the manifest (exported components,
permissions, flags), inventoried ~5,000 classes, decompiled entry methods via REA, and
the local model triaged each — accurate, no fabricated findings — with REA evidence IDs
attached for provenance. Works with both `qwen3.5:4b` and an uncensored equivalent;
tool-calling confirmed against Ollama's OpenAI-compatible endpoint.

## Version timeline (`apk_timeline.py`)
Validated across AntennaPod 3.12.1 → 3.12.2 → 3.12.3, where the newest was wrapped as a
synthetic `.apkm`:
- Container extraction worked (pulled the code-bearing `base.apk` from the `.apkm`).
- Versions ordered by versionCode; consecutive-version diffs produced for permissions,
  exported components, manifest flags, classes, and methods of exported classes.
- Correctly flagged a newly-exported component introduced between versions.
- Emitted the full local report, the redacted Claude-safe report, and a findings ledger,
  with one stable redaction map across all versions.

## Redaction (`redact.py` / `unredact.py`)
- Scrubs app package, app class simple-names, and all string-literal contents to
  `APPPKG1` / `Cls_N` / `STR_N`, keeping framework/library symbols and control flow.
- Custom `--terms` / `--terms-file` scrub arbitrary names (company/project/game codenames)
  case-insensitively as substrings → `TERM_N` (catches them inside dotted packages and
  permission strings).
- Round-trip verified: `unredact.py` restores placeholder-space advice to real names
  locally (longest-alias-first, word-boundary so `Cls_1` ≠ `Cls_12`).

## Multi-agent (`multiagent_demo.py`)
Sequential planner → execute(REA) → worker over a single local model ran successfully.
Finding: mechanically works; a 4B is a weak *planner*, which is why the normal setup puts
a stronger planner over local workers.

## Native (IL2CPP) lane
Il2CppDumper v6.7.46 (net6-win) installed; runs on the host's existing .NET 6.0.11.
REA ingests ARM64 ELF and Ghidra decompiles aarch64; whole-binary auto-analysis of a
large stripped library exceeds the default Ghidra deadline, so the lane targets specific
functions after symbol recovery (see `NATIVE-LANE.md`).

## Host
Windows 11 + WSL (Ubuntu) with REA/Ghidra/JADX/apktool; RTX 3050 (4 GB) / 16 GB RAM;
Ollama on the host; .NET 6 present. Local models run as a GPU/CPU split on this hardware.
