# Native lane — analyzing `libil2cpp.so` (Unity / IL2CPP) with REA

Your app is Unity/IL2CPP: at the big rewrite the Java/DEX collapsed to a thin glue
shell, and the real game logic moved into **native ARM64** (`libil2cpp.so`). The
Java-layer timeline covers the **Android attack surface** (exported components, IPC,
permissions). This lane covers the **native logic** (game rules, anti-cheat, network
protocol, embedded secrets) — harder, optional, do it only if that's your goal.

## Verified on this machine (non-app binary)
- REA ingests ARM64 ELF: `open_binary` on an aarch64 ELF returned `architecture: arm64`,
  Ghidra bound. ✓
- Ghidra decompiles ARM64: its log showed it decompiling aarch64 functions. ✓
- Caveat (also observed): whole-binary auto-analysis of a **large stripped** aarch64
  binary **exceeded the default 330 s Ghidra deadline**. `libil2cpp.so` is large and
  stripped, so you must either raise the timeout, trim analyzers, or — far better —
  recover symbols and target specific functions instead of analyzing everything.

## Prereqs (one-time, in WSL; REA/Ghidra already installed)
```bash
# raise Ghidra's import/analysis deadline and cap heap-hungry analyzers for big libs
export REA_GHIDRA_STARTUP_TIMEOUT_MS=2700000          # 45 min
export REA_GHIDRA_DISABLED_ANALYZERS="Decompiler Switch Analysis,Aggressive Instruction Finder"
# (put these in ~/.rea-env.sh so every `bash -lc "rea ..."` session has them)
```
Optional symbol recovery (the step that makes IL2CPP productive):
- **Il2CppDumper** (or Il2CppInspector) reconstructs C# class/method names + offsets from
  `global-metadata.dat` + `libil2cpp.so`, producing a symbol/offset map and a `script.json`
  Ghidra can apply. Install from its GitHub release (dotnet runtime). REA does not bundle it.

## The lane, step by step
1. **Extract the native pieces from your APK/APKM** (locally; don't send them to me):
   - `lib/arm64-v8a/libil2cpp.so`  (the code)
   - `assets/bin/Data/Managed/Metadata/global-metadata.dat`  (the names)
   - also note `lib/arm64-v8a/libunity.so` (engine, usually not your logic).
   From a container, pull them out of the base APK (or the arm64 split) with `unzip`.
2. **Recover symbols (optional but high-value):**
   ```bash
   Il2CppDumper libil2cpp.so global-metadata.dat out/     # -> dump.cs, script.json, symbols
   ```
   Without this you still get code, but function names are `FUN_<addr>` — slow going.
3. **Open in REA, targeted:**
   ```bash
   bash -lc "rea open-binary /abs/path/libil2cpp.so --provider ghidra"   # arm64 auto-detected
   ```
   Then work by **specific function**, not whole-binary:
   - `rea search-strings <pattern>` to find an interesting literal, then `rea xrefs <addr>`;
   - `rea procedure-pseudo-code <name-or-0xADDR>` to decompile ONE function (use the offsets
     Il2CppDumper gave you — e.g. a method you reached from a Java `native` declaration);
   - `rea analyze-function <name-or-addr>` for a dossier (calls, refs, strings).
   Avoid `binary-overview`/`list-procedures` on the full lib unless you raised the timeout —
   those force whole-binary analysis.
4. **Bridge Java ↔ native:** in the Java layer (JADX), find `native` method declarations and
   `System.loadLibrary("il2cpp")`; those JNI entry points map into `libil2cpp.so`. That tells
   you which native functions are reachable from the app's exposed surface.
5. **Dynamic (optional, on-device):** you already have `frida-server`. Hook IL2CPP functions
   at runtime (`il2cpp` bridge in Frida) to see real arguments/returns — confirms static guesses.

## Privacy in this lane
IL2CPP symbol names are your real C# class/method names. Before pasting any native
decompilation or symbol list to me, run it through the redactor **with your codenames as
terms** so they become `TERM_N`:
```bash
type native_snippet.txt | python redact.py --app-package <pkg> \
    --terms "yourgame,yourcompany,yourcompanylabs,<your real codenames>" --map redaction_map.json
```
and expand my placeholder-space advice back with `unredact.py` before acting on it.

## Honest expectations
On a 4 GB-GPU / 16 GB-RAM laptop, Ghidra on a large `libil2cpp.so` is CPU-heavy and slow;
whole-binary analysis may take a long time or need the raised timeout. The practical path is
**symbol-recover → target individual functions**, not "decompile the whole lib." The native
lane answers "how does the game logic / protocol / anti-cheat work," not "what's exposed to
other apps" (that's the Java timeline you already have).
