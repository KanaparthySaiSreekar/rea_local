# Local RE pipeline — setup, hybrid usage, APK playbook, multi-agent

Everything here keeps your app on the machine: REA runs in WSL, the model runs in
Ollama. Claude (me) only ever sees what you choose to show; in the hybrid's
private mode I see abstract questions, never your app's bytes.

---

## 1. Fix Hermes in your REAL profile (you must run this yourself)

I can't install Hermes into your real profile from the Claude app — this session's
`%LOCALAPPDATA%` writes are redirected into the app's sandbox, so the copy I
installed is stuck there. Do this in a **normal PowerShell window you open
yourself** (Start → "PowerShell", not inside Claude):

```powershell
iex (irm https://hermes-agent.nousresearch.com/install.ps1)
```

The first-run wizard works in a real console (it only failed for me because my
shell has no console). Then configure it for the local model:

```powershell
$h = "$env:LOCALAPPDATA\hermes\bin\hermes.exe"
& $h config set model.provider ollama
& $h config set model.base_url http://localhost:11434/v1
& $h config set model.default qwen3.5:4b
& $h config set model.context_length 65536
& $h config set model.ollama_num_ctx 65536
& $h config set model.stream false
& $h config set tools.tool_search.enabled off
```

Register REA — and when it asks **"Enable all 207 tools? [Y/n/select]"**, type
`select` and enable ONLY these ~6 (a 4B model drowns in 207 and can't use the
tool-search layer; a short direct list is what made it work in testing):

```powershell
& $h mcp add rea --command wsl.exe --connect-timeout 180 --args `
  -d Ubuntu-22.04 --exec bash -lc "REA_MCP_INPUT_SCHEMA_PROFILE=compact exec rea mcp"
# at the prompt: select -> decode_android_resources, inspect_android_package,
# search_android_classes, inspect_android_class, inspect_android_method, close_binary
```

Then run it interactively (MCP tools load in a real TTY session):

```powershell
hermes chat
```

Why the small toolset: tests showed `qwen3.5:4b` reliably calls a tool handed to
it directly, but hallucinates when it must search a 207-tool catalog. Keep the
list short. If you later use a bigger model (`qwen3.5:9b`), you can enable more.

---

## 2. The hybrid pipeline (no Hermes needed) — `hybrid_re.py`

The hybrid splits the work by what each part is good at:

| Part | Role | Where |
|---|---|---|
| REA | deterministic decompilation / manifest decode (ground truth, evidence IDs) | WSL, local |
| local model (qwen3.5:4b) | triage/summarize each method — the bulk volume work | Ollama, local |
| the plan (script, or Claude) | which components/methods to look at, what to look for | — |

Run it from a normal PowerShell:

```powershell
cd C:\Users\kanap\Desktop\claudeWork\hermes-rea
python hybrid_re.py --apk /home/<you>/path/your-app.apk --max-methods 8 --out report.md
```

(The APK path is as WSL sees it.) It decodes the manifest, picks the Application
class plus every exported component, decompiles each entry method with REA, has
the local model triage each, and writes a markdown report with REA evidence IDs
for provenance. Nothing leaves the machine.

The script is the "fixed-plan" hybrid. The "live" hybrid is this: you work with
me, I pick the REA calls and read the cheap evidence, and the local model (or the
script) does the bulk decompilation triage.

---

## 3. How I plan in the hybrid

RE is mostly navigation + a lot of reading. I'm good at the navigation; the local
model is fine at the reading. So in the hybrid I:

1. **Read the cheap, high-signal evidence first** — manifest (exported components,
   permissions, cleartext/backup flags, embedded keys), class/string inventories,
   xrefs. These are small and deterministic.
2. **Form the attack-surface map and hypotheses** — e.g. "this exported activity
   takes a `content://` extra and passes it to a FileProvider → check for path
   traversal"; "this receiver is exported with no permission → check what it acts on".
3. **Pick the next REA call** — decompile exactly the method that tests a
   hypothesis, follow an xref, or expand a call path. One targeted call at a time.
4. **Delegate the bulk** — hand long decompiled bodies to the local model to
   summarize/flag, so the volume work stays local and cheap.
5. **Keep the investigation state** — what's confirmed, what's open, what to check
   next — and verify claims against REA evidence, never against model prose.

Privacy modes:
- **Full private:** the local model reads the code; I only ever get your
  abstracted questions ("is an exported receiver acting on untrusted intent data a
  risk here?"). Your bytes never reach me.
- **Assisted:** you show me specific decompiled snippets you want deeper reasoning
  on. Faster, but those snippets go to Anthropic. You choose per snippet.

---

## 4. APK RE playbook (your own app, academic)

The loop, in order:

1. **Decode manifest** (`decode_android_resources`). Note: `exported="true"`
   components, `permission` gaps, `usesCleartextTraffic`, `allowBackup` /
   `restoreAnyVersion`, `debuggable`, `networkSecurityConfig`, deep-link
   `intent-filter`s with `autoVerify`, embedded `meta-data` keys.
2. **Inventory** (`inspect_android_package`, `search_android_classes`) — class
   count, find your own package's classes vs. libraries.
3. **Map the attack surface** = the exported components + any IPC/deep-link entry.
   That's where untrusted input enters.
4. **Decompile entry methods** (`inspect_android_method`) of each exported
   component: `onCreate`/`onStartCommand`/`onReceive`/`query`, and follow what they
   do with the incoming Intent/Uri/extras.
5. **Trace** suspicious data flow (`xrefs`, `inspect_android_class`, call paths).
6. **Check the usual Android bug classes:** exported-component hijack / intent
   redirection, `content://` path traversal through FileProviders, insecure
   deep-link handling, WebView `addJavascriptInterface` / `loadUrl` with untrusted
   input, SQL built from Intent extras, world-readable/backup data exposure,
   weak/hardcoded crypto keys, pending-intent mutability, exported receivers
   acting on broadcasts.
7. **Triage with the local model**, confirm against REA evidence, write findings.

Discipline (your "make no mistakes" rule): REA tags everything "observed/derived"
and warns static ≠ runtime. Treat the local model's summary as a lead, confirm the
actual decompiled code before calling anything a finding. Only your own app.

---

## 5. Multi-agent orchestration, locally — can you?

Short answer: **sequentially yes, concurrently no**, on this 4 GB-VRAM / 16 GB-RAM
laptop.

- **Concurrent multi-model** (planner + worker + critic all resident at once):
  not feasible. One 4B at 64k context already leans on system RAM; a second
  resident model won't fit in 4 GB VRAM and 16 GB RAM. Even if loaded, the single
  GPU serializes them, so there's no real parallelism.
- **Sequential multi-agent** (one model, different role prompts, one at a time —
  or two small models swapped by Ollama): works fine. This is the realistic local
  pattern: a "planner" turn decides the next step, a "worker" turn executes/
  summarizes, a "critic" turn checks — all `qwen3.5:4b`, run back to back.
- **Frameworks that drive local Ollama:** Hermes has `moa` (Mixture of Agents)
  and subagents built in; CrewAI, AutoGen, and LangGraph all point at Ollama's
  OpenAI-compatible endpoint. Any of them can host the roles.
- **The catch:** a 4B is a weak *planner* (it couldn't navigate tool-search over
  207 tools). Multi-agent with a weak planner compounds its mistakes. The planner
  role is exactly where a strong model earns its keep — which is why the hybrid
  (strong planner + local workers) beats all-local multi-agent on this hardware.
  If you want it fully local, use `qwen3.5:9b` for the planner role and keep the
  worker roles on `4b`, run sequentially.

### Demo result (measured on this machine, 2026-10-18)

`multiagent_demo.py` ran a sequential PLANNER → execute(REA) → WORKER crew on one
`qwen3.5:4b`, one role at a time:
- **Planner** emitted a valid structured tool call: `search_android_classes(query="Request")`.
- **Execute**: REA ran it locally and returned the result.
- **Worker** summarized it and recommended the next step (broaden the search).
- Total: **222 s (~3.7 min)**, one model resident throughout.

Verdict: the orchestration mechanics work locally and sequentially. The ceiling is
the planner's judgment — the 4B picked a weak search term ("Request" → zero hits).
That's the same weakness that broke tool-search: a 4B is a poor planner. So local
multi-agent is viable mechanically, but for good decisions put a strong planner on
top (the hybrid) or use `qwen3.5:9b` for the planner role and keep workers on 4b,
run sequentially. Run it yourself with: `python multiagent_demo.py`.
