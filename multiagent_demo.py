#!/usr/bin/env python3
"""
Sequential local multi-agent demo: PLANNER -> (execute REA) -> WORKER.
One model (qwen3.5:4b) plays two roles, one at a time — the only multi-agent
pattern that fits a 4 GB GPU. Proves local orchestration works and shows its
ceiling (a 4B planner is the weak link).
Stdlib only. Run from Windows PowerShell with Python 3.12.
"""
import json, subprocess, sys, time, urllib.request

WSL_DISTRO = "Ubuntu-22.04"
MODEL = "qwen3.5:4b"
OLLAMA = "http://localhost:11434/v1"
APK = sys.argv[1] if len(sys.argv) > 1 else "/home/sreeni/re-dryrun/antennapod/antennapod-3.12.3.apk"

TOOLS = [
    {"type": "function", "function": {"name": "search_android_classes",
     "description": "Search APK class names by case-sensitive substring (empty lists all).",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "query": {"type": "string"}},
                    "required": ["path", "query"]}}},
    {"type": "function", "function": {"name": "inspect_android_method",
     "description": "Decompile one method by class + method name.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "class_name": {"type": "string"},
                    "method_name": {"type": "string"}}, "required": ["path", "class_name", "method_name"]}}},
]


def _q(s):
    s = str(s)
    return "'" + s.replace("'", "'\\''") + "'" if (" " in s or '"' in s) else s


def rea(args, timeout=600):
    inner = "rea " + " ".join(_q(a) for a in args) + " --format json"
    cmd = ["wsl.exe", "-d", WSL_DISTRO, "--exec", "bash", "-lc", inner]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (json.loads(p.stdout) if p.returncode == 0 else {"error": p.stderr.strip()[:300]})


def chat(system, user, tools=None, timeout=600):
    msg = {"model": MODEL, "stream": False,
           "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
           "options": {"temperature": 0.2}}
    if tools:
        msg["tools"] = tools
    req = urllib.request.Request(OLLAMA.rstrip("/") + "/chat/completions",
                                 data=json.dumps(msg).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]


# --- PLANNER: pick the next REA action as a tool call ---
t0 = time.time()
print("[planner] deciding next REA action ...", flush=True)
plan_msg = chat(
    "You are the PLANNER agent in a reverse-engineering crew. Choose exactly ONE next REA "
    "tool call that best advances the goal. Call a tool; do not answer in prose.",
    f"Goal: for academic vuln review of our own app, find the most security-relevant class to examine. "
    f"APK path: {APK}. The manifest has 19 exported components and allows cleartext traffic. "
    f"Pick the next REA action.", tools=TOOLS)
tc = (plan_msg.get("tool_calls") or [None])[0]
print(f"[planner] -> {json.dumps(tc['function']) if tc else '(no tool_call) ' + plan_msg.get('content','')}", flush=True)

# --- EXECUTE the planner's chosen call via REA (the deterministic part) ---
rea_out = {"skipped": "planner emitted no tool call"}
if tc:
    fn = tc["function"]["name"]
    a = json.loads(tc["function"]["arguments"])
    if fn == "search_android_classes":
        print(f"[execute] rea search-android-classes {a.get('query')!r} ...", flush=True)
        r = rea(["search-android-classes", a["path"], a.get("query", "")])
        nr = r.get("normalized_result") or {}
        names = nr.get("classes") or nr.get("names") or nr.get("rows") or []
        rea_out = {"tool": fn, "match_count": len(names) if isinstance(names, list) else None,
                   "sample": (names[:12] if isinstance(names, list) else str(names)[:400])}
    elif fn == "inspect_android_method":
        print(f"[execute] rea inspect-android-method {a.get('class_name')}.{a.get('method_name')} ...", flush=True)
        r = rea(["inspect-android-method", a["path"], a["class_name"], a["method_name"]])
        nr = r.get("normalized_result") or {}
        rea_out = {"tool": fn, "body": ((nr.get("source") or {}).get("text") or "")[:1200]}

# --- WORKER: summarize the REA result and recommend the next step ---
print("[worker] summarizing REA result ...", flush=True)
work_msg = chat(
    "You are the WORKER agent. Read the REA result and report concisely (2-3 sentences): what it shows "
    "and the single best next step for vuln review. Only use the data given.",
    f"Planner chose: {json.dumps(tc['function']) if tc else 'nothing'}\nREA result:\n{json.dumps(rea_out)[:2500]}")
print("\n================ WORKER OUTPUT ================")
print(work_msg.get("content", "").strip())
print(f"\n[done] sequential planner->execute->worker in {round(time.time()-t0,1)}s "
      f"(one model resident at a time)", flush=True)
