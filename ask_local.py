#!/usr/bin/env python3
"""
Automatic redaction bridge between Claude and the local model.

Flow (all local):
  1. You paste Claude's instruction (placeholder-space: Cls_7, TERM_2, ...).
  2. This UN-redacts it to your real names via redaction_map.json.
  3. Sends the real-name instruction to the local model (Ollama), which works on
     the real decompiled code.
  4. Prints the model's answer. With --reredact it also prints a redacted copy
     (stable aliases from the same map) that is safe to paste back to Claude.

Nothing crosses to Claude here; this only translates between placeholder-space
(what Claude sees) and real names (what the local model needs), on your machine.

Usage:
  type claude_msg.txt | python ask_local.py --map redaction_map.json --model qwen3.5-4b-uncensored --reredact
  # append project context the model should always have:
  ... --context LOCAL-LLM-BRIEFING.md
"""
import argparse, json, sys, urllib.request
from unredact import load_reverse, expand
from redact import Redactor


def ollama(prompt, model, base_url, context="", timeout=900):
    sys_msg = ("You are a reverse-engineering assistant working on the user's OWN app, locally. "
               "You see real decompiled code and symbols. Report only what the code shows.")
    if context:
        sys_msg += "\n\n# Project briefing\n" + context
    body = json.dumps({"model": model, "stream": False,
                       "messages": [{"role": "system", "content": sys_msg},
                                    {"role": "user", "content": prompt}],
                       "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"].strip()


def reredactor_from_map(map_path):
    """Rebuild a Redactor preseeded with the existing map, so aliases stay stable."""
    m = json.load(open(map_path, encoding="utf-8"))
    fwd = m.get("forward") or {}
    pkg = next(iter(fwd.get("pkg", {})), "")
    classes = set(fwd.get("class", {}).keys())
    terms = list(fwd.get("term", {}).keys())
    r = Redactor(app_package=pkg, app_classes=classes, terms=terms)
    for k in ("pkg", "class", "string", "term"):           # preseed so existing aliases are reused
        r.map.setdefault(k, {}).update(fwd.get(k, {}))
    return r, map_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default="redaction_map.json")
    ap.add_argument("--model", default="qwen3.5-4b-uncensored")
    ap.add_argument("--ollama", default="http://localhost:11434/v1")
    ap.add_argument("--context", help="optional briefing file prepended to the system prompt (unredacted too)")
    ap.add_argument("--reredact", action="store_true", help="also print a Claude-safe redacted copy of the answer")
    a = ap.parse_args()

    rev = load_reverse(a.map)
    claude_text = sys.stdin.read()
    real_instruction = expand(claude_text, rev)            # placeholder -> real, locally
    context = ""
    if a.context:
        context = expand(open(a.context, encoding="utf-8").read(), rev)

    print("=== sent to local model (real names, local only) ===", file=sys.stderr)
    answer = ollama(real_instruction, a.model, a.ollama, context=context)
    print("\n================ LOCAL MODEL ANSWER (real names) ================\n")
    print(answer)

    if a.reredact:
        r, mp = reredactor_from_map(a.map)
        safe = r.redact(answer)
        r.save_map(mp)                                     # persist any new aliases, keep map stable
        print("\n================ REDACTED COPY (safe to paste to Claude) ================\n")
        print(safe)


if __name__ == "__main__":
    main()
