#!/usr/bin/env python3
"""
Interactive hybrid RE shell — a chat/CLI over one APK.

You drive it with typed prompts and slash-commands. It runs REA locally (ground
truth) and talks to the local model (reads the REAL decompiled code on-device).
Two commands make Claude part of the loop WITHOUT leaking your app:
  /claude            -> prints a REDACTED block to paste into your Claude chat
  /plan <directive>  -> ingests Claude's reply; de-aliases Cls_N -> real names
                        locally and executes (e.g. /plan decompile Cls_14 onReceive)

Nothing un-redacted ever leaves the machine. The real alias map stays local.

Run (your own PowerShell):
  cd C:\\Users\\kanap\\Desktop\\claudeWork\\hermes-rea
  python re_chat.py --apk C:\\...\\apks\\myapp\\app-release.apk --model qwen3.5:4b
Reads commands from stdin, so it also works piped (for scripting/testing).
"""
import argparse, json, os, sys, urllib.request
from apk_timeline import rea, win_to_wsl, resolve_base_apk, parse_manifest
from redact import Redactor

OLLAMA = "http://localhost:11434/v1"


def chat_local(messages, model, timeout=600):
    body = json.dumps({"model": model, "stream": False, "messages": messages,
                       "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(OLLAMA + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"].strip()


HELP = """commands:
  /open <path>              open an APK/APKM target (also --apk at launch)
  /manifest                 package, exported components, permissions, flags
  /classes <substr>         search class names (real)
  /methods <class|Cls_N>    list a class's methods
  /decompile <class|Cls_N> <method> [idx]   decompile; starts a chat about it
  <free text> or /ask <q>   ask the LOCAL model about the current method (conversational)
  /claude [question]        print a REDACTED block to paste into your Claude chat
  /plan <directive>         run Claude's directive locally (de-aliases Cls_N), e.g.
                            /plan decompile Cls_14 onReceive   |   /plan note <text>
  /note <text>              add a finding to the local log
  /save [path]              write transcript + notes + redaction map (local)
  /model <name>             switch local model
  /help   /quit
"""


class Shell:
    def __init__(self, model):
        self.model = model
        self.apk = None            # wsl path
        self.pkg = None
        self.redactor = None
        self.exported = []
        self.cur = None            # {"class","method","body"}
        self.llm = []              # conversation about current method
        self.notes = []
        self.transcript = []

    def deid(self, token):
        """Map a Cls_N / APPPKG1 alias back to the real name (local)."""
        if not self.redactor:
            return token
        rev = self.redactor.reverse()
        out = token
        for alias, original in rev.items():
            out = out.replace(alias, original)
        return out

    def open(self, path):
        work = os.path.join(os.path.dirname(os.path.abspath(path)) or ".", "_re_extract")
        apk_win, note = resolve_base_apk(path, work)
        if note:
            print("  " + note)
        self.apk = win_to_wsl(apk_win)
        res = rea(["decode-android-resources", self.apk, "--no-strings"])["normalized_result"]
        self.pkg = res["metadata"]["package_name"]
        _, self.exported, self.flags = parse_manifest(res["manifest"], self.pkg)
        inv = rea(["search-android-classes", self.apk, self.pkg])["normalized_result"]
        classes = [c for c in (inv.get("matches") or []) if c.startswith(self.pkg)]
        names = set()
        for fq in classes + [c["class"] for c in self.exported]:
            for part in fq.rsplit(".", 1)[-1].split("$"):
                if len(part) >= 3:
                    names.add(part)
        self.redactor = Redactor(app_package=self.pkg, app_classes=names)
        self.classes = classes
        print(f"  opened {self.pkg}  v{res['metadata']['version_name']}  "
              f"classes={len(classes)} exported={len(self.exported)}")

    def manifest(self):
        print(f"  package: {self.pkg}  flags: {self.flags}")
        print(f"  exported ({len(self.exported)}):")
        for c in self.exported:
            print(f"    [{c['kind']}] {c['class']}")

    def methods(self, cls):
        cls = self.deid(cls)
        r = rea(["inspect-android-class", self.apk, cls])["normalized_result"]
        for m in (r.get("methods") or []):
            print(f"    {m.get('name')}{m.get('dex_descriptor','')}")

    def decompile(self, cls, method, idx=None):
        cls = self.deid(cls)
        args = ["inspect-android-method", self.apk, cls, method]
        if idx is not None:
            args += ["--overload-index", str(idx)]
        ev = rea(args)
        body = ((ev.get("normalized_result") or {}).get("source") or {}).get("text")
        if not body:
            print("  (no body — wrong name/overload?)")
            return
        self.cur = {"class": cls, "method": method, "body": body, "evidence_id": ev.get("evidence_id")}
        self.llm = [{"role": "system", "content": "You are a security reviewer reading one decompiled "
                     "Android method. Answer only from the code; say so if something is not visible."},
                    {"role": "user", "content": f"Decompiled {cls}.{method}:\n```java\n{body}\n```\n"
                     "Give a one-line summary and note any untrusted-input handling."}]
        print(f"  decompiled {cls}.{method}  ({len(body)} chars, evidence {self.cur['evidence_id']})")
        self.ask("")   # initial summary

    def ask(self, q):
        if not self.cur:
            print("  open/decompile a method first"); return
        if q:
            self.llm.append({"role": "user", "content": q})
        ans = chat_local(self.llm, self.model)
        self.llm.append({"role": "assistant", "content": ans})
        self.transcript.append({"q": q, "a": ans, "method": f"{self.cur['class']}.{self.cur['method']}"})
        print("\nlocal> " + ans + "\n")

    def claude_block(self, question):
        R = self.redactor.redact if self.redactor else (lambda s: s)
        print("\n===== COPY TO CLAUDE (redacted) =====")
        print(f"Target: {R(self.pkg)}  exported components: {len(self.exported)}")
        if self.cur:
            print(f"\nMethod: {R(self.cur['class'])}.{self.cur['method']}")
            print("```java\n" + R(self.cur["body"])[:1600] + "\n```")
            if self.transcript:
                print("Local-model note: " + R(self.transcript[-1]["a"]))
        print("\nQuestion: " + (question or "what should I look at / decompile next?"))
        print("===== END =====\n(real names are in the local redaction map; reply using the Cls_N placeholders)\n")

    def plan(self, directive):
        parts = directive.split()
        if not parts:
            return
        verb = parts[0]
        if verb == "decompile" and len(parts) >= 3:
            self.decompile(parts[1], parts[2], parts[3] if len(parts) > 3 else None)
        elif verb == "methods" and len(parts) >= 2:
            self.methods(parts[1])
        elif verb == "note":
            self.note(directive[5:].strip())
        elif verb == "ask":
            self.ask(self.deid(directive[4:].strip()))
        else:
            print("  (recorded as guidance) " + directive)
            if self.cur:
                self.ask("Claude suggests: " + self.deid(directive))

    def note(self, text):
        self.notes.append(text)
        print("  noted.")

    def save(self, path):
        path = path or "re_session.json"
        json.dump({"package": self.pkg, "notes": self.notes, "transcript": self.transcript},
                  open(path, "w", encoding="utf-8"), indent=2)
        if self.redactor:
            self.redactor.save_map(os.path.join(os.path.dirname(os.path.abspath(path)) or ".",
                                                 "redaction_map.json"))
        print(f"  saved -> {path} (+ redaction_map.json)")

    def run(self, line):
        line = line.strip()
        if not line:
            return True
        if not line.startswith("/"):
            self.ask(line); return True
        cmd, _, rest = line[1:].partition(" ")
        rest = rest.strip()
        try:
            if cmd == "quit": return False
            elif cmd == "help": print(HELP)
            elif cmd == "open": self.open(rest)
            elif cmd == "manifest": self.manifest()
            elif cmd == "classes":
                for c in [x for x in self.classes if rest in x][:40]: print("   ", c)
            elif cmd == "methods": self.methods(rest)
            elif cmd == "decompile":
                a = rest.split(); self.decompile(a[0], a[1], a[2] if len(a) > 2 else None)
            elif cmd == "ask": self.ask(rest)
            elif cmd == "claude": self.claude_block(rest)
            elif cmd == "plan": self.plan(rest)
            elif cmd == "note": self.note(rest)
            elif cmd == "save": self.save(rest)
            elif cmd == "model": self.model = rest; print(f"  model = {self.model}")
            else: print("  unknown command; /help")
        except Exception as e:
            print(f"  error: {e}")
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk")
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--script", help="run commands from a file (one per line) then exit")
    a = ap.parse_args()
    sh = Shell(a.model)
    print("hybrid RE shell — /help for commands, /quit to exit")
    if a.apk:
        sh.run(f"/open {a.apk}")
    if a.script:
        for raw in open(a.script, encoding="utf-8"):
            raw = raw.strip()
            if not raw:
                continue
            print("re> " + raw)
            if sh.run(raw) is False:
                break
        return
    while True:
        try:
            line = input("re> ")
        except EOFError:
            break
        if sh.run(line) is False:
            break


if __name__ == "__main__":
    main()
