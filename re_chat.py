#!/usr/bin/env python3
"""
Interactive hybrid RE shell — a chat/CLI over one APK.

You drive it with typed prompts and slash-commands. It runs REA locally (ground
truth) and talks to the local model (reads the REAL decompiled code on-device).
Two commands make Claude part of the loop WITHOUT leaking your app:
  /claude            -> prints a REDACTED block to paste into your Claude chat
  /plan <directive>  -> ingests Claude's reply; de-aliases Cls_N -> real names
                        locally and executes (e.g. /plan decompile Cls_14 onReceive)
Bulk teardown:
  /decompileall      -> manifest + every class/method to .java files + all .so
                        (+ Il2CppDumper on libil2cpp.so) into a local folder,
                        resumable; every action auto-logged to re-session-log.md

Nothing un-redacted ever leaves the machine. The real alias map stays local.

Run (your own PowerShell):
  cd C:\\Users\\kanap\\Desktop\\claudeWork\\hermes-rea
  python re_chat.py --apk C:\\...\\apks\\myapp\\app-release.apk --model qwen3.5:4b
Reads commands from stdin, so it also works piped (for scripting/testing).
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, time, urllib.request, zipfile
from apk_timeline import rea, win_to_wsl, resolve_base_apk, parse_manifest, CONTAINER_EXT
from redact import Redactor

OLLAMA = "http://localhost:11434/v1"
IL2CPP_METADATA_ENTRY = "assets/bin/Data/Managed/Metadata/global-metadata.dat"


def longpath(p):
    """Windows-safe absolute path (\\\\?\\ prefix avoids the 260-char limit on deep package trees)."""
    p = os.path.abspath(p)
    return "\\\\?\\" + p if os.name == "nt" and not p.startswith("\\\\?\\") else p


_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_$@.-]")


def safe_name(s):
    """Filesystem-safe component (<init> -> _init_, keeps . $ _ @ -)."""
    return _SANITIZE_RE.sub("_", s) or "_"


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(longpath(path), "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def find_il2cppdumper():
    cands = [os.environ.get("RE_CHAT_IL2CPPDUMPER", ""),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "il2cppdumper", "Il2CppDumper.exe")]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None


def extract_native(apk_parts, outdir):
    """Pull lib/<abi>/*.so (+ IL2CPP global-metadata.dat) out of every APK part
    (base + splits). Returns (so_records, metadata_records) with path/sha256/bytes."""
    sos, metas, seen = [], [], set()
    for part in apk_parts:
        try:
            z = zipfile.ZipFile(longpath(part))
        except Exception:
            continue
        for n in z.namelist():
            ln = n.lower()
            is_so = ln.startswith("lib/") and ln.endswith(".so")
            is_meta = n == IL2CPP_METADATA_ENTRY
            if not (is_so or is_meta):
                continue
            key = (n, os.path.basename(part))
            if key in seen:
                continue
            seen.add(key)
            dest = os.path.join(outdir, "native", safe_name(os.path.basename(part)),
                                *[safe_name(c) for c in n.split("/")])
            os.makedirs(os.path.dirname(longpath(dest)), exist_ok=True)
            with z.open(n) as src, open(longpath(dest), "wb") as dst:
                shutil.copyfileobj(src, dst)
            rec = {"part": os.path.basename(part), "entry": n, "path": dest,
                   "sha256": sha256_file(dest), "bytes": os.path.getsize(longpath(dest))}
            (sos if is_so else metas).append(rec)
    return sos, metas


def run_il2cppdumper(exe, so_path, meta_path, outdir, timeout=3600):
    """Run Il2CppDumper.exe <so> <metadata> <outdir>; capture its log. Returns a record."""
    os.makedirs(longpath(outdir), exist_ok=True)
    try:
        p = subprocess.run([exe, so_path, meta_path, outdir], capture_output=True, text=True,
                           timeout=timeout, cwd=os.path.dirname(exe))
        open(longpath(os.path.join(outdir, "il2cppdumper.log")), "w", encoding="utf-8",
             errors="replace").write((p.stdout or "") + "\n--- stderr ---\n" + (p.stderr or ""))
        return {"returncode": p.returncode, "exe": exe,
                "outputs": sorted(os.path.basename(f) for f in os.listdir(longpath(outdir)))}
    except Exception as e:
        return {"returncode": -1, "error": str(e)}


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
  /decompileall [dir] [app|all] [max]       FULL teardown into a local folder:
        manifest + attack-surface JSON + EVERY class -> EVERY method overload
        -> one .java file each (with REA evidence ids in index.json), plus
        native/ : all .so extracted from base AND container splits, hashed;
        libil2cpp.so + global-metadata.dat -> Il2CppDumper runs automatically
        (dump.cs/script.json = full C# symbol map). Resumable: re-running
        skips files that already exist; Ctrl+C is safe (index is saved).
        scope 'app' = your package's classes only (default); 'all' = every
        class incl. third-party libs (slow). [max] caps the class count.
  <free text> or /ask <q>   ask the LOCAL model about the current method (conversational)
  /claude [question]        print a REDACTED block to paste into your Claude chat
  /plan <directive>         run Claude's directive locally (de-aliases Cls_N), e.g.
                            /plan decompile Cls_14 onReceive   |   /plan note <text>
  /note <text>              add a finding to the local log
  /save [path]              write transcript + notes + redaction map (local)
  /model <name>             switch local model
  /help   /quit
every action is auto-recorded in re-session-log.md (REAL names, local-only, gitignored)
"""


class Shell:
    def __init__(self, model):
        self.model = model
        self.apk = None            # wsl path
        self.apk_win = None        # windows path of the (extracted) base apk
        self.apk_src = None        # original path as given (may be a container)
        self.work_dir = None       # _re_extract dir next to the target
        self.pkg = None
        self.redactor = None
        self.exported = []
        self.flags = {}
        self.perms = []
        self.classes = []
        self.cur = None            # {"class","method","body"}
        self.llm = []              # conversation about current method
        self.notes = []
        self.transcript = []
        self.actions = []          # auto session-summary entries
        self.summary_path = "re-session-log.md"

    def log(self, action, detail="", write=True):
        """Auto session summary: every action is recorded and re-session-log.md is
        rewritten. Contains REAL names -> local-only file (gitignored)."""
        self.actions.append((time.strftime("%Y-%m-%d %H:%M:%S"), action, detail))
        if write:
            try:
                lines = [f"# RE session log — auto-updated ({time.strftime('%Y-%m-%d %H:%M')})",
                         f"target: {self.pkg or '-'}   model: {self.model}", ""]
                lines += [f"- {t}  **{a}**  {d}".rstrip() for t, a, d in self.actions]
                open(self.summary_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            except Exception:
                pass

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
        self.apk_src, self.work_dir, self.apk_win = path, work, apk_win
        self.apk = win_to_wsl(apk_win)
        res = rea(["decode-android-resources", self.apk, "--no-strings"])["normalized_result"]
        self.pkg = res["metadata"]["package_name"]
        self.perms, self.exported, self.flags = parse_manifest(res["manifest"], self.pkg)
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
        self.log("open", f"{os.path.basename(path)} -> {self.pkg} "
                 f"v{res['metadata'].get('version_name')} classes={len(classes)} exported={len(self.exported)}")

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
        self.log("decompile", f"{cls}.{method} ev={self.cur['evidence_id']}")
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
        self.log("note", text)
        print("  noted.")

    def save(self, path):
        path = path or "re_session.json"
        json.dump({"package": self.pkg, "notes": self.notes, "transcript": self.transcript},
                  open(path, "w", encoding="utf-8"), indent=2)
        if self.redactor:
            self.redactor.save_map(os.path.join(os.path.dirname(os.path.abspath(path)) or ".",
                                                 "redaction_map.json"))
        self.log("save", path)
        print(f"  saved -> {path} (+ redaction_map.json)")

    # ------------------------------------------------------------- bulk teardown
    def decompileall(self, outdir=None, scope="app", max_classes=None):
        """Recursive teardown of the open target into a local folder:
        manifest + attack surface, every class -> every method overload -> one
        .java file (REA evidence ids in index.json), all .so from base AND
        container splits, and an automatic Il2CppDumper run when libil2cpp.so
        + global-metadata.dat are present. Resumable; Ctrl+C-safe."""
        if not self.apk:
            print("  open an APK first (/open <path>)")
            return
        outdir = outdir or os.path.join(os.path.dirname(self.apk_win) or ".", "decompiled")
        os.makedirs(longpath(outdir), exist_ok=True)
        self.log("decompileall", f"start scope={scope} out={outdir}")
        index = {"package": self.pkg, "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "scope": scope, "outdir": outdir, "classes": {}, "native": {}, "errors": []}

        def save_index():
            json.dump(index, open(longpath(os.path.join(outdir, "index.json")), "w",
                                  encoding="utf-8"), indent=2)

        # -- 1) manifest / attack surface -------------------------------------
        mdir = os.path.join(outdir, "manifest")
        os.makedirs(longpath(mdir), exist_ok=True)
        res = rea(["decode-android-resources", self.apk, "--no-strings"])["normalized_result"]
        open(longpath(os.path.join(mdir, "AndroidManifest.decoded.xml")), "w",
             encoding="utf-8").write(res.get("manifest") or "")
        json.dump(res.get("metadata"), open(longpath(os.path.join(mdir, "metadata.json")), "w",
                                            encoding="utf-8"), indent=2)
        perms, exported, flags = parse_manifest(res["manifest"], self.pkg)
        json.dump({"permissions": perms, "exported": exported, "flags": flags},
                  open(longpath(os.path.join(mdir, "attack-surface.json")), "w",
                       encoding="utf-8"), indent=2)
        index["manifest"] = {"permissions": len(perms), "exported_components": len(exported),
                             "flags": flags}
        print(f"[manifest] perms={len(perms)} exported={len(exported)} flags={flags}")
        save_index()

        # -- 2) every class -> every method overload -> one file ---------------
        inv = rea(["search-android-classes", self.apk, self.pkg if scope == "app" else ""])["normalized_result"]
        classes = sorted(inv.get("matches") or [])
        if scope == "app":
            classes = [c for c in classes if c.startswith(self.pkg)]
        if max_classes:
            classes = classes[:max_classes]
        print(f"[java] tearing down {len(classes)} class(es) (scope={scope}; Ctrl+C stops, "
              f"re-run resumes where it left off)")
        java_root = os.path.join(outdir, "java")
        t0, done, skipped, errs, nobody = time.time(), 0, 0, 0, 0
        try:
            for ci, cls in enumerate(classes, 1):
                cdir = os.path.join(java_root, *[safe_name(p) for p in cls.split(".")])
                os.makedirs(longpath(cdir), exist_ok=True)
                entry = {"methods": {}, "errors": []}
                index["classes"][cls] = entry
                try:
                    ms = (rea(["inspect-android-class", self.apk, cls])["normalized_result"]
                          .get("methods") or [])
                except Exception as e:
                    entry["errors"].append(str(e)[:200])
                    index["errors"].append(f"{cls}: {e}")
                    continue
                groups = {}
                for m in ms:
                    groups.setdefault(m.get("name") or "_unnamed", []).append(m)
                for name, overs in groups.items():
                    for idx, m in enumerate(overs):
                        fpath = os.path.join(cdir, f"{safe_name(name)}__{idx}.java")
                        rec = {"descriptor": m.get("dex_descriptor", ""),
                               "file": os.path.relpath(fpath, outdir).replace(os.sep, "/")}
                        entry["methods"][f"{name}#{idx}"] = rec
                        if os.path.exists(longpath(fpath)):
                            rec["status"] = "resumed-skip"
                            skipped += 1
                            continue
                        try:
                            args = ["inspect-android-method", self.apk, cls, name]
                            if len(overs) > 1:
                                args += ["--overload-index", str(idx)]
                            ev = rea(args)
                            body = ((ev.get("normalized_result") or {}).get("source") or {}).get("text")
                            if body:
                                tmp = fpath + ".part"
                                open(longpath(tmp), "w", encoding="utf-8").write(body)
                                os.replace(longpath(tmp), longpath(fpath))
                                rec.update(status="ok", evidence_id=ev.get("evidence_id"),
                                           chars=len(body))
                                done += 1
                            else:
                                rec["status"] = "no-body (abstract/native?)"
                                nobody += 1
                        except Exception as e:
                            rec.update(status="error", error=str(e)[:200])
                            errs += 1
                if ci % 5 == 0 or ci == len(classes):
                    el = time.time() - t0
                    eta = (el / ci) * (len(classes) - ci) if ci else 0
                    print(f"[java] {ci}/{len(classes)}  {cls}  ok={done} skip={skipped} "
                          f"nobody={nobody} err={errs}  eta {int(eta // 60)}m{int(eta % 60):02d}s",
                          flush=True)
                    save_index()
                self.log("class", cls, write=(ci % 10 == 0 or ci == len(classes)))
        except KeyboardInterrupt:
            save_index()
            print("\n[interrupt] partial index saved — re-run /decompileall to resume "
                  "(already-written method files are skipped)")
            self.log("decompileall", f"INTERRUPTED at {len(index['classes'])}/{len(classes)} classes")
            return
        save_index()

        # -- 3) native: .so + metadata from every APK part (base + splits) -----
        parts = [self.apk_win]
        if self.apk_src and self.apk_src.lower().endswith(CONTAINER_EXT):
            try:
                with zipfile.ZipFile(longpath(self.apk_src)) as z:
                    for n in z.namelist():
                        if not n.lower().endswith(".apk"):
                            continue
                        dst = os.path.join(self.work_dir, safe_name(n))
                        if not os.path.exists(longpath(dst)):
                            with z.open(n) as src, open(longpath(dst), "wb") as out:
                                shutil.copyfileobj(src, out)
                        if os.path.abspath(dst) != os.path.abspath(self.apk_win):
                            parts.append(dst)
            except Exception as e:
                print(f"[native] container split extraction failed: {e}")
        sos, metas = extract_native(parts, outdir)
        index["native"]["so_files"] = sos
        index["native"]["il2cpp_metadata"] = metas
        print(f"[native] {len(sos)} .so extracted, {len(metas)} global-metadata.dat "
              f"(base + splits: {[os.path.basename(p) for p in parts]})")
        il2 = sorted((s for s in sos if s["entry"].endswith("libil2cpp.so")),
                     key=lambda s: 0 if "arm64" in s["entry"] else 1)
        if il2 and metas:
            exe = find_il2cppdumper()
            if exe:
                print(f"[il2cpp] running Il2CppDumper on {il2[0]['entry']} + metadata ...")
                dump = run_il2cppdumper(exe, il2[0]["path"], metas[0]["path"],
                                        os.path.join(outdir, "native", "il2cpp"))
                index["native"]["il2cpp_dump"] = dump
                print("[il2cpp] " + ("dump.cs / script.json written (full C# symbol map)"
                      if dump.get("returncode") == 0 else
                      f"FAILED rc={dump.get('returncode')} — see native/il2cpp/il2cppdumper.log"))
            else:
                index["native"]["il2cpp_dump"] = {"skipped": "Il2CppDumper.exe not found "
                                      "(put it in ..\\il2cppdumper\\ or set RE_CHAT_IL2CPPDUMPER)"}
        elif il2:
            index["native"]["il2cpp_dump"] = {"skipped":
                   "libil2cpp.so present but no global-metadata.dat in base/splits"}
        save_index()
        self.log("decompileall", f"DONE classes={len(index['classes'])} methods_ok={done} "
                 f"resumed={skipped} no_body={nobody} errors={errs} so={len(sos)} -> {outdir}")
        print(f"\n[done] {len(index['classes'])} classes | {done} methods decompiled "
              f"({skipped} resumed, {nobody} no-body, {errs} errors) | {len(sos)} .so\n"
              f"       out: {outdir}  (manifest/ java/ native/ + index.json with REA evidence ids)")

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
                a = rest.split()
                if len(a) < 2:
                    print("  usage: /decompile <class|Cls_N> <method> [overload-index]")
                else:
                    self.decompile(a[0], a[1], a[2] if len(a) > 2 else None)
            elif cmd == "decompileall":
                outdir = scope = maxi = None
                for tok in rest.split():
                    if tok in ("app", "all") and scope is None:
                        scope = tok
                    elif tok.isdigit() and maxi is None:
                        maxi = int(tok)
                    elif outdir is None:
                        outdir = tok
                self.decompileall(outdir, scope or "app", maxi)
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
