import re
import shlex
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory

REPO = Path.home() / "Downloads" / "sd_landing_v3_polished"
app = Flask(__name__, static_folder="static")

def run(cmd, cwd=REPO):
    p = subprocess.run(cmd, cwd=str(cwd), shell=True, capture_output=True, text=True)
    return {"cmd": cmd, "code": p.returncode, "out": (p.stdout or "").strip(), "err": (p.stderr or "").strip()}

def bump_cosmos_cache_buster(html: str) -> str:
    import time
    ts = str(int(time.time()))
    pat = re.compile(
        r'(<img[^>]*\bid=["\']ap_Cosmos["\'][^>]*\bsrc=["\']assets/pup_slides/cosmos_01\.jpg)(?:\?v=\d+)?(["\'])',
        re.I
    )
    html2, n = pat.subn(r'\1?v=' + ts + r'\2', html, count=1)
    if n == 0:
        raise RuntimeError('Could not find <img id="ap_Cosmos" ...> in index.html')
    return html2

@app.get("/")
def home():
    return send_from_directory("static", "index.html")

@app.get("/favicon.ico")
def favicon():
    # stop the 404 spam; blank response is fine
    return ("", 204)

@app.get("/api/status")
def status():
    if not (REPO / ".git").exists():
        return jsonify({"ok": False, "error": f"Repo not found: {REPO}"}), 400
    r1 = run("git status -sb")
    r2 = run("python3 sd_check.py") if (REPO/"sd_check.py").exists() else {"code": 127, "out": "", "err": "sd_check.py missing"}
    return jsonify({"ok": True, "repo": str(REPO), "git": r1, "check": r2})

@app.post("/api/check")
def check():
    return jsonify(run("python3 sd_check.py"))

@app.post("/api/rollback")
def rollback():
    if (REPO/"sdrollback").exists():
        return jsonify(run("./sdrollback"))
    return jsonify(run("git checkout baseline -- index.html styles.css"))

@app.post("/api/set_cosmos")
def set_cosmos():
    f = request.files.get("cosmos")
    if not f:
        return jsonify({"ok": False, "error": "No file uploaded (field name must be cosmos)"}), 400

    (REPO / "assets" / "pup_slides").mkdir(parents=True, exist_ok=True)
    out_path = REPO / "assets" / "pup_slides" / "cosmos_01.jpg"
    f.save(str(out_path))

    html = (REPO / "index.html").read_text(errors="ignore")
    try:
        html2 = bump_cosmos_cache_buster(html)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    (REPO / "index.html").write_text(html2)

    chk = run("python3 sd_check.py") if (REPO/"sd_check.py").exists() else {"code": 127, "out": "", "err": "sd_check.py missing"}
    if chk["code"] != 0:
        return jsonify({"ok": False, "error": "Check failed after swap (push blocked).", "check": chk}), 400

    if request.args.get("push") == "1":
        run("git add index.html assets/pup_slides/cosmos_01.jpg 2>/dev/null || true")
        run('git commit -m "Update Cosmos photo" || true')
        p = run("git push")
        return jsonify({"ok": True, "check": chk, "push": p})

    return jsonify({"ok": True, "check": chk})

@app.post("/api/commitpush")
def commitpush():
    msg = "update"
    if request.is_json:
        msg = (request.json.get("msg") or "update").strip() or "update"

    chk = run("python3 sd_check.py") if (REPO/"sd_check.py").exists() else {"code": 127, "out": "", "err": "sd_check.py missing"}
    if chk["code"] != 0:
        return jsonify({"ok": False, "error": "Check failed. Push blocked.", "check": chk}), 400

    run("git add index.html styles.css sd_check.py sdrollback tweaks.css 2>/dev/null || true")
    c = run(f'git commit -m {shlex.quote(msg)} || true')
    p = run("git push")
    return jsonify({"ok": True, "check": chk, "commit": c, "push": p})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
