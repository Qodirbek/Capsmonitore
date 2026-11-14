#!/usr/bin/env python3
"""CAPS Monitor Hub — auth, devices, downloads, distribution."""
from __future__ import annotations
import hashlib, hmac, json, os, secrets, sqlite3, time, zipfile, io
from pathlib import Path
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, redirect, url_for,
    session, send_file,
)

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA_DIR") or (ROOT / "data"))
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "hub.db"
DL = ROOT / "downloads"
SECRET = os.environ.get("SECRET_KEY") or "caps-hub-change-me"
TG_TOKEN = os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN") or ""

app = Flask(__name__)
app.secret_key = SECRET
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 30
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def db():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    return conn


def init_db():
    with db() as c:
        c.executescript(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            name TEXT,
            tg_id TEXT,
            tg_username TEXT,
            created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_code TEXT UNIQUE,
            name TEXT,
            platform TEXT,
            last_seen INTEGER,
            online INTEGER DEFAULT 0,
            capacity INTEGER DEFAULT 10,
            meta TEXT,
            created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS link_codes (
            code TEXT PRIMARY KEY,
            user_id INTEGER,
            purpose TEXT,
            expires INTEGER
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            external_key TEXT,
            platform TEXT,
            label TEXT,
            coin TEXT,
            balance REAL DEFAULT 0,
            status TEXT,
            device_id INTEGER,
            updated_at INTEGER
        );
        """
        )
        c.commit()


init_db()


def hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()
    return f"{salt}${h}"


def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
        return hmac.compare_digest(hash_pw(pw, salt), stored)
    except Exception:
        return False


def login_required(fn):
    @wraps(fn)
    def wrap(*a, **k):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **k)

    return wrap


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with db() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return dict(r) if r else None


def touch_device(code: str, name: str = "", platform: str = "", capacity: int = 10, meta=None):
    now = int(time.time())
    with db() as c:
        r = c.execute("SELECT * FROM devices WHERE device_code=?", (code,)).fetchone()
        if not r:
            return None
        c.execute(
            "UPDATE devices SET last_seen=?, online=1, name=COALESCE(NULLIF(?,''), name), platform=COALESCE(NULLIF(?,''), platform), capacity=?, meta=? WHERE id=?",
            (now, name, platform, capacity, json.dumps(meta or {}), r["id"]),
        )
        c.commit()
        return dict(c.execute("SELECT * FROM devices WHERE id=?", (r["id"],)).fetchone())


def mark_offline():
    cut = int(time.time()) - 90
    with db() as c:
        rows = c.execute(
            "SELECT id FROM devices WHERE online=1 AND (last_seen IS NULL OR last_seen<?)",
            (cut,),
        ).fetchall()
        for r in rows:
            c.execute("UPDATE devices SET online=0 WHERE id=?", (r["id"],))
            c.execute("UPDATE accounts SET device_id=NULL WHERE device_id=?", (r["id"],))
        c.commit()


def redistribute(user_id: int):
    mark_offline()
    with db() as c:
        devices = [
            dict(x)
            for x in c.execute(
                "SELECT * FROM devices WHERE user_id=? AND online=1 ORDER BY id",
                (user_id,),
            ).fetchall()
        ]
        if not devices:
            c.execute("UPDATE accounts SET device_id=NULL WHERE user_id=?", (user_id,))
            c.commit()
            return
        accs = [
            dict(x)
            for x in c.execute(
                "SELECT * FROM accounts WHERE user_id=? ORDER BY id", (user_id,)
            ).fetchall()
        ]
        load = {d["id"]: 0 for d in devices}
        for a in accs:
            if a.get("device_id") in load:
                load[a["device_id"]] += 1
        for a in accs:
            if a.get("device_id") in load:
                continue
            best = None
            for d in devices:
                cap = int(d.get("capacity") or 10)
                if load[d["id"]] < cap and (best is None or load[d["id"]] < load[best]):
                    best = d["id"]
            if best is None:
                best = devices[0]["id"]
            c.execute("UPDATE accounts SET device_id=? WHERE id=?", (best, a["id"]))
            load[best] = load.get(best, 0) + 1
        c.commit()


@app.route("/")
def index():
    u = current_user()
    if not u:
        return render_template("landing.html", user=None)
    mark_offline()
    with db() as c:
        devices = [
            dict(x)
            for x in c.execute(
                "SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC",
                (u["id"],),
            ).fetchall()
        ]
        accs = [
            dict(x)
            for x in c.execute(
                "SELECT * FROM accounts WHERE user_id=? ORDER BY id", (u["id"],)
            ).fetchall()
        ]
    online = sum(1 for d in devices if d.get("online"))
    return render_template(
        "dashboard.html", user=u, devices=devices, accounts=accs, online=online
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("auth.html", mode="signup", user=None, error=None)
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    name = (request.form.get("name") or "").strip() or email.split("@")[0]
    if not email or len(password) < 6:
        return render_template(
            "auth.html", mode="signup", user=None, error="Email va parol (min 6) kerak"
        )
    try:
        with db() as c:
            c.execute(
                "INSERT INTO users(email, pass_hash, name, created_at) VALUES(?,?,?,?)",
                (email, hash_pw(password), name, int(time.time())),
            )
            c.commit()
            uid = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        session["uid"] = uid
        session.permanent = True
        return redirect(url_for("index"))
    except sqlite3.IntegrityError:
        return render_template(
            "auth.html", mode="signup", user=None, error="Bu email band"
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth.html", mode="login", user=None, error=None)
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    with db() as c:
        r = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not r or not verify_pw(password, r["pass_hash"]):
        return render_template(
            "auth.html", mode="login", user=None, error="Email yoki parol xato"
        )
    session["uid"] = r["id"]
    session.permanent = True
    return redirect(request.args.get("next") or url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/devices")
@login_required
def devices_page():
    u = current_user()
    mark_offline()
    with db() as c:
        devices = [
            dict(x)
            for x in c.execute(
                "SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC",
                (u["id"],),
            ).fetchall()
        ]
    return render_template("devices.html", user=u, devices=devices)


@app.route("/devices/add", methods=["GET", "POST"])
@login_required
def devices_add():
    u = current_user()
    if request.method == "POST":
        name = (request.form.get("name") or "Device").strip()[:40]
        platform = (request.form.get("platform") or "android").strip()[:20]
        code = secrets.token_hex(4).upper()
        with db() as c:
            c.execute(
                "INSERT INTO devices(user_id, device_code, name, platform, last_seen, online, capacity, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (u["id"], code, name, platform, 0, 0, 10, int(time.time())),
            )
            c.commit()
        return render_template(
            "device_created.html", user=u, code=code, name=name, platform=platform
        )
    return render_template("device_add.html", user=u)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user())


@app.route("/profile/tg", methods=["POST"])
@login_required
def profile_tg():
    u = current_user()
    code = secrets.token_hex(3).upper()
    with db() as c:
        c.execute(
            "INSERT OR REPLACE INTO link_codes(code, user_id, purpose, expires) VALUES(?,?,?,?)",
            (code, u["id"], "tg", int(time.time()) + 900),
        )
        c.commit()
    return jsonify({"ok": True, "code": code, "hint": "Telegram botga: /link " + code})


@app.route("/download")
def download_page():
    return render_template("download.html", user=current_user())


@app.route("/download/<kind>")
def download_pkg(kind: str):
    kind = (kind or "").lower()
    if kind not in ("pc", "android"):
        return "Not found", 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("reporter.py", "config.example.json"):
            p = DL / name
            if p.is_file():
                z.write(p, f"caps-worker/{name}")
        if kind == "pc":
            p = DL / "start_pc.bat"
            if p.is_file():
                z.write(p, "caps-worker/start_pc.bat")
            z.writestr(
                "caps-worker/README.txt",
                "PC: open folder, copy config.example.json to config.json,\n"
                "set hub_url + device_code, run start_pc.bat\n"
                "Suggested path: C:\\caps-unified\\worker\n",
            )
        else:
            p = DL / "start_android.sh"
            if p.is_file():
                z.write(p, "caps-worker/start_android.sh")
            z.writestr(
                "caps-worker/README.txt",
                "Termux: bash start_android.sh\nUse termux-wake-lock\n",
            )
    buf.seek(0)
    fname = f"caps-worker-{kind}.zip"
    return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/zip")


@app.post("/api/device/heartbeat")
def api_heartbeat():
    body = request.get_json(silent=True) or {}
    code = (body.get("device_code") or body.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "device_code kerak"}), 400
    d = touch_device(
        code,
        name=str(body.get("name") or ""),
        platform=str(body.get("platform") or ""),
        capacity=int(body.get("capacity") or 10),
        meta=body.get("meta") if isinstance(body.get("meta"), dict) else {},
    )
    if not d:
        return jsonify({"error": "noma'lum device_code"}), 404
    redistribute(d["user_id"])
    with db() as c:
        assigned = [
            dict(x)
            for x in c.execute(
                "SELECT id, external_key, platform, label, coin, balance, status FROM accounts WHERE device_id=?",
                (d["id"],),
            ).fetchall()
        ]
    return jsonify({"ok": True, "device_id": d["id"], "assigned": assigned, "server_ts": int(time.time())})


@app.post("/api/device/report")
def api_report():
    body = request.get_json(silent=True) or {}
    code = (body.get("device_code") or "").strip().upper()
    d = touch_device(code, name=str(body.get("name") or ""), platform=str(body.get("platform") or ""))
    if not d:
        return jsonify({"error": "device"}), 404
    items = body.get("accounts") or []
    now = int(time.time())
    with db() as c:
        for it in items:
            if not isinstance(it, dict):
                continue
            key = str(it.get("external_key") or it.get("folder") or it.get("id") or "")[:80]
            if not key:
                continue
            label = str(it.get("label") or it.get("user") or key)[:40]
            coin = str(it.get("coin") or "TRX")[:10]
            try:
                bal = float(it.get("balance") or 0)
            except Exception:
                bal = 0.0
            st = str(it.get("status") or "")[:20]
            plat = str(it.get("platform") or "")[:20]
            row = c.execute(
                "SELECT id FROM accounts WHERE user_id=? AND external_key=?",
                (d["user_id"], key),
            ).fetchone()
            if row:
                c.execute(
                    "UPDATE accounts SET label=?, coin=?, balance=?, status=?, platform=?, device_id=?, updated_at=? WHERE id=?",
                    (label, coin, bal, st, plat, d["id"], now, row["id"]),
                )
            else:
                c.execute(
                    "INSERT INTO accounts(user_id, external_key, platform, label, coin, balance, status, device_id, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (d["user_id"], key, plat, label, coin, bal, st, d["id"], now),
                )
        c.commit()
    redistribute(d["user_id"])
    return jsonify({"ok": True})


@app.post("/api/tg/webhook")
def tg_webhook():
    if not TG_TOKEN:
        return jsonify({"ok": True})
    body = request.get_json(silent=True) or {}
    msg = body.get("message") or {}
    text = (msg.get("text") or "").strip()
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    username = (chat.get("username") or "")[:40]
    if not text or not chat_id:
        return jsonify({"ok": True})
    if text.startswith("/link"):
        parts = text.split()
        code = (parts[1] if len(parts) > 1 else "").strip().upper()
        with db() as c:
            row = c.execute("SELECT * FROM link_codes WHERE code=?", (code,)).fetchone()
            if not row or int(row["expires"] or 0) < time.time():
                _tg_send(chat_id, "Kod notogri yoki muddati otgan.")
            else:
                c.execute(
                    "UPDATE users SET tg_id=?, tg_username=? WHERE id=?",
                    (str(chat_id), username, row["user_id"]),
                )
                c.execute("DELETE FROM link_codes WHERE code=?", (code,))
                c.commit()
                _tg_send(chat_id, "Telegram CAPS hub ga ulandi")
    elif text.startswith("/start"):
        _tg_send(chat_id, "CAPS Monitor\nUlash: /link KOD")
    return jsonify({"ok": True})


def _tg_send(chat_id, text):
    if not TG_TOKEN:
        return
    try:
        import urllib.request

        data = json.dumps({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=15)
    except Exception:
        pass


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": int(time.time())})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
