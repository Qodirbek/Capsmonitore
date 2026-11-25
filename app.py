#!/usr/bin/env python3
"""CAPS Monitor Hub — professional controller.
PostgreSQL (Render) preferred, SQLite fallback.
Workers send only status/balance — never secrets.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import zipfile
import io
from pathlib import Path
from functools import wraps
from contextlib import contextmanager

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
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()

app = Flask(__name__)
app.secret_key = SECRET
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 30
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("RENDER"):
    app.config["SESSION_COOKIE_SECURE"] = True

# ── Dual DB ──────────────────────────────────────────────────────────
_USE_PG = False
_pg_pool = None


def _setup_pg():
    global _USE_PG, _pg_pool
    if not DATABASE_URL:
        return
    try:
        import psycopg2
        from psycopg2.pool import SimpleConnectionPool
        from psycopg2.extras import RealDictCursor
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        _pg_pool = SimpleConnectionPool(1, 8, url, cursor_factory=RealDictCursor)
        conn = _pg_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        _pg_pool.putconn(conn)
        _USE_PG = True
        print("[hub] PostgreSQL ready")
    except Exception as e:
        print("[hub] Postgres unavailable → SQLite:", e)
        _USE_PG = False


_setup_pg()


@contextmanager
def db():
    if _USE_PG and _pg_pool:
        conn = _pg_pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            _pg_pool.putconn(conn)
    else:
        conn = sqlite3.connect(str(DB_PATH), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()


def _q(sql: str) -> str:
    """? → %s for Postgres."""
    if _USE_PG:
        return sql.replace("?", "%s")
    return sql


def _fetchone(cur):
    row = cur.fetchone()
    if row is None:
        return None
    if _USE_PG:
        return dict(row)
    return dict(row)


def _fetchall(cur):
    rows = cur.fetchall()
    if _USE_PG:
        return [dict(r) for r in rows]
    return [dict(r) for r in rows]


def init_db():
    schema_sqlite = """
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
    schema_pg = [
        """CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            name TEXT,
            tg_id TEXT,
            tg_username TEXT,
            created_at BIGINT
        )""",
        """CREATE TABLE IF NOT EXISTS devices (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            device_code TEXT UNIQUE,
            name TEXT,
            platform TEXT,
            last_seen BIGINT,
            online INTEGER DEFAULT 0,
            capacity INTEGER DEFAULT 10,
            meta TEXT,
            created_at BIGINT
        )""",
        """CREATE TABLE IF NOT EXISTS link_codes (
            code TEXT PRIMARY KEY,
            user_id INTEGER,
            purpose TEXT,
            expires BIGINT
        )""",
        """CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            external_key TEXT,
            platform TEXT,
            label TEXT,
            coin TEXT,
            balance DOUBLE PRECISION DEFAULT 0,
            status TEXT,
            device_id INTEGER,
            updated_at BIGINT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_devices_code ON devices(device_code)",
        "CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)",
    ]
    with db() as conn:
        if _USE_PG:
            cur = conn.cursor()
            for stmt in schema_pg:
                cur.execute(stmt)
        else:
            conn.executescript(schema_sqlite)
    print("[hub] schema ready · db=", "postgres" if _USE_PG else "sqlite")


init_db()


# ── Auth ─────────────────────────────────────────────────────────────

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
            return redirect(url_for("login"))
        return fn(*a, **k)
    return wrap


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with db() as conn:
        cur = conn.cursor()
        cur.execute(_q("SELECT * FROM users WHERE id=?"), (uid,))
        return _fetchone(cur)


# ── Device helpers ───────────────────────────────────────────────────

def touch_device(code: str, name: str = "", platform: str = "", capacity: int = 10, meta=None):
    now = int(time.time())
    meta_s = json.dumps(meta) if meta is not None else None
    with db() as conn:
        cur = conn.cursor()
        cur.execute(_q("SELECT * FROM devices WHERE device_code=?"), (code,))
        r = _fetchone(cur)
        if not r:
            return None
        cur.execute(
            _q(
                "UPDATE devices SET last_seen=?, online=1, "
                "name=COALESCE(NULLIF(?,''), name), "
                "platform=COALESCE(NULLIF(?,''), platform), "
                "capacity=?, meta=COALESCE(?, meta) WHERE id=?"
            ),
            (now, name, platform, capacity, meta_s, r["id"]),
        )
        cur.execute(_q("SELECT * FROM devices WHERE id=?"), (r["id"],))
        return _fetchone(cur)


def mark_offline():
    cutoff = int(time.time()) - 180
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("SELECT id FROM devices WHERE online=1 AND (last_seen IS NULL OR last_seen<?)"),
            (cutoff,),
        )
        rows = _fetchall(cur)
        for r in rows:
            cur.execute(_q("UPDATE devices SET online=0 WHERE id=?"), (r["id"],))
            cur.execute(_q("UPDATE accounts SET device_id=NULL WHERE device_id=?"), (r["id"],))


def redistribute(user_id: int):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("SELECT * FROM devices WHERE user_id=? AND online=1 ORDER BY id"),
            (user_id,),
        )
        devices = _fetchall(cur)
        cur.execute(_q("SELECT * FROM accounts WHERE user_id=?"), (user_id,))
        accs = _fetchall(cur)

        if not devices:
            cur.execute(_q("UPDATE accounts SET device_id=NULL WHERE user_id=?"), (user_id,))
            return

        load = {d["id"]: 0 for d in devices}
        for a in accs:
            if a.get("device_id") in load:
                load[a["device_id"]] += 1

        for a in accs:
            if a.get("device_id") in load:
                continue
            best = None
            best_load = 10**9
            for d in devices:
                cap = int(d.get("capacity") or 10)
                cur_load = load[d["id"]]
                if cur_load < cap and cur_load < best_load:
                    best_load = cur_load
                    best = d["id"]
            if best is None:
                best = devices[0]["id"]
            cur.execute(_q("UPDATE accounts SET device_id=? WHERE id=?"), (best, a["id"]))
            load[best] = load.get(best, 0) + 1


# ── Routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    u = current_user()
    if not u:
        return render_template("landing.html")
    mark_offline()
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC"),
            (u["id"],),
        )
        devices = _fetchall(cur)
        cur.execute(
            _q("SELECT * FROM accounts WHERE user_id=? ORDER BY updated_at DESC"),
            (u["id"],),
        )
        accs = _fetchall(cur)
    online = sum(1 for d in devices if d.get("online"))
    return render_template(
        "dashboard.html", user=u, devices=devices, accounts=accs, online=online
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("auth.html", mode="signup")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    name = (request.form.get("name") or "").strip()[:60]
    if not email or len(password) < 6:
        return render_template("auth.html", mode="signup", error="Email va kamida 6 belgili parol kerak")
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                _q("INSERT INTO users(email, pass_hash, name, created_at) VALUES(?,?,?,?)"),
                (email, hash_pw(password), name, int(time.time())),
            )
        return redirect(url_for("login"))
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg or "integrity" in msg:
            return render_template("auth.html", mode="signup", error="Bu email band")
        return render_template("auth.html", mode="signup", error=str(e)[:120])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth.html", mode="login")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    with db() as conn:
        cur = conn.cursor()
        cur.execute(_q("SELECT * FROM users WHERE email=?"), (email,))
        u = _fetchone(cur)
    if not u or not verify_pw(password, u["pass_hash"]):
        return render_template("auth.html", mode="login", error="Email yoki parol xato")
    session["uid"] = u["id"]
    session.permanent = True
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/devices")
@login_required
def devices_page():
    u = current_user()
    mark_offline()
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            _q("SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC"),
            (u["id"],),
        )
        devices = _fetchall(cur)
    return render_template("devices.html", user=u, devices=devices)


@app.route("/devices/add", methods=["GET", "POST"])
@login_required
def devices_add():
    u = current_user()
    if request.method == "POST":
        name = (request.form.get("name") or "Device").strip()[:40]
        platform = (request.form.get("platform") or "pc").strip()[:20]
        code = secrets.token_hex(4).upper()
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                _q(
                    "INSERT INTO devices(user_id, device_code, name, platform, last_seen, online, capacity, created_at) "
                    "VALUES(?,?,?,?,?,0,?,?)"
                ),
                (u["id"], code, name, platform, int(time.time()), 10, int(time.time())),
            )
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
    with db() as conn:
        cur = conn.cursor()
        if _USE_PG:
            cur.execute(
                "INSERT INTO link_codes(code, user_id, purpose, expires) VALUES(%s,%s,%s,%s) "
                "ON CONFLICT (code) DO UPDATE SET user_id=EXCLUDED.user_id, purpose=EXCLUDED.purpose, expires=EXCLUDED.expires",
                (code, u["id"], "tg", int(time.time()) + 900),
            )
        else:
            cur.execute(
                "INSERT OR REPLACE INTO link_codes(code, user_id, purpose, expires) VALUES(?,?,?,?)",
                (code, u["id"], "tg", int(time.time()) + 900),
            )
    return jsonify({"ok": True, "code": code, "hint": "Telegram botga: /link " + code})


@app.route("/download")
def download_page():
    return render_template("download.html", user=current_user())


@app.route("/download/full")
def download_full():
    path = DL / "caps-unified-full.zip"
    if not path.is_file():
        return "Full package not found on server", 404
    return send_file(
        path, as_attachment=True, download_name="caps-unified.zip", mimetype="application/zip"
    )


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
                "PC: copy config.example.json → config.json\n"
                "set hub_url + device_code, run start_pc.bat\n",
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
    return send_file(
        buf, as_attachment=True, download_name=f"caps-worker-{kind}.zip", mimetype="application/zip"
    )


# ── Worker API ───────────────────────────────────────────────────────

@app.post("/api/device/heartbeat")
def api_heartbeat():
    body = request.get_json(silent=True) or {}
    code = (body.get("device_code") or body.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "device_code required"}), 400
    d = touch_device(
        code,
        name=(body.get("name") or "")[:40],
        platform=(body.get("platform") or "")[:20],
        capacity=int(body.get("capacity") or 10),
        meta=body.get("meta"),
    )
    if not d:
        return jsonify({"error": "unknown device_code"}), 404
    return jsonify({"ok": True, "device_id": d["id"], "online": 1})


@app.post("/api/device/report")
def api_report():
    body = request.get_json(silent=True) or {}
    code = (body.get("device_code") or body.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "device_code required"}), 400
    d = touch_device(
        code,
        name=(body.get("name") or "")[:40],
        platform=(body.get("platform") or "")[:20],
        capacity=int(body.get("capacity") or 10),
    )
    if not d:
        return jsonify({"error": "unknown device_code"}), 404

    accounts = body.get("accounts") or []
    if not isinstance(accounts, list):
        accounts = []
    now = int(time.time())
    with db() as conn:
        cur = conn.cursor()
        for a in accounts[:80]:
            if not isinstance(a, dict):
                continue
            key = (a.get("external_key") or a.get("key") or "")[:80]
            if not key:
                continue
            label = (a.get("label") or key)[:60]
            coin = (a.get("coin") or "")[:12]
            plat = (a.get("platform") or coin.lower())[:20]
            try:
                bal = float(a.get("balance") or 0)
            except Exception:
                bal = 0.0
            st = (a.get("status") or "")[:40]

            cur.execute(
                _q("SELECT id FROM accounts WHERE user_id=? AND external_key=?"),
                (d["user_id"], key),
            )
            row = _fetchone(cur)
            if row:
                cur.execute(
                    _q(
                        "UPDATE accounts SET label=?, coin=?, balance=?, status=?, "
                        "platform=?, device_id=?, updated_at=? WHERE id=?"
                    ),
                    (label, coin, bal, st, plat, d["id"], now, row["id"]),
                )
            else:
                cur.execute(
                    _q(
                        "INSERT INTO accounts(user_id, external_key, platform, label, coin, balance, status, device_id, updated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)"
                    ),
                    (d["user_id"], key, plat, label, coin, bal, st, d["id"], now),
                )
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
        with db() as conn:
            cur = conn.cursor()
            cur.execute(_q("SELECT * FROM link_codes WHERE code=?"), (code,))
            row = _fetchone(cur)
            if not row or int(row["expires"] or 0) < time.time():
                _tg_send(chat_id, "Kod notogri yoki muddati otgan.")
            else:
                cur.execute(
                    _q("UPDATE users SET tg_id=?, tg_username=? WHERE id=?"),
                    (str(chat_id), username, row["user_id"]),
                )
                cur.execute(_q("DELETE FROM link_codes WHERE code=?"), (code,))
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
    return jsonify({
        "ok": True,
        "ts": int(time.time()),
        "db": "postgres" if _USE_PG else "sqlite",
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
