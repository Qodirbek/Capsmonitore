#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CAPS Monitor reporter — yengil, fon, past nagruzka.
Faqat panel_status.json ni o'qiydi, botlarga tegmaydi.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    raise

# ── sozlamalar (past nagruzka) ──────────────────────────
INTERVAL_OK = 90          # muvaffaqiyatli hb dan keyin (soniya)
INTERVAL_ERR = 45         # tarmoq xato
INTERVAL_EMPTY = 120      # akk topilmasa
SCAN_CACHE_SEC = 25       # bir xil scan natijasini qayta ishlatish
MAX_LIST = 60             # serverga max akk tafsiloti


def find_root(caps_root: str = "") -> Path:
    if caps_root:
        return Path(caps_root)
    here = Path(__file__).resolve().parent
    for cand in (here, here.parent):
        if (cand / "run.py").is_file() or (cand / "app.py").is_file() or (cand / "accounts").is_dir():
            return cand
    env = os.environ.get("CAPS_ROOT")
    return Path(env) if env else here


def _f(x, default=0.0) -> float:
    try:
        if x is None:
            return default
        return float(str(x).replace(",", "").split()[0])
    except Exception:
        return default


_scan_cache = {"t": 0.0, "data": None, "sig": ""}


def _panels_sig(root: Path) -> str:
    """Tez o'zgarish tekshiruvi — to'liq parse qilmasdan."""
    parts = []
    try:
        for p in root.rglob("panel_status.json"):
            try:
                st = p.stat()
                parts.append(f"{p}:{int(st.st_mtime)}:{st.st_size}")
            except Exception:
                pass
    except Exception:
        pass
    return "|".join(parts[:120])


def scan(root: Path) -> dict:
    """panel_status.json larni yig'ish. Cache + mtime."""
    global _scan_cache
    now = time.time()
    sig = _panels_sig(root)
    if (
        _scan_cache["data"] is not None
        and sig == _scan_cache["sig"]
        and (now - _scan_cache["t"]) < SCAN_CACHE_SEC
    ):
        return _scan_cache["data"]

    out = {
        "accounts": 0,
        "online": 0,
        "claims_today": 0,
        "coins": {},
        "balances": {},
        "list": [],
    }
    if not root.is_dir():
        return out

    seen = set()
    for p in root.rglob("panel_status.json"):
        try:
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            j = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            folder = p.parent.name
            coin = (j.get("coin") or "").upper().strip()
            if not coin or coin in ("—", "-", "?", "NONE"):
                coin = folder.split("_")[0].upper() if "_" in folder else "UNK"
            user = str(j.get("user") or j.get("label") or folder)[:40]
            bal = _f(j.get("balance"))
            st = (j.get("status") or "").upper()
            claims = int(j.get("claims_today") or 0)

            out["accounts"] += 1
            if st in ("RUN", "OK", "CAP", "WAIT", "WARN", "CLAIM"):
                out["online"] += 1
            out["claims_today"] += claims
            out["coins"][coin] = out["coins"].get(coin, 0) + 1
            out["balances"][coin] = round(out["balances"].get(coin, 0.0) + bal, 8)
            out["list"].append(
                {
                    "folder": folder,
                    "user": user,
                    "coin": coin,
                    "balance": bal,
                    "status": st or "—",
                    "claims_today": claims,
                    "last": str(j.get("last") or "")[:40],
                }
            )
        except Exception:
            continue

    out["list"] = sorted(
        out["list"], key=lambda x: (-float(x.get("balance") or 0), x.get("folder") or "")
    )[:MAX_LIST]
    _scan_cache = {"t": now, "data": out, "sig": sig}
    return out


def register(hub: str, code: str, name: str) -> str:
    r = requests.post(
        f"{hub}/api/device/register",
        json={"code": code, "name": name[:48], "platform": platform.system()[:32]},
        timeout=20,
    )
    j = r.json() if r.ok else {}
    if not j.get("ok") or not j.get("token"):
        raise SystemExit(f"register fail: {r.status_code} {j}")
    return j["token"]


def heartbeat(hub: str, tok: str, payload: dict) -> bool:
    r = requests.post(
        f"{hub}/api/device/heartbeat",
        json=payload,
        headers={"X-Device-Token": tok},
        timeout=18,
    )
    return r.ok


def main():
    ap = argparse.ArgumentParser(description="CAPS Monitor reporter (yengil)")
    ap.add_argument("--hub", required=True)
    ap.add_argument("--code", default="")
    ap.add_argument("--name", default="")
    ap.add_argument("--token", default="")
    ap.add_argument("--token-file", default="device_token.txt")
    ap.add_argument("--caps-root", default="")
    ap.add_argument("--interval", type=int, default=INTERVAL_OK, help="soniya (default 90)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="kam log")
    args = ap.parse_args()

    hub = args.hub.rstrip("/")
    root = find_root(args.caps_root)
    quiet = args.quiet
    interval = max(45, int(args.interval or INTERVAL_OK))

    if not quiet:
        print("[reporter] root =", root)
        print("[reporter] hub  =", hub)

    tf = Path(args.token_file)
    tok = (args.token or "").strip()
    if not tok and tf.is_file():
        tok = tf.read_text(encoding="utf-8").strip()

    if not tok:
        if not args.code:
            print("--code yoki --token kerak", file=sys.stderr)
            sys.exit(1)
        name = (args.name or platform.node() or "device")[:48]
        tok = register(hub, args.code, name)
        tf.write_text(tok, encoding="utf-8")
        if not quiet:
            print("[reporter] registered →", tf)

    try:
        os.nice(10)
    except Exception:
        pass

    fail = 0
    while True:
        try:
            payload = scan(root)
            ok = heartbeat(hub, tok, payload)
            if ok:
                fail = 0
                if not quiet:
                    bals = payload.get("balances") or {}
                    short = " ".join(f"{k}:{v:g}" for k, v in list(bals.items())[:4]) or "—"
                    print(
                        time.strftime("%H:%M:%S"),
                        f"akk={payload['accounts']} on={payload['online']} {short}",
                    )
                sleep_s = interval if payload["accounts"] else INTERVAL_EMPTY
            else:
                fail += 1
                if not quiet:
                    print(time.strftime("%H:%M:%S"), "hb fail")
                sleep_s = INTERVAL_ERR
        except Exception as e:
            fail += 1
            if not quiet:
                print(time.strftime("%H:%M:%S"), "err", type(e).__name__)
            sleep_s = INTERVAL_ERR

        if args.once:
            break
        jitter = 5 + (int(time.time()) % 11)
        time.sleep(sleep_s + jitter)


if __name__ == "__main__":
    main()