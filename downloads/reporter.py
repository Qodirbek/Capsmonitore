#!/usr/bin/env python3
"""Lightweight device reporter — no secrets to hub."""
import json, time, urllib.request, pathlib, os, sys

BASE = pathlib.Path(__file__).resolve().parent
CFG_PATH = BASE / "config.json"

def load_cfg():
    if not CFG_PATH.is_file():
        print("config.json yoq")
        sys.exit(1)
    return json.loads(CFG_PATH.read_text(encoding="utf-8"))

def post(url, data):
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())

def scan_accounts(root: pathlib.Path):
    out = []
    if not root.is_dir():
        return out
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        ps = folder / "panel_status.json"
        if not ps.is_file():
            continue
        try:
            j = json.loads(ps.read_text(encoding="utf-8"))
        except Exception:
            continue
        coin = "TRX"
        name = folder.name.lower()
        if name.startswith("ton"): coin = "TON"
        elif name.startswith("sui"): coin = "SUI"
        elif name.startswith("sol"): coin = "SOL"
        elif name.startswith("doge"): coin = "DOGE"
        elif name.startswith("ltc") or name.startswith("lite"): coin = "LTC"
        out.append({
            "external_key": folder.name,
            "label": j.get("user") or folder.name,
            "balance": j.get("balance") or 0,
            "status": j.get("status") or "",
            "coin": j.get("coin") or coin,
            "platform": coin.lower(),
        })
    return out

def main():
    cfg = load_cfg()
    hub = (cfg.get("hub_url") or "").rstrip("/")
    code = (cfg.get("device_code") or "").strip().upper()
    if not hub or not code:
        print("hub_url va device_code shart")
        sys.exit(1)
    root = cfg.get("caps_root") or ""
    if not root:
        candidates = [
            BASE.parent / "caps-unified" / "accounts",
            BASE / "accounts",
            pathlib.Path("/sdcard/pul/eror/caps-unified/accounts"),
            pathlib.Path("/sdcard/pul/caps/accounts"),
            pathlib.Path("C:/caps-unified/accounts"),
        ]
        for c in candidates:
            if c.is_dir():
                root = str(c)
                break
    interval = int(cfg.get("interval_sec") or 30)
    print("CAPS reporter ->", hub, "device", code, "root", root or "(none)")
    while True:
        try:
            accs = scan_accounts(pathlib.Path(root)) if root else []
            post(hub + "/api/device/heartbeat", {
                "device_code": code,
                "name": cfg.get("name") or "",
                "platform": cfg.get("platform") or "",
                "capacity": int(cfg.get("capacity") or 10),
            })
            if accs:
                post(hub + "/api/device/report", {
                    "device_code": code,
                    "name": cfg.get("name") or "",
                    "platform": cfg.get("platform") or "",
                    "accounts": accs,
                })
            print(time.strftime("%H:%M:%S"), "ok", len(accs), "acc")
        except Exception as e:
            print("err", e)
        time.sleep(interval)

if __name__ == "__main__":
    main()
