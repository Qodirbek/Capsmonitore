# CAPS Monitor Hub

Sign up / Login · Devices · Download PC/Android · Account distribution (monitor)

## Deploy Render
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --bind 0.0.0.0:$PORT`
- Env: `SECRET_KEY`, optional `TG_BOT_TOKEN`

## Local
```bash
pip install -r requirements.txt
python app.py
```

## Security
Workers send only status/balance. No passwords or cookies to the hub.

## Captcha (CAPS Unified)

To‘liq bot `downloads/caps-unified-full.zip` — saytdan **Download CAPS Unified**.

Ishlash:
1. Countdown tugagach claim oynasi
2. Captcha yechiladi (Icon lokal, boshqalar API)
3. ~1 soat + random kutish
4. Kuniga ~21–24 claim / hisob

Reporter faqat hub monitori; captcha yechmaydi.
