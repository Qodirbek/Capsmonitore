# CAPS Monitor Hub (Professional)

Nazoratchi + xavfsizlik qatlami. Render + PostgreSQL.

## Deploy (Render)
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4`
- Env:
  - `SECRET_KEY` (majburiy, uzun random)
  - `DATABASE_URL` = Render Postgres connection string
  - `TG_BOT_TOKEN` (ixtiyoriy)

## Local
```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://..."
python app.py
```

## Security
- Worker faqat status / balance yuboradi
- Cookie, password, email, wallet **hech qachon** hubga ketmaydi
- Device code bilan autentifikatsiya

## CAPS Unified (bot)
Download: **/download/full** → `caps-unified.zip`

Professional humanize:
- Har akkaunt har kuni random 18–24 claim target
- Wait 52–110 min real jitter (pattern yo‘q)
- 100–200 akkaunt, 16GB RAM da bemalol
- Local IconCaptcha + ixtiyoriy Gemini

Reporter faqat monitor; captcha yechmaydi.
