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
