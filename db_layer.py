"""Dual database layer: PostgreSQL (Render) preferred, SQLite fallback."""
from __future__ import annotations
import os, json, time
from pathlib import Path
from contextlib import contextmanager

DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
DATA = Path(os.environ.get("DATA_DIR") or (Path(__file__).parent / "data"))
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "hub.db"

_USE_PG = False
_pool = None

def init():
    global _USE_PG, _pool
    if not DATABASE_URL:
        return
    try:
        import psycopg2
        from psycopg2.pool import SimpleConnectionPool
        from psycopg2.extras import RealDictCursor
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        _pool = SimpleConnectionPool(1, 10, url, cursor_factory=RealDictCursor)
        # test
        c = _pool.getconn()
        c.cursor().execute("SELECT 1")
        _pool.putconn(c)
        _USE_PG = True
        print("[db] PostgreSQL OK")
    except Exception as e:
        print("[db] Postgres fail → SQLite:", e)
        _USE_PG = False

init()

@contextmanager
def connection():
    if _USE_PG and _pool:
        conn = _pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            _pool.putconn(conn)
    else:
        import sqlite3
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
            conn.rollback()
            raise
        finally:
            conn.close()

def is_pg():
    return _USE_PG

def q(sql: str) -> str:
    """? → %s for Postgres."""
    if _USE_PG:
        return sql.replace("?", "%s")
    return sql
