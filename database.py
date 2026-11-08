import sqlite3
from datetime import datetime

DB_FILE = "checks.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                host TEXT,
                level TEXT NOT NULL,
                score INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def save_check(url, host, level, score):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO checks (url, host, level, score, created_at) VALUES (?, ?, ?, ?, ?)",
            (url[:500], host, level, score, datetime.now().isoformat(timespec="seconds")),
        )


def get_stats():
    with sqlite3.connect(DB_FILE) as conn:
        total = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        by_level = dict(conn.execute(
            "SELECT level, COUNT(*) FROM checks GROUP BY level").fetchall())
        avg = conn.execute("SELECT AVG(score) FROM checks").fetchone()[0]
        recent = conn.execute(
            "SELECT host, level, score, created_at FROM checks ORDER BY id DESC LIMIT 10"
        ).fetchall()
        top = conn.execute(
            "SELECT host, COUNT(*) c FROM checks GROUP BY host ORDER BY c DESC LIMIT 5"
        ).fetchall()
    return {
        "total": total,
        "safe": by_level.get("safe", 0),
        "warn": by_level.get("warn", 0),
        "bad": by_level.get("bad", 0),
        "avg": round(avg) if avg is not None else 0,
        "recent": recent,
        "top": top,
    }