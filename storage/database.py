import sqlite3
from pathlib import Path

DB_PATH = Path('data/legion.db')


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = connect()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            category TEXT,
            severity TEXT,
            summary TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            endpoint TEXT,
            source TEXT
        )
    ''')

    conn.commit()
    conn.close()
