import sqlite3
from pathlib import Path

DB_PATH = Path('data/legion.db')


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    with connect() as conn:
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

        cur.execute('''
            CREATE TABLE IF NOT EXISTS endpoint_classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                endpoint TEXT,
                category TEXT,
                confidence TEXT,
                reason TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS auth_diffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                endpoint TEXT,
                risk TEXT,
                summary TEXT,
                signals TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS recon_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                phase TEXT,
                tool TEXT,
                file_path TEXT,
                line_count INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')


def insert_endpoint(target: str, endpoint: str, source: str):
    with connect() as conn:
        conn.execute(
            'INSERT INTO endpoints (target, endpoint, source) VALUES (?, ?, ?)',
            (target, endpoint, source),
        )


def insert_recon_artifact(target: str, phase: str, tool: str, file_path: str, line_count: int):
    with connect() as conn:
        conn.execute(
            'INSERT INTO recon_artifacts (target, phase, tool, file_path, line_count) VALUES (?, ?, ?, ?, ?)',
            (target, phase, tool, file_path, line_count),
        )

    cur.execute('''
        CREATE TABLE IF NOT EXISTS recon_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            phase TEXT,
            tool TEXT,
            file_path TEXT,
            line_count INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def insert_endpoint(target: str, endpoint: str, source: str):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO endpoints (target, endpoint, source) VALUES (?, ?, ?)',
        (target, endpoint, source),
    )
    conn.commit()
    conn.close()


def insert_recon_artifact(target: str, phase: str, tool: str, file_path: str, line_count: int):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO recon_artifacts (target, phase, tool, file_path, line_count) VALUES (?, ?, ?, ?, ?)',
        (target, phase, tool, file_path, line_count),
    )
    conn.commit()
    conn.close()
