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
            source TEXT,
            UNIQUE(target, endpoint, source)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS recon_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            tool TEXT,
            command TEXT,
            output_path TEXT,
            returncode INTEGER,
            stdout TEXT,
            stderr TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def save_endpoint(target: str, endpoint: str, source: str):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        '''
        INSERT OR IGNORE INTO endpoints (target, endpoint, source)
        VALUES (?, ?, ?)
        ''',
        (target, endpoint, source),
    )
    conn.commit()
    conn.close()


def save_recon_run(
    target: str,
    tool: str,
    command: str,
    output_path: str,
    returncode: int,
    stdout: str,
    stderr: str,
):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        '''
        INSERT INTO recon_runs (target, tool, command, output_path, returncode, stdout, stderr)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (target, tool, command, output_path, returncode, stdout, stderr),
    )
    conn.commit()
    conn.close()
