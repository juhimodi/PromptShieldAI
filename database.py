import sqlite3


def init_db():

    conn = sqlite3.connect("prompts.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prompt TEXT,
        findings TEXT,
        score INTEGER,
        risk TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_log(prompt, findings, score, risk):

    conn = sqlite3.connect("prompts.db")

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs(prompt, findings, score, risk)
    VALUES (?, ?, ?, ?)
    """, (prompt, findings, score, risk))

    conn.commit()
    conn.close()