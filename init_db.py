import sqlite3, os
os.makedirs('logs', exist_ok=True)
conn = sqlite3.connect('logs/attacks.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    ip TEXT,
    username TEXT,
    password TEXT,
    filename TEXT,
    endpoint TEXT,
    user_agent TEXT,
    timestamp TEXT
)
''')
conn.commit()
conn.close()
print("Database created at logs/attacks.db")
