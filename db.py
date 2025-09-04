import sqlite3

DB_PATH = "bot_users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # جدول کاربران تلگرام
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bot_users (
        tg_id INTEGER PRIMARY KEY,
        fullname TEXT,
        username TEXT,
        last_seen INTEGER,
        last_notif INTEGER DEFAULT 0
    )
    """)

    # جدول نگاشت تلگرام ↔ UUID
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tg_id INTEGER,
        uuid TEXT,
        allow_ip INTEGER DEFAULT 1,
        FOREIGN KEY (tg_id) REFERENCES bot_users (tg_id)
    )
    """)

    conn.commit()
    conn.close()

def add_or_update_user(tg_id, username, fullname):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO bot_users (tg_id, fullname, username)
        VALUES (?, ?, ?)
    """, (tg_id, fullname, username))
    conn.commit()
    conn.close()
    return True

def update_last_seen(tg_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE bot_users 
        SET last_seen = strftime('%s','now')
        WHERE tg_id = ?
    """, (tg_id,))
    conn.commit()
    conn.close()

def get_last_seen(tg_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT last_seen FROM bot_users WHERE tg_id = ?", (tg_id,))
    row = cursor.fetchone()
    conn.close()
    return int(row[0]) if row and row[0] else None

# ---------------- last notification ----------------
def get_last_notification(tg_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT last_notif FROM bot_users WHERE tg_id = ?", (tg_id,))
    row = cursor.fetchone()
    conn.close()
    return int(row[0]) if row and row[0] else None

def update_last_notification(tg_id, timestamp):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE bot_users
        SET last_notif = ?
        WHERE tg_id = ?
    """, (timestamp, tg_id))
    conn.commit()
    conn.close()

# ---------------- subscriptions ----------------
def link_subscription(tg_id, uuid, allow_ip=1):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO subscriptions (tg_id, uuid, allow_ip) VALUES (?, ?, ?)", (tg_id, uuid, allow_ip))
    conn.commit()
    conn.close()

def remove_subscription(tg_id, uuid):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM subscriptions WHERE tg_id=? AND uuid=?", (tg_id, uuid))
    conn.commit()
    conn.close()

def get_user_subscriptions(tg_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT uuid FROM subscriptions WHERE tg_id = ?", (tg_id,))
    uuids = [row[0] for row in cursor.fetchall()]
    conn.close()
    return uuids

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT tg_id, uuid, allow_ip FROM subscriptions")
    rows = cursor.fetchall()
    conn.close()
    return [(tg_id, uuid, allow_ip) for tg_id, uuid, allow_ip in rows]
