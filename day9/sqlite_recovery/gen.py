#!/usr/bin/env python3
"""
Task 16: Database Forensics - Generator
Створює SQLite базу з видаленими записами що містять прапор
"""

import os
import sqlite3
import random
import base64
from datetime import datetime, timedelta

# Конфігурація
OUTPUT_DIR = "generated"
DB_FILE = "database.db"
SCHEMA_FILE = "schema.txt"
FLAG = "FLAG{sql1t3_n3v3r_f0rg3ts}"
FLAG_B64 = base64.b64encode(FLAG.encode()).decode()

def generate_database():
    """Створює SQLite базу даних"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    db_path = os.path.join(OUTPUT_DIR, DB_FILE)

    # Видалити стару базу якщо є
    if os.path.exists(db_path):
        os.remove(db_path)



    print(f"[*] Creating SQLite database: {db_path}")

    # Підключитися до бази
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Створити таблиці
    cursor.execute("PRAGMA journal_mode=DELETE;")
    cursor.execute("PRAGMA secure_delete = OFF;")
    cursor.execute("PRAGMA secure_delete;")

    conn.commit()

    try:
        for row in cursor.execute("PRAGMA compile_options;"):
            print("compile_option:", row[0])
    except Exception as e:
        print("Не вдалося виконати PRAGMA compile_options:", e)


    print("[1/5] Creating tables...")

    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')

    # Додати нормальні записи
    print("[2/5] Inserting normal users...")

    normal_users = [
        ('john', 'john@example.com'),
        ('alice', 'alice@example.com'),
        ('bob', 'bob@example.com'),
    ]

    base_date = datetime(2024, 12, 10)
    for i, (username, email) in enumerate(normal_users):
        date = (base_date + timedelta(days=i)).strftime('%Y-%m-%d')
        print(f'INSERT INTO users (username, email, created_at) VALUES ({username, email, date})')
        cursor.execute(
            'INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)',
            (username, email, date)
        )

    # Додати SECRET запис з прапором (який буде видалено)
    print("[3/5] Inserting secret record (to be deleted)...")

    secret_date = (base_date + timedelta(days=3)).strftime('%Y-%m-%d')
    print(f'INSERT INTO users (username, email, created_at) VALUES (admin_secret, {FLAG_B64}@secret.local, secret_date)')
    cursor.execute(
        'INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)',
        ('admin_secret', f'{FLAG_B64}@secret.local', secret_date)
    )

    cursor.execute(
        'INSERT INTO secrets (key, value, created_at) VALUES (?, ?, ?)',
        ('flag_b64', FLAG_B64, secret_date)
    )

    cursor.execute(
        'INSERT INTO secrets (key, value, created_at) VALUES (?, ?, ?)',
        ('api_key', 'sk_live_1234567890', secret_date)
    )

    # Додати логи
    print("[4/5] Adding activity logs...")

    actions = ['login', 'logout', 'view_profile', 'update_settings']
    for user_id in range(1, 4):
        for j in range(random.randint(3, 8)):
            timestamp = (base_date + timedelta(days=random.randint(0, 5),
                                              hours=random.randint(0, 23))).strftime('%Y-%m-%d %H:%M:%S')
            action = random.choice(actions)
            print(f'INSERT INTO logs (user_id, action, timestamp, details) VALUES ("{user_id}", "{action}", "{timestamp}", "User performed {action}");')
            cursor.execute(
                'INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, ?, ?)',
                (user_id, action, timestamp, f'User performed {action}')
            )

    # Додати один лог для admin_secret (який також буде видалено)
    admin_timestamp = (base_date + timedelta(days=3, hours=14)).strftime('%Y-%m-%d %H:%M:%S')
    print(f'INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, ?, ?)')
    cursor.execute(
        'INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, ?, ?)',
        (4, 'access_flag', admin_timestamp, f'Admin accessed: {FLAG_B64} (base64)')
    )

    # Зберегти зміни
    conn.commit()

    # ВИДАЛИТИ секретні записи (але вони залишаться у файлі!)
    print("[5/5] Deleting secret records (physical data remains!)...")

    cursor.execute('DELETE FROM users WHERE username = "admin_secret"')
    cursor.execute('DELETE FROM secrets WHERE key = "flag"')
    cursor.execute('DELETE FROM logs WHERE action = "access_flag"')

    conn.commit()

    # НЕ робити VACUUM - це видалить дані фізично!
    # conn.execute('VACUUM')  # <-- NOT DOING THIS!

    conn.close()

    return db_path

def save_schema_info():
    """Зберігає інформацію про структуру бази"""
    schema_path = os.path.join(OUTPUT_DIR, SCHEMA_FILE)

    schema_info = """Database Schema Information
=============================

Tables:
-------

1. users
   - id (INTEGER PRIMARY KEY)
   - username (TEXT)
   - email (TEXT)
   - created_at (TEXT)

2. logs
   - id (INTEGER PRIMARY KEY)
   - user_id (INTEGER)
   - action (TEXT)
   - timestamp (TEXT)
   - details (TEXT)

3. secrets
   - id (INTEGER PRIMARY KEY)
   - key (TEXT)
   - value (TEXT)
   - created_at (TEXT)

Notes:
------
- Some records have been deleted from the database
- Deleted records may still exist in free pages
- Use forensics tools to recover deleted data

Hints:
------
- Try: strings database.db (look for base64 encoded data)
- Try: sqlite3 database.db ".dump" | grep -i flag
- Look for free pages in the database file
- Check if there are -wal or -journal files
- FLAG is base64 encoded - decode what you find!
"""

    with open(schema_path, 'w') as f:
        f.write(schema_info)

    return schema_path

def main():
    print("=" * 50)
    print("Task 16: Database Forensics - Generator")
    print("=" * 50)
    print()

    # Створити базу
    db_path = generate_database()

    # Зберегти схему
    schema_path = save_schema_info()

    # Статистика
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM users')
    users_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM logs')
    logs_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM secrets')
    secrets_count = cursor.fetchone()[0]

    conn.close()

    print()
    print("[+] Database created successfully!")
    print(f"[+] Database: {db_path}")
    print(f"[+] Schema: {schema_path}")
    print(f"[+] File size: {os.path.getsize(db_path)} bytes")
    print()
    print(f"[*] Visible records:")
    print(f"    Users: {users_count}")
    print(f"    Logs: {logs_count}")
    print(f"    Secrets: {secrets_count}")
    print()
    print(f"[*] Flag: {FLAG}")
    print("[*] Flag was DELETED but still in free pages!")
    print()
    print("[*] To solve:")
    print(f"    strings {db_path} (look for base64 data)")
    print("    # or")
    print(f"    sqlite3 {db_path} 'SELECT * FROM users;'")
    print(f"    xxd {db_path} | grep -i flag")
    print("    # then decode: echo '<base64>' | base64 -d")
    print()
    print("[!] The flag was deleted with DELETE command")
    print("[!] VACUUM was NOT run, so data still exists physically")
    print("[!] This is a common mistake in database forensics")
    print(f"[!] TIP: strings won't show readable FLAG!")
    print(f"[!] FLAG is base64 encoded in deleted records")
    print()
    print("[✓] Generation complete!")

if __name__ == "__main__":
    main()
