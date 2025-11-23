#!/usr/bin/env python3

import os
import sqlite3
import json
import tarfile
import base64
from datetime import datetime, timedelta

# Конфігурація
OUTPUT_DIR = "generated"
ARCHIVE_NAME = "browser_data.tar.gz"
FLAG = "FLAG{br0ws3r_f0r3ns1cs_tr4ck5_3v3ryth1ng}"
FLAG_B64 = base64.b64encode(FLAG.encode()).decode()

def chrome_timestamp(dt):
    """
    Конвертує datetime у Chrome timestamp
    Chrome використовує мікросекунди з 1 січня 1601 року
    """
    epoch_start = datetime(1601, 1, 1)
    delta = dt - epoch_start
    return int(delta.total_seconds() * 1000000)

def create_history_database(temp_dir):
    """Створює History базу даних"""
    print("[*] Creating History database...")

    db_path = os.path.join(temp_dir, "History")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Створити таблиці (спрощена версія Chrome History)
    cursor.execute('''
        CREATE TABLE urls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE visits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE downloads(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_path TEXT NOT NULL,
            tab_url TEXT,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER,
            total_bytes INTEGER
        )
    ''')

    # Додати нормальні URL
    base_time = datetime(2024, 12, 10, 10, 0, 0)

    normal_sites = [
        ("https://www.google.com/", "Google", 50),
        ("https://www.youtube.com/", "YouTube", 30),
        ("https://github.com/", "GitHub", 25),
        ("https://stackoverflow.com/", "Stack Overflow", 20),
        ("https://www.reddit.com/", "Reddit", 15),
        ("https://www.wikipedia.org/", "Wikipedia", 10),
        ("https://www.amazon.com/", "Amazon", 8),
        ("https://www.facebook.com/", "Facebook", 5),
        ("https://twitter.com/", "Twitter", 5),
        ("https://www.linkedin.com/", "LinkedIn", 3),
    ]

    print("  [+] Adding normal browsing history...")
    for i, (url, title, visit_count) in enumerate(normal_sites):
        visit_time = chrome_timestamp(base_time + timedelta(hours=i))
        cursor.execute(
            'INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)',
            (url, title, visit_count, visit_time)
        )

    # Додати ПІДОЗРІЛІ сайти з прапором
    print("  [+] Adding suspicious sites with FLAG...")

    suspicious_sites = [
        (f"https://evil-domain.com/data?secret={FLAG_B64}", "Secret Page", 1),
        ("https://suspicious-site.com/login?session=abc123def456", "Login Portal", 2),
        ("https://malware-download.net/files", "Download Center", 1),
        ("https://phishing-bank.com/secure/login", "Bank Login", 1),
        (f"https://hacker-forum.onion/thread?id=1337&token={FLAG_B64[:30]}", "Dark Web Forum", 1),
    ]

    for i, (url, title, visit_count) in enumerate(suspicious_sites):
        visit_time = chrome_timestamp(base_time + timedelta(hours=12 + i))
        cursor.execute(
            'INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)',
            (url, title, visit_count, visit_time)
        )

    # Додати downloads
    downloads = [
        ("/home/user/Downloads/report.pdf", "https://github.com/user/repo", 1024000),
        ("/home/user/Downloads/suspicious.exe", "https://malware-download.net/files", 2048000),
    ]

    for target_path, tab_url, total_bytes in downloads:
        start_time = chrome_timestamp(base_time + timedelta(hours=15))
        cursor.execute(
            'INSERT INTO downloads (target_path, tab_url, start_time, received_bytes, total_bytes) VALUES (?, ?, ?, ?, ?)',
            (target_path, tab_url, start_time, total_bytes, total_bytes)
        )

    conn.commit()
    conn.close()

    print("  [✓] History database created")
    return db_path

def create_cookies_database(temp_dir):
    """Створює Cookies базу даних"""
    print("[*] Creating Cookies database...")

    db_path = os.path.join(temp_dir, "Cookies")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Створити таблицю (спрощена версія)
    cursor.execute('''
        CREATE TABLE cookies(
            creation_utc INTEGER NOT NULL,
            host_key TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            path TEXT NOT NULL,
            expires_utc INTEGER NOT NULL,
            is_secure INTEGER NOT NULL,
            is_httponly INTEGER NOT NULL,
            last_access_utc INTEGER NOT NULL,
            has_expires INTEGER NOT NULL DEFAULT 1,
            is_persistent INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 1
        )
    ''')

    # Додати нормальні cookies
    base_time = datetime(2024, 12, 10, 10, 0, 0)
    creation = chrome_timestamp(base_time)
    expires = chrome_timestamp(base_time + timedelta(days=365))

    normal_cookies = [
        (".google.com", "CONSENT", "YES+cb.20240101-07-p0.en+FX+410"),
        (".github.com", "logged_in", "yes"),
        (".stackoverflow.com", "prov", "12345678-1234-1234-1234-123456789012"),
        (".reddit.com", "session_tracker", "abcdef123456"),
    ]

    print("  [+] Adding normal cookies...")
    for host, name, value in normal_cookies:
        cursor.execute(
            '''INSERT INTO cookies
            (creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (creation, host, name, value, "/", expires, 1, 0, creation)
        )

    # Додати ПІДОЗРІЛІ cookies з частиною прапора
    print("  [+] Adding suspicious cookies...")
    suspicious_cookies = [
        ("evil-domain.com", "session_token_b64", f"{FLAG_B64[:35]}"),
        ("evil-domain.com", "user_id", "admin_1337"),
        ("suspicious-site.com", "auth", "Bearer_abc123def456"),
        ("malware-download.net", "tracker", "track_12345"),
    ]

    for host, name, value in suspicious_cookies:
        cursor.execute(
            '''INSERT INTO cookies
            (creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (creation, host, name, value, "/", expires, 0, 0, creation)
        )

    conn.commit()
    conn.close()

    print("  [✓] Cookies database created")
    return db_path

def create_bookmarks(temp_dir):
    """Створює bookmarks.json файл"""
    print("[*] Creating bookmarks...")

    bookmarks_path = os.path.join(temp_dir, "bookmarks.json")

    bookmarks = {
        "checksum": "abc123def456",
        "roots": {
            "bookmark_bar": {
                "children": [
                    {"name": "Google", "type": "url", "url": "https://www.google.com/"},
                    {"name": "GitHub", "type": "url", "url": "https://github.com/"},
                    {
                        "name": "Work",
                        "type": "folder",
                        "children": [
                            {"name": "Email", "type": "url", "url": "https://mail.google.com/"},
                            {"name": "Docs", "type": "url", "url": "https://docs.google.com/"},
                        ]
                    },
                    {
                        "name": "Suspicious",
                        "type": "folder",
                        "children": [
                            {"name": "Secret", "type": "url", "url": f"https://evil-domain.com/bookmark?data={FLAG_B64}"},
                            {"name": "Hidden", "type": "url", "url": "https://hacker-forum.onion/"},
                        ]
                    }
                ],
                "name": "Bookmarks Bar",
                "type": "folder"
            },
            "other": {"children": [], "name": "Other Bookmarks", "type": "folder"},
            "synced": {"children": [], "name": "Mobile Bookmarks", "type": "folder"}
        },
        "version": 1
    }

    with open(bookmarks_path, 'w') as f:
        json.dump(bookmarks, f, indent=2)

    print("  [✓] Bookmarks created")
    return bookmarks_path

def create_archive(temp_dir):
    """Створює tar.gz архів"""
    print("[*] Creating archive...")

    archive_path = os.path.join(OUTPUT_DIR, ARCHIVE_NAME)

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(temp_dir, arcname="browser_data")

    print(f"  [✓] Archive created: {archive_path}")
    return archive_path

def main():
    print("=" * 50)
    print("Task 17: Browser Forensics - Generator")
    print("=" * 50)
    print()

    # Створити директорії
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Тимчасова директорія для браузерних даних
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp()

    try:
        # Створити бази даних
        history_path = create_history_database(temp_dir)
        cookies_path = create_cookies_database(temp_dir)
        bookmarks_path = create_bookmarks(temp_dir)

        # Створити архів
        archive_path = create_archive(temp_dir)

        print()
        print("[+] Browser data generated successfully!")
        print(f"[+] Archive: {archive_path}")
        print(f"[+] Archive size: {os.path.getsize(archive_path)} bytes")
        print()
        print(f"[*] Flag hidden in (base64 encoded):")
        print(f"    - History URL: {FLAG}")
        print(f"    - Cookies: {FLAG_B64[:35]}")
        print(f"    - Bookmarks: https://evil-domain.com/bookmark?data={FLAG_B64}")
        print()
        print("[*] To solve:")
        print(f"    tar -xzf {ARCHIVE_NAME}")
        print("    cd browser_data")
        print("    strings History (look for base64)")
        print("    # or")
        print('    sqlite3 History "SELECT url FROM urls WHERE url LIKE \'%evil%\';"')
        print("    # then decode: echo '<base64>' | base64 -d")
        print(f"[!] TIP: strings won't show readable FLAG!")
        print(f"[!] FLAG is base64 encoded in URLs, cookies, and bookmarks")
        print()
        print("[✓] Generation complete!")

    finally:
        # Очистити тимчасові файли
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
