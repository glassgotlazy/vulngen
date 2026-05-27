"""
examples/sql_injection_demo.py
-------------------------------
Worked example: CWE-89 SQL Injection (Section VI-A of the paper).

Demonstrates how GPT-3.5-turbo (baseline prompt) generates a vulnerable
query function, and how the Combined hardening prompt produces a secure one.

Run: python examples/sql_injection_demo.py

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

# ---------------------------------------------------------------------------
# Vulnerable code — typical GPT-3.5-turbo baseline output
# (representative example matching paper Section VI-A)
# ---------------------------------------------------------------------------

VULNERABLE_CODE = '''
import sqlite3
from typing import Optional

def get_user(db_connection: sqlite3.Connection, username: str) -> Optional[dict]:
    """Retrieve a user record by username."""
    cursor = db_connection.cursor()
    # VULNERABLE: direct string interpolation — CWE-89
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    if row is None:
        return None
    columns = [description[0] for description in cursor.description]
    return dict(zip(columns, row))
'''

# ---------------------------------------------------------------------------
# Secure code — typical Combined-prompt (SP+CB+FSE) output
# ---------------------------------------------------------------------------

SECURE_CODE = '''
import sqlite3
import re
from typing import Optional

def get_user(db_connection: sqlite3.Connection, username: str) -> Optional[dict]:
    """
    Retrieve a user record by username using a parameterised query.

    Security controls applied:
      - Input validation: username must match [a-zA-Z0-9_] (max 64 chars)
      - Parameterised query: prevents CWE-89 SQL Injection
      - Explicit error handling: never exposes DB errors to caller
    """
    # Input validation — reject unexpected characters
    if not isinstance(username, str) or not re.fullmatch(r"[a-zA-Z0-9_]{1,64}", username):
        raise ValueError("Invalid username format")

    try:
        cursor = db_connection.cursor()
        # SECURE: parameterised placeholder — database driver escapes input
        cursor.execute(
            "SELECT id, username, email, created_at FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
    except sqlite3.Error as exc:
        # Log internally; never propagate raw DB errors
        raise RuntimeError("Database query failed") from exc

    if row is None:
        return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))
'''


# ---------------------------------------------------------------------------
# Demonstrate exploitation of the vulnerable version
# ---------------------------------------------------------------------------

def demonstrate_exploitation():
    """Show a classic SQL injection payload against the vulnerable function."""

    import sqlite3, tempfile, os

    # Set up a demo DB
    db_path = tempfile.mktemp(suffix=".db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
        "email TEXT, password_hash TEXT, created_at TEXT)"
    )
    conn.execute(
        "INSERT INTO users VALUES (1, 'alice', 'alice@example.com', "
        "'$2b$12$...', '2024-01-01')"
    )
    conn.execute(
        "INSERT INTO users VALUES (2, 'admin', 'admin@example.com', "
        "'$2b$12$...', '2024-01-01')"
    )
    conn.commit()

    # Patch exec into local scope for demo
    exec(compile(VULNERABLE_CODE, "<vulnerable>", "exec"), globals())
    get_user_vulnerable = globals()["get_user"]

    print("=" * 60)
    print("CWE-89 SQL Injection Demonstration (Section VI-A)")
    print("=" * 60)

    # Normal query
    result = get_user_vulnerable(conn, "alice")
    print(f"\n[Normal query] username='alice'\n  → {result}\n")

    # SQL injection payload
    payload = "' OR '1'='1"
    result = get_user_vulnerable(conn, payload)
    print(f"[Injection payload] username={payload!r}")
    print(f"  → {result}")
    print("  ↑ VULNERABLE: returns first row regardless of username!\n")

    conn.close()
    os.unlink(db_path)

    print("=" * 60)
    print("Secure version (Combined prompt output)")
    print("=" * 60)
    try:
        exec(compile(SECURE_CODE, "<secure>", "exec"), globals())
        get_user_secure = globals()["get_user"]
        db2 = sqlite3.connect(":memory:")
        db2.execute(
            "CREATE TABLE users (id INTEGER, username TEXT, email TEXT, created_at TEXT)"
        )
        db2.execute("INSERT INTO users VALUES (1,'alice','alice@example.com','2024-01-01')")
        db2.commit()
        result = get_user_secure(db2, "alice")
        print(f"\n[Normal query] username='alice'\n  → {result}")
        try:
            get_user_secure(db2, payload)
        except ValueError as e:
            print(f"\n[Injection payload] username={payload!r}")
            print(f"  → Rejected: {e}")
            print("  ↑ SECURE: input validation blocks the injection attempt.")
    finally:
        pass


if __name__ == "__main__":
    demonstrate_exploitation()
