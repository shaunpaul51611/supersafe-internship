from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from pqcrypto.kem import ml_kem_768


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = get_app_dir()
SERVER_DB_PATH = APP_DIR / "secure_share_server.db"
MAX_REQUEST_BYTES = 100 * 1024 * 1024

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,24}$")
RESERVED_ECHO_USERNAME = "__secure_echo__"
RESERVED_ECHO_EMAIL = "secure-echo@quantum-safe.local"

USER_KEY_FIELDS = [
    "password_salt",
    "password_verifier",
    "kem_public_key",
    "kem_secret_key_nonce",
    "kem_secret_key_ciphertext",
]
TRANSFER_BYTE_FIELDS = [
    "file_nonce",
    "file_ciphertext",
    "kem_ciphertext",
    "wrap_salt",
    "wrap_nonce",
    "wrapped_file_key",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def from_b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def normalize_username(username: str) -> str:
    return username.strip()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Usernames must be 3-32 characters: letters, numbers, _, ., -")
    if username.lower() == RESERVED_ECHO_USERNAME.lower():
        raise ValueError("That username is reserved for the built-in secure echo test.")


def validate_email(email: str) -> None:
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    if email.lower() == RESERVED_ECHO_EMAIL.lower():
        raise ValueError("That email is reserved for the built-in secure echo test.")


def encode_row(row: sqlite3.Row, byte_fields: list[str]) -> dict:
    payload = dict(row)
    for field in byte_fields:
        if field in payload and payload[field] is not None:
            payload[field] = b64(payload[field])
    return payload


def decode_payload(payload: dict, byte_fields: list[str]) -> dict:
    decoded = dict(payload)
    for field in byte_fields:
        if field in decoded and isinstance(decoded[field], str):
            decoded[field] = from_b64(decoded[field])
    return decoded


class SecureShareServerStore:
    def __init__(self, db_path: Path = SERVER_DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode = TRUNCATE")
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.lock = threading.RLock()
        self.sessions: dict[str, int] = {}
        self.create_schema()

    def create_schema(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    email TEXT UNIQUE COLLATE NOCASE,
                    password_salt BLOB NOT NULL,
                    password_verifier BLOB NOT NULL,
                    kem_public_key BLOB NOT NULL,
                    kem_secret_key_nonce BLOB NOT NULL,
                    kem_secret_key_ciphertext BLOB NOT NULL,
                    is_system INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase
                ON users(email COLLATE NOCASE)
                WHERE email IS NOT NULL;

                CREATE TABLE IF NOT EXISTS friend_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requester_id INTEGER NOT NULL,
                    addressee_id INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'accepted', 'rejected')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(requester_id, addressee_id),
                    FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(addressee_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS file_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_nonce BLOB NOT NULL,
                    file_ciphertext BLOB NOT NULL,
                    kem_ciphertext BLOB NOT NULL,
                    wrap_salt BLOB NOT NULL,
                    wrap_nonce BLOB NOT NULL,
                    wrapped_file_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    downloaded_at TEXT,
                    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def get_user_by_id(self, user_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def get_user_by_username(self, username: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

    def get_user_by_email(self, email: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
            (normalize_email(email),),
        ).fetchone()

    def get_user_by_login(self, identifier: str) -> sqlite3.Row | None:
        identifier = identifier.strip()
        if "@" in identifier:
            return self.get_user_by_email(identifier)
        return self.get_user_by_username(identifier)

    def public_user(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "kem_public_key": b64(row["kem_public_key"]),
            "is_system": row["is_system"],
            "created_at": row["created_at"],
        }

    def auth_user(self, row: sqlite3.Row) -> dict:
        return encode_row(row, USER_KEY_FIELDS)

    def session_user_id(self, token: str) -> int | None:
        return self.sessions.get(token)

    def create_user(self, payload: dict) -> dict:
        username = normalize_username(payload.get("username", ""))
        email = normalize_email(payload.get("email", ""))
        validate_username(username)
        validate_email(email)
        if self.get_user_by_username(username):
            raise ValueError("That username is already taken.")
        if self.get_user_by_email(email):
            raise ValueError("That email is already connected to an account.")
        decoded = decode_payload(payload, USER_KEY_FIELDS)
        now = utc_now()
        with self.lock:
            cur = self.conn.execute(
                """
                INSERT INTO users (
                    username, email, password_salt, password_verifier, kem_public_key,
                    kem_secret_key_nonce, kem_secret_key_ciphertext, is_system, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    username,
                    email,
                    decoded["password_salt"],
                    decoded["password_verifier"],
                    decoded["kem_public_key"],
                    decoded["kem_secret_key_nonce"],
                    decoded["kem_secret_key_ciphertext"],
                    now,
                ),
            )
            self.conn.commit()
        return {"id": cur.lastrowid, "username": username, "email": email}

    def auth_lookup(self, identifier: str) -> dict:
        row = self.get_user_by_login(identifier)
        if not row or row["is_system"]:
            raise PermissionError("Invalid username/email or password.")
        return {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "password_salt": b64(row["password_salt"]),
        }

    def auth_login(self, identifier: str, verifier: bytes) -> dict:
        row = self.get_user_by_login(identifier)
        if not row or row["is_system"]:
            raise PermissionError("Invalid username/email or password.")
        if not secrets.compare_digest(verifier, row["password_verifier"]):
            raise PermissionError("Invalid username/email or password.")
        token = secrets.token_urlsafe(32)
        self.sessions[token] = row["id"]
        return {"session_token": token, "user": self.auth_user(row)}

    def find_relationship(self, left_id: int, right_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM friend_requests
            WHERE (requester_id = ? AND addressee_id = ?)
               OR (requester_id = ? AND addressee_id = ?)
            ORDER BY id DESC
            LIMIT 1
            """,
            (left_id, right_id, right_id, left_id),
        ).fetchone()

    def are_friends(self, left_id: int, right_id: int) -> bool:
        row = self.find_relationship(left_id, right_id)
        return bool(row and row["status"] == "accepted")

    def send_friend_request(self, requester_id: int, target_username: str) -> str:
        target = self.get_user_by_username(normalize_username(target_username))
        if not target:
            raise ValueError("No user exists with that username.")
        if target["is_system"]:
            raise ValueError("That username is reserved for the built-in secure echo test.")
        if target["id"] == requester_id:
            raise ValueError("You cannot friend yourself.")
        existing = self.find_relationship(requester_id, target["id"])
        now = utc_now()
        with self.lock:
            if existing:
                if existing["status"] == "accepted":
                    return f"You and {target['username']} are already friends."
                if existing["status"] == "pending" and existing["addressee_id"] == requester_id:
                    self.respond_to_friend_request(existing["id"], requester_id, "accepted")
                    return f"You accepted {target['username']}'s friend request."
                if existing["status"] == "pending":
                    return f"Friend request to {target['username']} is already pending."
                self.conn.execute(
                    """
                    UPDATE friend_requests
                    SET requester_id = ?, addressee_id = ?, status = 'pending',
                        created_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (requester_id, target["id"], now, now, existing["id"]),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO friend_requests (
                        requester_id, addressee_id, status, created_at, updated_at
                    )
                    VALUES (?, ?, 'pending', ?, ?)
                    """,
                    (requester_id, target["id"], now, now),
                )
            self.conn.commit()
        return f"Friend request sent to {target['username']}."

    def respond_to_friend_request(self, request_id: int, user_id: int, status: str) -> None:
        if status not in {"accepted", "rejected"}:
            raise ValueError("Invalid friend request status.")
        with self.lock:
            cur = self.conn.execute(
                """
                UPDATE friend_requests
                SET status = ?, updated_at = ?
                WHERE id = ? AND addressee_id = ? AND status = 'pending'
                """,
                (status, utc_now(), request_id, user_id),
            )
            self.conn.commit()
        if cur.rowcount == 0:
            raise ValueError("Friend request was already handled.")

    def list_incoming_requests(self, user_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT fr.*, u.username AS requester_username
            FROM friend_requests fr
            JOIN users u ON u.id = fr.requester_id
            WHERE fr.addressee_id = ? AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_outgoing_requests(self, user_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT fr.*, u.username AS addressee_username
            FROM friend_requests fr
            JOIN users u ON u.id = fr.addressee_id
            WHERE fr.requester_id = ? AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_friends(self, user_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT u.*
            FROM friend_requests fr
            JOIN users u ON u.id = CASE
                WHEN fr.requester_id = ? THEN fr.addressee_id
                ELSE fr.requester_id
            END
            WHERE fr.status = 'accepted'
              AND (fr.requester_id = ? OR fr.addressee_id = ?)
              AND u.is_system = 0
            ORDER BY u.username COLLATE NOCASE
            """,
            (user_id, user_id, user_id),
        ).fetchall()
        return [self.public_user(row) for row in rows]

    def insert_transfer(self, sender_id: int, recipient_id: int, payload: dict) -> int:
        decoded = decode_payload(payload, TRANSFER_BYTE_FIELDS)
        with self.lock:
            cur = self.conn.execute(
                """
                INSERT INTO file_transfers (
                    sender_id, recipient_id, original_name, file_size,
                    file_nonce, file_ciphertext, kem_ciphertext, wrap_salt,
                    wrap_nonce, wrapped_file_key, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sender_id,
                    recipient_id,
                    decoded["original_name"],
                    decoded["file_size"],
                    decoded["file_nonce"],
                    decoded["file_ciphertext"],
                    decoded["kem_ciphertext"],
                    decoded["wrap_salt"],
                    decoded["wrap_nonce"],
                    decoded["wrapped_file_key"],
                    utc_now(),
                ),
            )
            self.conn.commit()
        return cur.lastrowid

    def list_inbox(self, user_id: int, include_ciphertext: bool = False) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT ft.*, sender.username AS sender_username, recipient.username AS recipient_username
            FROM file_transfers ft
            JOIN users sender ON sender.id = ft.sender_id
            JOIN users recipient ON recipient.id = ft.recipient_id
            WHERE ft.recipient_id = ?
            ORDER BY ft.created_at DESC, ft.id DESC
            """,
            (user_id,),
        ).fetchall()
        if include_ciphertext:
            return [encode_row(row, TRANSFER_BYTE_FIELDS) for row in rows]
        metadata_keys = {
            "id",
            "sender_id",
            "recipient_id",
            "original_name",
            "file_size",
            "created_at",
            "downloaded_at",
            "sender_username",
            "recipient_username",
        }
        return [{key: row[key] for key in metadata_keys} for row in rows]

    def get_transfer_for_recipient(self, transfer_id: int, recipient_id: int) -> dict:
        row = self.conn.execute(
            """
            SELECT ft.*, sender.username AS sender_username, recipient.username AS recipient_username
            FROM file_transfers ft
            JOIN users sender ON sender.id = ft.sender_id
            JOIN users recipient ON recipient.id = ft.recipient_id
            WHERE ft.id = ? AND ft.recipient_id = ?
            """,
            (transfer_id, recipient_id),
        ).fetchone()
        if not row:
            raise ValueError("File transfer not found.")
        return encode_row(row, TRANSFER_BYTE_FIELDS)

    def mark_downloaded(self, transfer_id: int, recipient_id: int) -> None:
        with self.lock:
            self.conn.execute(
                """
                UPDATE file_transfers
                SET downloaded_at = ?
                WHERE id = ? AND recipient_id = ?
                """,
                (utc_now(), transfer_id, recipient_id),
            )
            self.conn.commit()

    def ensure_echo_user(self) -> sqlite3.Row:
        existing = self.get_user_by_username(RESERVED_ECHO_USERNAME)
        if existing:
            return existing
        public_key, secret_key = ml_kem_768.generate_keypair()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO users (
                    username, email, password_salt, password_verifier, kem_public_key,
                    kem_secret_key_nonce, kem_secret_key_ciphertext, is_system, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    RESERVED_ECHO_USERNAME,
                    RESERVED_ECHO_EMAIL,
                    os.urandom(16),
                    os.urandom(32),
                    public_key,
                    os.urandom(12),
                    secret_key,
                    utc_now(),
                ),
            )
            self.conn.commit()
        return self.get_user_by_username(RESERVED_ECHO_USERNAME)

    def ensure_echo_friendship(self, user_id: int) -> sqlite3.Row:
        echo = self.ensure_echo_user()
        existing = self.find_relationship(user_id, echo["id"])
        if existing and existing["status"] == "accepted":
            return echo
        now = utc_now()
        with self.lock:
            if existing:
                self.conn.execute(
                    """
                    UPDATE friend_requests
                    SET requester_id = ?, addressee_id = ?, status = 'accepted',
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (echo["id"], user_id, now, existing["id"]),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO friend_requests (
                        requester_id, addressee_id, status, created_at, updated_at
                    )
                    VALUES (?, ?, 'accepted', ?, ?)
                    """,
                    (echo["id"], user_id, now, now),
                )
            self.conn.commit()
        return echo


class SecureShareHandler(BaseHTTPRequestHandler):
    server: "SecureShareHTTPServer"

    def do_GET(self) -> None:
        self.route("GET")

    def do_POST(self) -> None:
        self.route("POST")

    def route(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.strip("/")
            parts = path.split("/") if path else []
            store = self.server.store

            if method == "GET" and path == "health":
                self.send_json({"ok": True})
                return

            if method == "POST" and path == "users":
                self.send_json(store.create_user(self.read_json()), status=201)
                return

            if method == "POST" and path == "auth/lookup":
                payload = self.read_json()
                self.send_json(store.auth_lookup(payload.get("identifier", "")))
                return

            if method == "POST" and path == "auth/login":
                payload = self.read_json()
                self.send_json(
                    store.auth_login(
                        payload.get("identifier", ""),
                        from_b64(payload.get("password_verifier", "")),
                    )
                )
                return

            user_id = self.require_user_id()

            if method == "GET" and len(parts) == 2 and parts[0] == "users":
                user = store.get_user_by_id(int(parts[1]))
                if not user:
                    raise ValueError("User not found.")
                self.send_json(store.public_user(user))
                return

            if method == "POST" and path == "friends/request":
                payload = self.read_json()
                message = store.send_friend_request(user_id, payload.get("target_username", ""))
                self.send_json({"message": message})
                return

            if method == "POST" and path == "friends/respond":
                payload = self.read_json()
                store.respond_to_friend_request(
                    int(payload.get("request_id", 0)),
                    user_id,
                    payload.get("status", ""),
                )
                self.send_json({"ok": True})
                return

            if method == "GET" and path == "friends/incoming":
                self.send_json(store.list_incoming_requests(user_id))
                return

            if method == "GET" and path == "friends/outgoing":
                self.send_json(store.list_outgoing_requests(user_id))
                return

            if method == "GET" and path == "friends":
                self.send_json(store.list_friends(user_id))
                return

            if method == "GET" and len(parts) == 4 and parts[:2] == ["friends", "check"]:
                self.send_json({"accepted": store.are_friends(int(parts[2]), int(parts[3]))})
                return

            if method == "POST" and path == "files/send":
                payload = self.read_json()
                recipient_id = int(payload.get("recipient_id", 0))
                if not store.are_friends(user_id, recipient_id):
                    raise ValueError("Files can only be shared with accepted friends.")
                transfer_id = store.insert_transfer(user_id, recipient_id, payload)
                self.send_json({"id": transfer_id}, status=201)
                return

            if method == "GET" and path == "files/inbox":
                self.send_json(store.list_inbox(user_id))
                return

            if method == "GET" and len(parts) == 2 and parts[0] == "files":
                self.send_json(store.get_transfer_for_recipient(int(parts[1]), user_id))
                return

            if method == "POST" and len(parts) == 3 and parts[0] == "files" and parts[2] == "downloaded":
                store.mark_downloaded(int(parts[1]), user_id)
                self.send_json({"ok": True})
                return

            if method == "POST" and path == "echo/friendship":
                echo = store.ensure_echo_friendship(user_id)
                self.send_json(store.public_user(echo))
                return

            if method == "POST" and path == "echo/return":
                echo = store.ensure_echo_friendship(user_id)
                transfer_id = store.insert_transfer(echo["id"], user_id, self.read_json())
                self.send_json({"id": transfer_id}, status=201)
                return

            self.send_json({"error": "Not found."}, status=404)
        except PermissionError as exc:
            self.send_json({"error": str(exc)}, status=401)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Server error: {exc}"}, status=500)

    def require_user_id(self) -> int:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise PermissionError("Missing session token.")
        user_id = self.server.store.session_user_id(header[len(prefix) :].strip())
        if not user_id:
            raise PermissionError("Invalid or expired session token.")
        return user_id

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        if length > MAX_REQUEST_BYTES:
            max_mb = MAX_REQUEST_BYTES // 1024 // 1024
            raise ValueError(f"Request is too large. Max request size is {max_mb} MB.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_json(self, payload: dict | list, status: int = 200) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        return


class SecureShareHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], store: SecureShareServerStore) -> None:
        super().__init__(address, SecureShareHandler)
        self.store = store


def main() -> None:
    host = os.getenv("SECURE_SHARE_HOST", "127.0.0.1")
    port = int(os.getenv("SECURE_SHARE_PORT", "8000"))
    store = SecureShareServerStore()
    server = SecureShareHTTPServer((host, port), store)
    print(f"Secure Share server running at http://{host}:{port}", flush=True)
    print(f"Database path: {SERVER_DB_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
