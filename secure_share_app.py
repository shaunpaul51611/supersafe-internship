from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    X,
    Y,
    BooleanVar,
    StringVar,
    Tk,
    filedialog,
    messagebox,
    ttk,
)
import tkinter as tk

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from pqcrypto.kem import ml_kem_768

    CRYPTO_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - used for a friendly runtime error.
    CRYPTO_IMPORT_ERROR = exc


APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "secure_share.db"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,24}$")
APP_ISSUER = "Quantum Safe Share"
RESERVED_ECHO_USERNAME = "__secure_echo__"
RESERVED_ECHO_EMAIL = "secure-echo@quantum-safe.local"
RESERVED_ECHO_NAME = "Secure Echo"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
NONCE_SIZE = 12


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def from_b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def require_crypto() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Missing crypto dependencies. Run: pip install -r requirements.txt"
        ) from CRYPTO_IMPORT_ERROR


def normalize_username(username: str) -> str:
    return username.strip()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_reserved_username(username: str) -> bool:
    return normalize_username(username).lower() == RESERVED_ECHO_USERNAME.lower()


def is_reserved_email(email: str) -> bool:
    return normalize_email(email) == RESERVED_ECHO_EMAIL.lower()


def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Usernames must be 3-32 characters: letters, numbers, _, ., -")
    if is_reserved_username(username):
        raise ValueError("That username is reserved for the built-in secure echo test.")


def validate_email(email: str) -> None:
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    if is_reserved_email(email):
        raise ValueError("That email is reserved for the built-in secure echo test.")


def derive_user_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    require_crypto()
    kdf = Scrypt(salt=salt, length=64, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def password_verifier(username: str, auth_key: bytes) -> bytes:
    return hmac.new(
        auth_key,
        b"secure-share-auth-v1:" + username.lower().encode("utf-8"),
        hashlib.sha256,
    ).digest()


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    require_crypto()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    require_crypto()
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_json(key: bytes, payload: dict, aad: bytes) -> tuple[bytes, bytes]:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return aes_encrypt(key, raw, aad)


def decrypt_json(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> dict:
    raw = aes_decrypt(key, nonce, ciphertext, aad)
    return json.loads(raw.decode("utf-8"))


def derive_file_wrap_key(shared_secret: bytes, salt: bytes, sender: str, recipient: str) -> bytes:
    require_crypto()
    info = f"secure-share-file-key-v1|{sender.lower()}|{recipient.lower()}".encode(
        "utf-8"
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def crypto_label() -> str:
    return "ML-KEM-768 (CRYSTALS-Kyber) + AES-256-GCM"


@dataclass
class CurrentUser:
    id: int
    username: str
    email: str
    vault_key: bytes
    kem_public_key: bytes
    kem_secret_key: bytes


class SecureStore:
    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode = TRUNCATE")
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_schema()

    def create_schema(self) -> None:
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

            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                entry_nonce BLOB NOT NULL,
                entry_ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

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
        self.migrate_schema()
        self.conn.commit()

    def migrate_schema(self) -> None:
        columns = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(users)").fetchall()
        }
        migrations = [
            ("email", "ALTER TABLE users ADD COLUMN email TEXT"),
            (
                "is_system",
                "ALTER TABLE users ADD COLUMN is_system INTEGER NOT NULL DEFAULT 0",
            ),
        ]
        for column, statement in migrations:
            if column not in columns:
                self.conn.execute(statement)
        self.conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase
            ON users(email COLLATE NOCASE)
            WHERE email IS NOT NULL
            """
        )

    def close(self) -> None:
        self.conn.close()

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

    def get_user_by_id(self, user_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def create_user(self, username: str, email: str, password: str) -> CurrentUser:
        require_crypto()
        username = normalize_username(username)
        email = normalize_email(email)
        validate_username(username)
        validate_email(email)
        if len(password) < 10:
            raise ValueError("Use a master password of at least 10 characters.")
        if self.get_user_by_username(username):
            raise ValueError("That username is already taken.")
        if self.get_user_by_email(email):
            raise ValueError("That email is already connected to an account.")

        auth_salt = os.urandom(16)
        auth_key, vault_key = derive_user_keys(password, auth_salt)
        verifier = password_verifier(username, auth_key)
        kem_public_key, kem_secret_key = ml_kem_768.generate_keypair()
        kem_nonce, kem_ciphertext = aes_encrypt(
            vault_key,
            kem_secret_key,
            f"secure-share-kem-secret-v1:{username.lower()}".encode("utf-8"),
        )
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO users (
                    username, email, password_salt, password_verifier, kem_public_key,
                    kem_secret_key_nonce, kem_secret_key_ciphertext,
                    is_system, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    username,
                    email,
                    auth_salt,
                    verifier,
                    kem_public_key,
                    kem_nonce,
                    kem_ciphertext,
                    utc_now(),
                ),
            )
        return CurrentUser(
            id=cur.lastrowid,
            username=username,
            email=email,
            vault_key=vault_key,
            kem_public_key=kem_public_key,
            kem_secret_key=kem_secret_key,
        )

    def authenticate_password(self, identifier: str, password: str) -> CurrentUser:
        require_crypto()
        row = self.get_user_by_login(identifier)
        if not row:
            raise ValueError("Invalid username/email or password.")
        if row["is_system"]:
            raise ValueError("That reserved account is not available for sign in.")

        auth_key, vault_key = derive_user_keys(password, row["password_salt"])
        expected = password_verifier(row["username"], auth_key)
        if not hmac.compare_digest(expected, row["password_verifier"]):
            raise ValueError("Invalid username/email or password.")

        aad = f"secure-share-kem-secret-v1:{row['username'].lower()}".encode("utf-8")
        try:
            kem_secret_key = aes_decrypt(
                vault_key,
                row["kem_secret_key_nonce"],
                row["kem_secret_key_ciphertext"],
                aad,
            )
        except InvalidTag as exc:
            raise ValueError("Unable to unlock this account.") from exc

        return CurrentUser(
            id=row["id"],
            username=row["username"],
            email=row["email"] or "",
            vault_key=vault_key,
            kem_public_key=row["kem_public_key"],
            kem_secret_key=kem_secret_key,
        )

    def ensure_reserved_echo_user(self) -> sqlite3.Row:
        require_crypto()
        existing = self.get_user_by_username(RESERVED_ECHO_USERNAME)
        if existing:
            if not existing["is_system"]:
                raise ValueError("Reserved echo username already exists as a normal user.")
            return existing

        vault_key = os.urandom(32)
        auth_salt = os.urandom(16)
        kem_public_key, kem_secret_key = ml_kem_768.generate_keypair()
        kem_nonce, kem_ciphertext = aes_encrypt(
            vault_key,
            kem_secret_key,
            f"secure-share-kem-secret-v1:{RESERVED_ECHO_USERNAME.lower()}".encode(
                "utf-8"
            ),
        )
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO users (
                    username, email, password_salt, password_verifier, kem_public_key,
                    kem_secret_key_nonce, kem_secret_key_ciphertext,
                    is_system, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    RESERVED_ECHO_USERNAME,
                    RESERVED_ECHO_EMAIL,
                    auth_salt,
                    os.urandom(32),
                    kem_public_key,
                    kem_nonce,
                    kem_ciphertext,
                    utc_now(),
                ),
            )
        return self.get_user_by_username(RESERVED_ECHO_USERNAME)

    def add_vault_entry(self, user: CurrentUser, payload: dict) -> None:
        aad = f"secure-share-vault-v1:{user.username.lower()}".encode("utf-8")
        nonce, ciphertext = encrypt_json(user.vault_key, payload, aad)
        now = utc_now()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO vault_entries (user_id, entry_nonce, entry_ciphertext, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user.id, nonce, ciphertext, now, now),
            )

    def delete_vault_entry(self, user_id: int, entry_id: int) -> None:
        with self.conn:
            self.conn.execute(
                "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
                (entry_id, user_id),
            )

    def list_vault_entries(self, user_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT * FROM vault_entries
                WHERE user_id = ?
                ORDER BY updated_at DESC, id DESC
                """,
                (user_id,),
            )
        )

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

    def send_friend_request(self, requester_id: int, target_username: str) -> str:
        target_username = normalize_username(target_username)
        target = self.get_user_by_username(target_username)
        if not target:
            raise ValueError("No user exists with that username.")
        if target["is_system"]:
            raise ValueError("That username is reserved for the built-in secure echo test.")
        if target["id"] == requester_id:
            raise ValueError("You cannot friend yourself.")

        existing = self.find_relationship(requester_id, target["id"])
        now = utc_now()
        if existing:
            if existing["status"] == "accepted":
                return f"You and {target['username']} are already friends."
            if existing["status"] == "pending" and existing["addressee_id"] == requester_id:
                self.respond_to_friend_request(existing["id"], requester_id, "accepted")
                return f"You accepted {target['username']}'s friend request."
            if existing["status"] == "pending":
                return f"Friend request to {target['username']} is already pending."
            with self.conn:
                self.conn.execute(
                    """
                    UPDATE friend_requests
                    SET requester_id = ?, addressee_id = ?, status = 'pending',
                        created_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (requester_id, target["id"], now, now, existing["id"]),
                )
            return f"Friend request sent to {target['username']}."

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO friend_requests (requester_id, addressee_id, status, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?)
                """,
                (requester_id, target["id"], now, now),
            )
        return f"Friend request sent to {target['username']}."

    def respond_to_friend_request(self, request_id: int, user_id: int, status: str) -> None:
        if status not in {"accepted", "rejected"}:
            raise ValueError("Invalid friend request status.")
        with self.conn:
            cur = self.conn.execute(
                """
                UPDATE friend_requests
                SET status = ?, updated_at = ?
                WHERE id = ? AND addressee_id = ? AND status = 'pending'
                """,
                (status, utc_now(), request_id, user_id),
            )
        if cur.rowcount == 0:
            raise ValueError("Friend request was already handled.")

    def list_incoming_requests(self, user_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT fr.*, u.username AS requester_username
                FROM friend_requests fr
                JOIN users u ON u.id = fr.requester_id
                WHERE fr.addressee_id = ? AND fr.status = 'pending'
                ORDER BY fr.created_at DESC
                """,
                (user_id,),
            )
        )

    def list_outgoing_requests(self, user_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT fr.*, u.username AS addressee_username
                FROM friend_requests fr
                JOIN users u ON u.id = fr.addressee_id
                WHERE fr.requester_id = ? AND fr.status = 'pending'
                ORDER BY fr.created_at DESC
                """,
                (user_id,),
            )
        )

    def list_friends(self, user_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
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
            )
        )

    def are_friends(self, left_id: int, right_id: int) -> bool:
        row = self.find_relationship(left_id, right_id)
        return bool(row and row["status"] == "accepted")

    def create_file_transfer(
        self,
        sender: CurrentUser,
        recipient_id: int,
        source_path: Path,
    ) -> int:
        return self.create_file_transfer_bytes(
            sender,
            recipient_id,
            source_path.name,
            source_path.read_bytes(),
        )

    def create_file_transfer_bytes(
        self,
        sender: CurrentUser,
        recipient_id: int,
        original_name: str,
        file_data: bytes,
    ) -> int:
        require_crypto()
        recipient = self.get_user_by_id(recipient_id)
        if not recipient:
            raise ValueError("Recipient no longer exists.")
        if not self.are_friends(sender.id, recipient_id):
            raise ValueError("Files can only be shared with accepted friends.")

        file_key = os.urandom(32)
        file_aad = (
            f"secure-share-file-v1|{sender.username.lower()}|"
            f"{recipient['username'].lower()}|{original_name}"
        ).encode("utf-8")
        file_nonce, file_ciphertext = aes_encrypt(file_key, file_data, file_aad)

        kem_ciphertext, shared_secret = ml_kem_768.encrypt(recipient["kem_public_key"])
        wrap_salt = os.urandom(16)
        wrap_key = derive_file_wrap_key(
            shared_secret,
            wrap_salt,
            sender.username,
            recipient["username"],
        )
        wrap_aad = (
            f"secure-share-wrap-v1|{sender.username.lower()}|"
            f"{recipient['username'].lower()}|{original_name}"
        ).encode("utf-8")
        wrap_nonce, wrapped_file_key = aes_encrypt(wrap_key, file_key, wrap_aad)

        with self.conn:
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
                    sender.id,
                    recipient_id,
                    original_name,
                    len(file_data),
                    file_nonce,
                    file_ciphertext,
                    kem_ciphertext,
                    wrap_salt,
                    wrap_nonce,
                    wrapped_file_key,
                    utc_now(),
                ),
            )
        return cur.lastrowid

    def ensure_echo_friendship(self, user_id: int) -> sqlite3.Row:
        echo = self.ensure_reserved_echo_user()
        existing = self.find_relationship(user_id, echo["id"])
        if existing and existing["status"] == "accepted":
            return echo
        now = utc_now()
        with self.conn:
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
        return echo

    def run_echo_transfer_test(
        self,
        user: CurrentUser,
        original_name: str = "secure-echo-test.txt",
        file_data: bytes | None = None,
    ) -> int:
        echo = self.ensure_echo_friendship(user.id)
        payload = file_data or (
            f"Secure echo test for {user.username} at {utc_now()}\n"
            f"Encryption: {crypto_label()}\n"
        ).encode("utf-8")
        self.create_file_transfer_bytes(
            user,
            echo["id"],
            f"outbound-{original_name}",
            payload,
        )
        echo_sender = CurrentUser(
            id=echo["id"],
            username=echo["username"],
            email=echo["email"] or RESERVED_ECHO_EMAIL,
            vault_key=b"",
            kem_public_key=echo["kem_public_key"],
            kem_secret_key=b"",
        )
        return self.create_file_transfer_bytes(
            echo_sender,
            user.id,
            f"echo-{original_name}",
            payload,
        )

    def list_received_files(self, user_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT ft.*, u.username AS sender_username
                FROM file_transfers ft
                JOIN users u ON u.id = ft.sender_id
                WHERE ft.recipient_id = ?
                ORDER BY ft.created_at DESC, ft.id DESC
                """,
                (user_id,),
            )
        )

    def decrypt_received_file(self, user: CurrentUser, transfer_id: int) -> tuple[str, bytes]:
        require_crypto()
        transfer = self.conn.execute(
            """
            SELECT ft.*, sender.username AS sender_username, recipient.username AS recipient_username
            FROM file_transfers ft
            JOIN users sender ON sender.id = ft.sender_id
            JOIN users recipient ON recipient.id = ft.recipient_id
            WHERE ft.id = ? AND ft.recipient_id = ?
            """,
            (transfer_id, user.id),
        ).fetchone()
        if not transfer:
            raise ValueError("File transfer not found.")

        shared_secret = ml_kem_768.decrypt(user.kem_secret_key, transfer["kem_ciphertext"])
        wrap_key = derive_file_wrap_key(
            shared_secret,
            transfer["wrap_salt"],
            transfer["sender_username"],
            transfer["recipient_username"],
        )
        wrap_aad = (
            f"secure-share-wrap-v1|{transfer['sender_username'].lower()}|"
            f"{transfer['recipient_username'].lower()}|{transfer['original_name']}"
        ).encode("utf-8")
        file_key = aes_decrypt(
            wrap_key,
            transfer["wrap_nonce"],
            transfer["wrapped_file_key"],
            wrap_aad,
        )
        file_aad = (
            f"secure-share-file-v1|{transfer['sender_username'].lower()}|"
            f"{transfer['recipient_username'].lower()}|{transfer['original_name']}"
        ).encode("utf-8")
        plaintext = aes_decrypt(
            file_key,
            transfer["file_nonce"],
            transfer["file_ciphertext"],
            file_aad,
        )
        with self.conn:
            self.conn.execute(
                "UPDATE file_transfers SET downloaded_at = ? WHERE id = ?",
                (utc_now(), transfer_id),
            )
        return transfer["original_name"], plaintext


class SecureShareApp(Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Quantum Safe Share")
        self.geometry("1120x760")
        self.minsize(980, 680)
        self.store = SecureStore()
        self.current_user: CurrentUser | None = None
        self.dark_mode = BooleanVar(value=True)
        self.current_view = "login"
        self.selected_file = StringVar(value="")
        self.friend_choice = StringVar(value="")
        self.vault_entries: list[tuple[int, dict]] = []
        self.inbox_entries: list[sqlite3.Row] = []
        self.colors: dict[str, str] = {}
        self.style = ttk.Style(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.apply_theme()
        self.show_login()

    def apply_theme(self) -> None:
        if self.dark_mode.get():
            self.colors = {
                "bg": "#080809",
                "panel": "#141012",
                "panel_alt": "#251217",
                "text": "#fff7f7",
                "muted": "#b9a9ad",
                "accent": "#ff3158",
                "accent_alt": "#4d0f1a",
                "border": "#3a1b24",
                "input": "#100c0e",
                "button_text": "#fff7f7",
                "danger": "#ff6b6b",
                "good": "#21c875",
            }
        else:
            self.colors = {
                "bg": "#f6fbf7",
                "panel": "#ffffff",
                "panel_alt": "#e9f7ee",
                "text": "#0c1c12",
                "muted": "#5d6f62",
                "accent": "#128a46",
                "accent_alt": "#d8f4e2",
                "border": "#bddfc9",
                "input": "#ffffff",
                "button_text": "#ffffff",
                "danger": "#b42318",
                "good": "#139948",
            }
        self.configure(bg=self.colors["bg"])
        self.style.theme_use("clam")
        self.style.configure(
            "Treeview",
            background=self.colors["panel"],
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            rowheight=32,
        )
        self.style.configure(
            "Treeview.Heading",
            background=self.colors["panel_alt"],
            foreground=self.colors["text"],
            relief="flat",
        )
        self.style.map(
            "Treeview",
            background=[("selected", self.colors["accent"])],
            foreground=[("selected", self.colors["button_text"])],
        )
        self.style.configure(
            "TCombobox",
            fieldbackground=self.colors["input"],
            background=self.colors["input"],
            foreground=self.colors["text"],
            arrowcolor=self.colors["accent"],
        )

    def on_close(self) -> None:
        self.store.close()
        self.destroy()

    def reset_content(self) -> tk.Frame:
        for child in self.winfo_children():
            child.destroy()
        self.apply_theme()
        root = tk.Frame(self, bg=self.colors["bg"])
        root.pack(fill=BOTH, expand=True)
        return root

    def card(self, parent: tk.Widget, padx: int = 24, pady: int = 24) -> tk.Frame:
        frame = tk.Frame(
            parent,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["border"],
            highlightthickness=1,
            padx=padx,
            pady=pady,
        )
        return frame

    def label(
        self,
        parent: tk.Widget,
        text: str,
        size: int = 11,
        weight: str = "normal",
        muted: bool = False,
        wraplength: int = 0,
    ) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            font=("Segoe UI", size, weight),
            fg=self.colors["muted"] if muted else self.colors["text"],
            bg=parent.cget("bg"),
            anchor="w",
            justify="left",
            wraplength=wraplength,
        )

    def entry(self, parent: tk.Widget, show: str = "") -> tk.Entry:
        return tk.Entry(
            parent,
            show=show,
            font=("Segoe UI", 11),
            fg=self.colors["text"],
            bg=self.colors["input"],
            insertbackground=self.colors["accent"],
            relief="flat",
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
            highlightthickness=1,
        )

    def text_box(self, parent: tk.Widget, height: int = 4) -> tk.Text:
        return tk.Text(
            parent,
            height=height,
            font=("Segoe UI", 10),
            fg=self.colors["text"],
            bg=self.colors["input"],
            insertbackground=self.colors["accent"],
            relief="flat",
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
            highlightthickness=1,
            wrap="word",
        )

    def button(
        self,
        parent: tk.Widget,
        text: str,
        command,
        primary: bool = False,
        danger: bool = False,
    ) -> tk.Button:
        bg = self.colors["accent"] if primary else self.colors["panel_alt"]
        fg = self.colors["button_text"] if primary else self.colors["text"]
        if danger:
            bg = self.colors["danger"]
            fg = "#ffffff"
        return tk.Button(
            parent,
            text=text,
            command=command,
            font=("Segoe UI", 10, "bold"),
            fg=fg,
            bg=bg,
            activebackground=self.colors["accent"],
            activeforeground=self.colors["button_text"],
            relief="flat",
            borderwidth=0,
            padx=14,
            pady=9,
            cursor="hand2",
        )

    def stat_tile(self, parent: tk.Widget, title: str, value: str) -> tk.Frame:
        tile = tk.Frame(
            parent,
            bg=self.colors["panel_alt"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            padx=14,
            pady=12,
        )
        self.label(tile, value, 18, "bold").pack(anchor="w")
        self.label(tile, title, 9, muted=True).pack(anchor="w", pady=(4, 0))
        return tile

    def section_title(self, parent: tk.Widget, title: str, subtitle: str = "") -> None:
        self.label(parent, title, 18, "bold").pack(anchor="w")
        if subtitle:
            self.label(parent, subtitle, 10, muted=True, wraplength=720).pack(
                anchor="w", pady=(4, 0)
            )

    def top_bar(self, parent: tk.Widget, title: str) -> tk.Frame:
        bar = tk.Frame(parent, bg=self.colors["bg"], padx=28, pady=18)
        bar.pack(fill=X)
        left = tk.Frame(bar, bg=self.colors["bg"])
        left.pack(side=LEFT, fill=X, expand=True)
        self.label(left, title, size=20, weight="bold").pack(anchor="w")
        subtitle = crypto_label()
        if self.current_user:
            subtitle = f"{self.current_user.email}  |  {crypto_label()}"
        self.label(left, subtitle, size=10, muted=True).pack(anchor="w", pady=(4, 0))
        mode_text = "Light mode" if self.dark_mode.get() else "Dark mode"
        self.button(bar, mode_text, self.toggle_theme).pack(side=RIGHT, padx=(8, 0))
        if self.current_user:
            self.button(bar, "Sign out", self.logout).pack(side=RIGHT, padx=(8, 0))
        return bar

    def toggle_theme(self) -> None:
        self.dark_mode.set(not self.dark_mode.get())
        if self.current_user:
            self.show_dashboard(self.current_view)
        elif self.current_view == "register":
            self.show_register()
        else:
            self.show_login()

    def show_login(self) -> None:
        self.current_view = "login"
        root = self.reset_content()
        self.top_bar(root, "Quantum Safe Share")
        body = tk.Frame(root, bg=self.colors["bg"], padx=28, pady=18)
        body.pack(fill=BOTH, expand=True)

        left = tk.Frame(body, bg=self.colors["bg"])
        left.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 20))
        self.label(left, "Friends, encrypted files, and secure return.", 28, "bold", wraplength=560).pack(
            anchor="w", pady=(60, 18)
        )
        metrics = tk.Frame(left, bg=self.colors["bg"])
        metrics.pack(fill=X, pady=(0, 20))
        self.stat_tile(metrics, "file exchange", "Kyber + AES").pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self.stat_tile(metrics, "account lock", "Master password").pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self.stat_tile(metrics, "sharing rule", "Friends only").pack(side=LEFT, fill=X, expand=True)
        self.label(
            left,
            f"Reserved test sender: {RESERVED_ECHO_NAME}. Normal users cannot claim its username.",
            11,
            muted=True,
            wraplength=560,
        ).pack(anchor="w")

        form = self.card(body, padx=34, pady=34)
        form.pack(side=RIGHT, fill=Y, ipadx=30)
        self.label(form, "Sign in", 22, "bold").pack(anchor="w", pady=(0, 18))

        self.label(form, "Username or email", 10, muted=True).pack(anchor="w")
        identifier_entry = self.entry(form)
        identifier_entry.pack(fill=X, pady=(5, 14), ipady=8)
        self.label(form, "Master password", 10, muted=True).pack(anchor="w")
        password_entry = self.entry(form, show="*")
        password_entry.pack(fill=X, pady=(5, 10), ipady=8)
        show_password = BooleanVar(value=False)

        def toggle_login_password() -> None:
            password_entry.configure(show="" if show_password.get() else "*")

        tk.Checkbutton(
            form,
            text="Show password",
            variable=show_password,
            command=toggle_login_password,
            font=("Segoe UI", 10),
            fg=self.colors["muted"],
            bg=form.cget("bg"),
            activebackground=form.cget("bg"),
            activeforeground=self.colors["text"],
            selectcolor=self.colors["input"],
        ).pack(anchor="w", pady=(0, 18))

        def do_login() -> None:
            try:
                self.current_user = self.store.authenticate_password(
                    identifier_entry.get(),
                    password_entry.get(),
                )
                self.show_dashboard("friends")
            except Exception as exc:
                password_entry.delete(0, END)
                messagebox.showerror("Sign in failed", str(exc))

        self.button(form, "Unlock account", do_login, primary=True).pack(fill=X, pady=(0, 10))
        self.button(form, "Create an account", self.show_register).pack(fill=X)
        identifier_entry.focus_set()
        password_entry.bind("<Return>", lambda _event: do_login())

    def show_register(self) -> None:
        self.current_view = "register"
        root = self.reset_content()
        self.top_bar(root, "Create Account")
        body = tk.Frame(root, bg=self.colors["bg"], padx=28, pady=18)
        body.pack(fill=BOTH, expand=True)
        form = self.card(body, padx=34, pady=34)
        form.pack(anchor="center", ipadx=58, ipady=10)
        self.label(form, "Create secure account", 22, "bold").pack(anchor="w", pady=(0, 18))

        self.label(form, "Username", 10, muted=True).pack(anchor="w")
        username_entry = self.entry(form)
        username_entry.pack(fill=X, pady=(5, 12), ipady=8)
        self.label(form, "Email", 10, muted=True).pack(anchor="w")
        email_entry = self.entry(form)
        email_entry.pack(fill=X, pady=(5, 12), ipady=8)
        self.label(form, "Master password", 10, muted=True).pack(anchor="w")
        password_entry = self.entry(form, show="*")
        password_entry.pack(fill=X, pady=(5, 12), ipady=8)
        self.label(form, "Confirm password", 10, muted=True).pack(anchor="w")
        confirm_entry = self.entry(form, show="*")
        confirm_entry.pack(fill=X, pady=(5, 10), ipady=8)
        show_passwords = BooleanVar(value=False)

        def toggle_register_passwords() -> None:
            mask = "" if show_passwords.get() else "*"
            password_entry.configure(show=mask)
            confirm_entry.configure(show=mask)

        tk.Checkbutton(
            form,
            text="Show passwords",
            variable=show_passwords,
            command=toggle_register_passwords,
            font=("Segoe UI", 10),
            fg=self.colors["muted"],
            bg=form.cget("bg"),
            activebackground=form.cget("bg"),
            activeforeground=self.colors["text"],
            selectcolor=self.colors["input"],
        ).pack(anchor="w", pady=(0, 18))

        def do_register() -> None:
            if password_entry.get() != confirm_entry.get():
                password_entry.delete(0, END)
                confirm_entry.delete(0, END)
                messagebox.showerror("Account not created", "Passwords do not match.")
                return
            try:
                new_user = self.store.create_user(
                    username_entry.get(),
                    email_entry.get(),
                    password_entry.get(),
                )
                self.current_user = None
                messagebox.showinfo(
                    "Account created",
                    f"Your account for {new_user.email} is ready. Sign in with your password.",
                )
                self.show_login()
            except Exception as exc:
                password_entry.delete(0, END)
                confirm_entry.delete(0, END)
                messagebox.showerror("Account not created", str(exc))

        self.button(form, "Create account", do_register, primary=True).pack(fill=X, pady=(0, 10))
        self.button(form, "Back to sign in", self.show_login).pack(fill=X)
        username_entry.focus_set()
        confirm_entry.bind("<Return>", lambda _event: do_register())

    def logout(self) -> None:
        self.current_user = None
        self.show_login()

    def show_dashboard(self, view: str = "friends") -> None:
        if not self.current_user:
            self.show_login()
            return
        self.current_view = view
        root = self.reset_content()
        self.top_bar(root, f"Signed in as {self.current_user.username}")
        shell = tk.Frame(root, bg=self.colors["bg"], padx=28, pady=8)
        shell.pack(fill=BOTH, expand=True)

        nav = tk.Frame(shell, bg=self.colors["bg"], width=180)
        nav.pack(side=LEFT, fill=Y, padx=(0, 18))
        stats = tk.Frame(nav, bg=self.colors["bg"])
        stats.pack(fill=X, pady=(0, 12))
        self.stat_tile(
            stats,
            "friends",
            str(len(self.store.list_friends(self.current_user.id))),
        ).pack(fill=X, pady=(0, 8))
        self.stat_tile(
            stats,
            "inbox files",
            str(len(self.store.list_received_files(self.current_user.id))),
        ).pack(fill=X)

        for label, target in [
            ("Friends", "friends"),
            ("Share File", "share"),
            ("Inbox", "inbox"),
        ]:
            self.button(
                nav,
                label,
                lambda target=target: self.show_dashboard(target),
                primary=(target == view),
            ).pack(fill=X, pady=(0, 10))

        content = self.card(shell, padx=26, pady=26)
        content.pack(side=LEFT, fill=BOTH, expand=True)
        if view == "friends":
            self.render_friends(content)
        elif view == "share":
            self.render_share(content)
        elif view == "inbox":
            self.render_inbox(content)
        else:
            self.show_dashboard("friends")

    def render_vault(self, parent: tk.Frame) -> None:
        assert self.current_user
        header = tk.Frame(parent, bg=parent.cget("bg"))
        header.pack(fill=X)
        self.section_title(header, "Password Vault", "Saved passwords are encrypted with your account vault key.")

        layout = tk.Frame(parent, bg=parent.cget("bg"))
        layout.pack(fill=BOTH, expand=True, pady=(20, 0))
        list_side = tk.Frame(layout, bg=parent.cget("bg"))
        list_side.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 18))
        form_side = tk.Frame(layout, bg=parent.cget("bg"), width=320)
        form_side.pack(side=RIGHT, fill=Y)

        columns = ("service", "login", "updated")
        tree = ttk.Treeview(list_side, columns=columns, show="headings", height=13)
        tree.heading("service", text="Service")
        tree.heading("login", text="Login")
        tree.heading("updated", text="Updated")
        tree.column("service", width=220)
        tree.column("login", width=180)
        tree.column("updated", width=170)
        tree.pack(fill=BOTH, expand=True)

        self.vault_entries = []
        aad = f"secure-share-vault-v1:{self.current_user.username.lower()}".encode("utf-8")
        for row in self.store.list_vault_entries(self.current_user.id):
            try:
                payload = decrypt_json(
                    self.current_user.vault_key,
                    row["entry_nonce"],
                    row["entry_ciphertext"],
                    aad,
                )
            except Exception:
                payload = {
                    "service": "Unable to decrypt",
                    "login": "",
                    "password": "",
                    "notes": "",
                }
            self.vault_entries.append((row["id"], payload))
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    payload.get("service", ""),
                    payload.get("login", ""),
                    row["updated_at"].replace("T", " "),
                ),
            )

        def selected_entry() -> tuple[int, dict] | None:
            selection = tree.selection()
            if not selection:
                return None
            entry_id = int(selection[0])
            return next((entry for entry in self.vault_entries if entry[0] == entry_id), None)

        def reveal() -> None:
            entry = selected_entry()
            if not entry:
                messagebox.showinfo("Vault", "Select an entry first.")
                return
            payload = entry[1]
            details = (
                f"Service: {payload.get('service', '')}\n"
                f"Login: {payload.get('login', '')}\n"
                f"Password: {payload.get('password', '')}\n\n"
                f"Notes:\n{payload.get('notes', '')}"
            )
            messagebox.showinfo("Vault entry", details)

        def delete() -> None:
            entry = selected_entry()
            if not entry:
                messagebox.showinfo("Vault", "Select an entry first.")
                return
            if messagebox.askyesno("Delete entry", "Delete this saved password?"):
                self.store.delete_vault_entry(self.current_user.id, entry[0])
                self.show_dashboard("vault")

        actions = tk.Frame(list_side, bg=parent.cget("bg"))
        actions.pack(fill=X, pady=(12, 0))
        self.button(actions, "Reveal", reveal, primary=True).pack(side=LEFT, padx=(0, 10))
        self.button(actions, "Delete", delete, danger=True).pack(side=LEFT)

        self.label(form_side, "Add Password", 16, "bold").pack(anchor="w", pady=(0, 14))
        self.label(form_side, "Service", 10, muted=True).pack(anchor="w")
        service = self.entry(form_side)
        service.pack(fill=X, pady=(4, 10), ipady=7)
        self.label(form_side, "Login", 10, muted=True).pack(anchor="w")
        login = self.entry(form_side)
        login.pack(fill=X, pady=(4, 10), ipady=7)
        self.label(form_side, "Password", 10, muted=True).pack(anchor="w")
        password = self.entry(form_side)
        password.pack(fill=X, pady=(4, 10), ipady=7)
        self.label(form_side, "Notes", 10, muted=True).pack(anchor="w")
        notes = self.text_box(form_side, height=5)
        notes.pack(fill=X, pady=(4, 14))

        def add_entry() -> None:
            if not service.get().strip() or not password.get():
                messagebox.showerror("Vault", "Service and password are required.")
                return
            self.store.add_vault_entry(
                self.current_user,
                {
                    "service": service.get().strip(),
                    "login": login.get().strip(),
                    "password": password.get(),
                    "notes": notes.get("1.0", END).strip(),
                },
            )
            self.show_dashboard("vault")

        self.button(form_side, "Save password", add_entry, primary=True).pack(fill=X)

    def render_friends(self, parent: tk.Frame) -> None:
        assert self.current_user
        self.section_title(parent, "Friends", "Only accepted friends can receive encrypted files.")
        add_bar = tk.Frame(parent, bg=parent.cget("bg"))
        add_bar.pack(fill=X, pady=(18, 20))
        self.label(add_bar, "Friend username", 10, muted=True).pack(anchor="w")
        target_entry = self.entry(add_bar)
        target_entry.pack(side=LEFT, fill=X, expand=True, ipady=8, padx=(0, 10), pady=(4, 0))

        def send_request() -> None:
            try:
                msg = self.store.send_friend_request(self.current_user.id, target_entry.get())
                messagebox.showinfo("Friends", msg)
                self.show_dashboard("friends")
            except Exception as exc:
                messagebox.showerror("Friends", str(exc))

        self.button(add_bar, "Add friend", send_request, primary=True).pack(side=RIGHT)

        columns = ("username", "email")
        friends = ttk.Treeview(parent, columns=columns, show="headings", height=6)
        friends.heading("username", text="Accepted friends")
        friends.heading("email", text="Email")
        friends.column("username", width=240)
        friends.column("email", width=320)
        friends.pack(fill=X, pady=(0, 20))
        for friend in self.store.list_friends(self.current_user.id):
            friends.insert("", END, values=(friend["username"], friend["email"] or ""))

        requests = tk.Frame(parent, bg=parent.cget("bg"))
        requests.pack(fill=BOTH, expand=True)
        incoming = tk.Frame(requests, bg=parent.cget("bg"))
        incoming.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 18))
        outgoing = tk.Frame(requests, bg=parent.cget("bg"))
        outgoing.pack(side=RIGHT, fill=BOTH, expand=True)

        self.label(incoming, "Incoming Requests", 14, "bold").pack(anchor="w", pady=(0, 10))
        incoming_rows = self.store.list_incoming_requests(self.current_user.id)
        if not incoming_rows:
            self.label(incoming, "No pending requests.", 10, muted=True).pack(anchor="w")
        for row in incoming_rows:
            req = tk.Frame(
                incoming,
                bg=self.colors["panel_alt"],
                padx=12,
                pady=10,
                highlightbackground=self.colors["border"],
                highlightthickness=1,
            )
            req.pack(fill=X, pady=(0, 8))
            self.label(req, row["requester_username"], 11, "bold").pack(side=LEFT)
            self.button(
                req,
                "Accept",
                lambda request_id=row["id"]: self.handle_friend_response(request_id, "accepted"),
                primary=True,
            ).pack(side=RIGHT, padx=(8, 0))
            self.button(
                req,
                "Reject",
                lambda request_id=row["id"]: self.handle_friend_response(request_id, "rejected"),
            ).pack(side=RIGHT)

        self.label(outgoing, "Outgoing Requests", 14, "bold").pack(anchor="w", pady=(0, 10))
        outgoing_rows = self.store.list_outgoing_requests(self.current_user.id)
        if not outgoing_rows:
            self.label(outgoing, "No sent requests waiting.", 10, muted=True).pack(anchor="w")
        for row in outgoing_rows:
            req = tk.Frame(
                outgoing,
                bg=self.colors["panel_alt"],
                padx=12,
                pady=10,
                highlightbackground=self.colors["border"],
                highlightthickness=1,
            )
            req.pack(fill=X, pady=(0, 8))
            self.label(req, row["addressee_username"], 11, "bold").pack(side=LEFT)
            self.label(req, "pending", 10, muted=True).pack(side=RIGHT)

    def handle_friend_response(self, request_id: int, status: str) -> None:
        assert self.current_user
        try:
            self.store.respond_to_friend_request(request_id, self.current_user.id, status)
            self.show_dashboard("friends")
        except Exception as exc:
            messagebox.showerror("Friends", str(exc))

    def render_share(self, parent: tk.Frame) -> None:
        assert self.current_user
        self.section_title(
            parent,
            "Share File",
            f"{crypto_label()} protects the payload before it lands in a friend's inbox.",
        )

        friends = self.store.list_friends(self.current_user.id)
        friend_map = {friend["username"]: friend["id"] for friend in friends}
        if friends:
            self.friend_choice.set(friends[0]["username"])
        else:
            self.friend_choice.set("")

        form = tk.Frame(parent, bg=parent.cget("bg"))
        form.pack(fill=X, pady=(20, 0))
        self.label(form, "Recipient", 10, muted=True).pack(anchor="w")
        combo = ttk.Combobox(
            form,
            textvariable=self.friend_choice,
            values=list(friend_map.keys()),
            state="readonly",
            font=("Segoe UI", 11),
        )
        combo.pack(fill=X, pady=(5, 14), ipady=6)

        selected_label = self.label(form, "No file selected", 10, muted=True)
        selected_label.pack(anchor="w", pady=(0, 12))

        def choose_file() -> None:
            filename = filedialog.askopenfilename(title="Choose a file to encrypt and share")
            if filename:
                self.selected_file.set(filename)
                selected_label.configure(text=filename)

        def send_file() -> None:
            if not friend_map:
                messagebox.showerror("Share File", "Add and accept a friend first.")
                return
            if not self.selected_file.get():
                messagebox.showerror("Share File", "Choose a file first.")
                return
            try:
                recipient_id = friend_map[self.friend_choice.get()]
                self.store.create_file_transfer(
                    self.current_user,
                    recipient_id,
                    Path(self.selected_file.get()),
                )
                self.selected_file.set("")
                messagebox.showinfo("Share File", "Encrypted file sent to your friend's inbox.")
                self.show_dashboard("inbox")
            except Exception as exc:
                messagebox.showerror("Share File", str(exc))

        buttons = tk.Frame(form, bg=parent.cget("bg"))
        buttons.pack(fill=X)
        self.button(buttons, "Choose file", choose_file).pack(side=LEFT, padx=(0, 10))
        self.button(buttons, "Encrypt and send", send_file, primary=True).pack(side=LEFT)

        echo_panel = tk.Frame(
            parent,
            bg=self.colors["panel_alt"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            padx=18,
            pady=16,
        )
        echo_panel.pack(fill=X, pady=(26, 0))
        self.label(echo_panel, RESERVED_ECHO_NAME, 15, "bold").pack(anchor="w")
        self.label(
            echo_panel,
            "Run a private loopback transfer from the reserved internal sender.",
            10,
            muted=True,
        ).pack(anchor="w", pady=(4, 12))

        def run_echo_test() -> None:
            try:
                if self.selected_file.get():
                    source = Path(self.selected_file.get())
                    transfer_id = self.store.run_echo_transfer_test(
                        self.current_user,
                        source.name,
                        source.read_bytes(),
                    )
                else:
                    transfer_id = self.store.run_echo_transfer_test(self.current_user)
                messagebox.showinfo(
                    "Secure Echo",
                    f"Encrypted echo file returned to your inbox. Transfer #{transfer_id}.",
                )
                self.show_dashboard("inbox")
            except Exception as exc:
                messagebox.showerror("Secure Echo", str(exc))

        self.button(echo_panel, "Run echo test", run_echo_test, primary=True).pack(anchor="w")

    def render_inbox(self, parent: tk.Frame) -> None:
        assert self.current_user
        self.section_title(parent, "Inbox", "Decrypt received files when you are ready to save them.")
        columns = ("name", "sender", "size", "received", "status")
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=14)
        tree.heading("name", text="File")
        tree.heading("sender", text="Sender")
        tree.heading("size", text="Bytes")
        tree.heading("received", text="Received")
        tree.heading("status", text="Status")
        tree.column("name", width=260)
        tree.column("sender", width=130)
        tree.column("size", width=90)
        tree.column("received", width=190)
        tree.column("status", width=120)
        tree.pack(fill=BOTH, expand=True, pady=(18, 12))

        self.inbox_entries = self.store.list_received_files(self.current_user.id)
        for row in self.inbox_entries:
            sender_name = (
                RESERVED_ECHO_NAME
                if row["sender_username"] == RESERVED_ECHO_USERNAME
                else row["sender_username"]
            )
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    row["original_name"],
                    sender_name,
                    row["file_size"],
                    row["created_at"].replace("T", " "),
                    "saved" if row["downloaded_at"] else "new",
                ),
            )

        def save_selected() -> None:
            selection = tree.selection()
            if not selection:
                messagebox.showinfo("Inbox", "Select a file first.")
                return
            transfer_id = int(selection[0])
            try:
                original_name, data = self.store.decrypt_received_file(
                    self.current_user,
                    transfer_id,
                )
                target = filedialog.asksaveasfilename(initialfile=original_name)
                if not target:
                    return
                Path(target).write_bytes(data)
                messagebox.showinfo("Inbox", f"Decrypted and saved {original_name}.")
                self.show_dashboard("inbox")
            except Exception as exc:
                messagebox.showerror("Inbox", str(exc))

        self.button(parent, "Decrypt and save", save_selected, primary=True).pack(anchor="w")


def main() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        root = Tk()
        root.withdraw()
        messagebox.showerror(
            "Missing dependencies",
            "Install the required crypto packages first:\n\npip install -r requirements.txt",
        )
        root.destroy()
        return
    app = SecureShareApp()
    app.mainloop()


if __name__ == "__main__":
    main()
