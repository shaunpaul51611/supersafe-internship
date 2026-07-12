from __future__ import annotations

import os
from pathlib import Path

from secure_share_app import (
    RESERVED_ECHO_USERNAME,
    SecureStore,
)


def main() -> None:
    base = Path(".self_test_runs") / os.urandom(4).hex()
    base.mkdir(parents=True, exist_ok=True)
    store = SecureStore(base / "self_test.db")
    try:
        user = store.create_user(
            "test_user",
            "test.user@example.com",
            "correct horse battery staple",
        )
        unlocked = store.authenticate_password(
            "test.user@example.com",
            "correct horse battery staple",
        )
        try:
            store.create_user(
                RESERVED_ECHO_USERNAME,
                "not-allowed@example.com",
                "correct horse battery staple",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Reserved echo username was allowed.")

        returned_id = store.run_echo_transfer_test(
            unlocked,
            "roundtrip.txt",
            b"hello from the secure echo self-test",
        )
        original_name, decrypted = store.decrypt_received_file(unlocked, returned_id)

        assert original_name == "echo-roundtrip.txt"
        assert decrypted == b"hello from the secure echo self-test"
        print("self-test ok: email login, reserved username block, echo transfer")
    finally:
        store.close()


if __name__ == "__main__":
    main()
