from __future__ import annotations

import os
import threading
from pathlib import Path

from secure_share_app import RemoteSecureStore
from secure_share_server import SecureShareHTTPServer, SecureShareServerStore


def main() -> None:
    base = Path(".self_test_runs") / os.urandom(4).hex()
    base.mkdir(parents=True, exist_ok=True)
    server_store = SecureShareServerStore(base / "server.db")
    server = SecureShareHTTPServer(("127.0.0.1", 0), server_store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        alice_client = RemoteSecureStore(url)
        bob_client = RemoteSecureStore(url)

        alice_client.create_user(
            "alice_net",
            "alice.net@example.com",
            "correct horse battery staple",
        )
        bob_client.create_user(
            "bob_net",
            "bob.net@example.com",
            "another correct horse battery",
        )

        alice = alice_client.authenticate_password(
            "alice.net@example.com",
            "correct horse battery staple",
        )
        bob = bob_client.authenticate_password(
            "bob_net",
            "another correct horse battery",
        )

        alice_client.send_friend_request(alice.id, "bob_net")
        incoming = bob_client.list_incoming_requests(bob.id)
        bob_client.respond_to_friend_request(incoming[0]["id"], bob.id, "accepted")

        transfer_id = alice_client.create_file_transfer_bytes(
            alice,
            bob.id,
            "network-roundtrip.txt",
            b"hello over the server",
        )
        inbox = bob_client.list_received_files(bob.id)
        assert any(row["id"] == transfer_id for row in inbox)

        original_name, decrypted = bob_client.decrypt_received_file(bob, transfer_id)
        assert original_name == "network-roundtrip.txt"
        assert decrypted == b"hello over the server"
        print("network self-test ok: server-backed cross-device transfer")
    finally:
        server.shutdown()
        server.server_close()
        server_store.close()


if __name__ == "__main__":
    main()
