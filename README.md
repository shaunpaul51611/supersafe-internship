# Quantum Safe Share

A Python desktop prototype for secure sign-in, friend requests, and encrypted file sharing.

## What It Uses

- `ML-KEM-768`, the standardized CRYSTALS-Kyber family, through `pqcrypto`
- `AES-256-GCM` for file payload encryption
- `scrypt` to derive account unlock keys from each user's master password
- Username-or-email sign-in with a master password
- `SQLite` for account, friendship, and encrypted inbox storage
- `tkinter` for the desktop UI with black/red dark mode and white/green light mode

## Local Desktop Mode

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python secure_share_app.py
```

If `venv` or `ensurepip` is blocked in a OneDrive-managed folder, install into your user Python environment instead:

```powershell
python -m pip install -r requirements.txt
python secure_share_app.py
```

## Server Mode

For cross-device transfer, run the server on one machine:

```powershell
$env:SECURE_SHARE_HOST="0.0.0.0"
$env:SECURE_SHARE_PORT="8000"
python secure_share_server.py
```

Then run the desktop app on each device with the same server URL:

```powershell
$env:SECURE_SHARE_SERVER_URL="http://SERVER_IP_ADDRESS:8000"
python secure_share_app.py
```

Files are encrypted on the client before upload. The server stores shared accounts, friend requests, public keys, encrypted file blobs, and inbox metadata so different devices can see the same transfers.

## Cloud Deployment

The server can be hosted with Docker on a VPS or cloud server. The included `Dockerfile` and `compose.yaml` run only the backend server and store its database in a persistent Docker volume.

Oracle Cloud Always Free is the recommended free-tier path for this prototype. The repo includes an Oracle setup script at `deploy/oracle-cloud-setup.sh`.

Quick local Docker test:

```bash
docker compose up -d --build
curl http://127.0.0.1:8000/health
```

For a full cloud setup with HTTPS and update workflow, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Built-In Tests

```powershell
python secure_share_self_test.py
python secure_share_network_self_test.py
```

The reserved test username is `__secure_echo__`. Normal users cannot register or friend that username directly; the app uses it internally for the secure echo test.

## Notes

This is a strong learning prototype, not an audited production security product. For real deployment, keep the server behind HTTPS and add device/key verification, rate limiting, audit logging, backups, and a recovery design for lost master passwords.
