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

This runs everything on one computer with a local app database.

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

## Host From Your Computer

For cross-device transfer without cloud hosting, run the server on your computer:

```powershell
$env:SECURE_SHARE_HOST="0.0.0.0"
$env:SECURE_SHARE_PORT="8000"
python secure_share_server.py
```

Then run the desktop app on each device with your computer's local network IP address:

```powershell
$env:SECURE_SHARE_SERVER_URL="http://YOUR_COMPUTER_IP:8000"
python secure_share_app.py
```

The server stays online only while your computer is powered on, awake, connected to the network, and the server window is still running. You may also need to allow Python or `SecureShareServer.exe` through Windows Firewall.

Files are encrypted on the client before upload. The server running on your computer stores shared accounts, friend requests, public keys, encrypted file blobs, and inbox metadata so devices on your network can see the same transfers.

## Built-In Tests

```powershell
python secure_share_self_test.py
python secure_share_network_self_test.py
```

The reserved test username is `__secure_echo__`. Normal users cannot register or friend that username directly; the app uses it internally for the secure echo test.

## Notes

This is a strong learning prototype, not an audited production security product. Keep it on a trusted local network unless you add HTTPS, stronger abuse protection, audit logging, backups, and device/key verification.
