# Cloud Deployment

This guide deploys the server-side file transfer backend to a cloud VPS with Docker. The desktop app still runs on each user's computer and connects to the server URL.

## Important Security Note

Use HTTPS before letting real users sign in over the internet. File contents are client-side encrypted, but login/session traffic still needs transport protection.

## 1. Prepare The Cloud Server

Use an Ubuntu VPS or similar Linux server. Install Docker and the Compose plugin, then clone this GitHub repo:

```bash
sudo apt update
sudo apt install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker

git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git quantum-safe-share
cd quantum-safe-share
```

Optional config:

```bash
cp .env.example .env
```

## Oracle Cloud Always Free Quick Start

Oracle Cloud is a good free-tier option for this project because the backend only needs a small Linux VM, Docker, and persistent disk storage.

Create the VM in Oracle Cloud:

- Image: `Ubuntu 24.04` or newer
- Shape: an Always Free eligible shape, such as Ampere A1 if available
- Networking: assign a public IPv4 address
- SSH: add your public SSH key during VM creation
- Ingress rules: allow TCP `22` for SSH, then TCP `80` and `443` for HTTPS

After the VM is running, SSH into it and run:

```bash
curl -fsSL https://raw.githubusercontent.com/shaunpaul51611/supersafe-internship/main/deploy/oracle-cloud-setup.sh | bash
```

That script installs Docker, clones this repo, starts the server container, and checks `/health`.

If you want to test without a domain first, temporarily allow TCP `8000` in the Oracle Cloud subnet security list, then visit:

```text
http://YOUR_ORACLE_PUBLIC_IP:8000/health
```

For real use, prefer HTTPS on `80`/`443` with Caddy instead of exposing port `8000` publicly.

## 2. Start The Server

```bash
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8000/health
```

The server database is stored in the `secure-share-data` Docker volume. Rebuilding the code does not delete that volume.

## 3. Add HTTPS

Point a domain or subdomain to your VPS, then use a reverse proxy. Caddy is the simplest option because it automatically gets HTTPS certificates.

Example Caddy setup:

```bash
sudo apt install -y caddy
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Edit `/etc/caddy/Caddyfile` and replace `secure-share.example.com` with your real domain.

After HTTPS is working, the desktop app should use:

```powershell
$env:SECURE_SHARE_SERVER_URL="https://secure-share.example.com"
.\QuantumSafeShare.exe
```

## 4. Push Code Updates To The Cloud

Code changes do not automatically appear on the cloud server just because they exist on your computer. The normal update flow is:

1. Commit and push your local code to GitHub.
2. SSH into the cloud server.
3. Pull the new code and rebuild the container.

From the server:

```bash
cd quantum-safe-share
bash deploy/update-server.sh
```

That script runs:

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

## 5. Backups

Back up the Docker volume regularly:

```bash
docker run --rm \
  -v quantum-safe-share_secure-share-data:/data \
  -v "$PWD/backups:/backup" \
  alpine tar czf /backup/secure-share-data-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
```

Keep backup files somewhere private and secure.

## 6. Recommended Hardening Before Real Users

- Put the server behind HTTPS before sign-ins leave your local network.
- Add rate limiting at the reverse proxy.
- Add admin tooling for account support and abuse handling.
- Add public-key/device verification so users can confirm they are encrypting to the right person.
- Add database backup and restore drills.
- Keep server logs, but avoid logging passwords, file contents, or secret keys.
