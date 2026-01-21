# Deployment & Usage Manual

## 🛠 Deployment Methods

AstracatDNS supports multiple deployment methods depending on your environment.

### 1. Local Deployment (No SSH)
Use this method if you are running the installation directly on the target machine (e.g., your local server or a VPS where you are already logged in).

**Script:** `local_install.sh`

**Usage:**
```bash
# Must be run as root
sudo ./local_install.sh
```

**What it does:**
- Installs system dependencies (`libunbound`, etc.).
- Builds the Go binary locally.
- Sets up systemd service `astracat.service`.
- **Certificates**: Automatically checks `internal/config/myceeert` for valid certificates (`fullchain.pem`, `privkey.pem`) and installs them.

### 2. Remote Deployment (via SSH)
Use this method to deploy from your dev machine to a remote server.

**Script:** `deploy_prod.sh`

**Usage:**
```bash
./deploy_prod.sh <REMOTE_SERVER_IP>
```

**What it does:**
- Packages the local source code.
- Connects to the remote server via SSH.
- Uploads the source and runs the installation script remotely.
- **Certificates**: If you have certificates in `internal/config/myceeert` locally, they will be packaged, uploaded, and installed on the remote server.

---

## 🔐 Certificates Configuration

### Option A: Automatic File Detection
Place your certificate files in:
- `internal/config/myceeert/fullchain.pem`
- `internal/config/myceeert/privkey.pem`

The deployment scripts will automatically copy these to the working directory as `cert.pem` and `key.pem`.

### Option B: Environment Variables (Docker / Cloud Injection)
You can pass the *content* of your certificates directly via environment variables. This is useful for Docker, Kubernetes, or CI/CD pipelines where you don't want to manage files.

**Variables:**
- `SSL_CERT_CONTENT`: The full content of your `fullchain.pem`.
- `SSL_KEY_CONTENT`: The full content of your `privkey.pem`.

**Behavior:**
At startup, the application checks these variables. If set, it writes their content to `cert.pem` and `key.pem` on disk, overriding existing files.

**Example (Docker):**
```bash
docker run -d \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 443:443/tcp \
  -e SSL_CERT_CONTENT="-----BEGIN CERTIFICATE-----
...base64 content...
-----END CERTIFICATE-----" \
  -e SSL_KEY_CONTENT="-----BEGIN PRIVATE KEY-----
...base64 content...
-----END PRIVATE KEY-----" \
  astracat-dns
```

---

## 🐳 Docker Deployment

1. **Build the image:**
   ```bash
   docker build -t astracat-dns .
   ```

2. **Run:**
   ```bash
   docker run -d --name dns -p 5053:53/udp -p 5053:53/tcp astracat-dns
   ```
