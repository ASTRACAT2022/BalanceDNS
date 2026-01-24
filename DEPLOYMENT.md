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

## 🧭 Cluster Mode (Admin + Nodes)

AstracatDNS can run in a simple cluster layout:

- **Admin node**: runs the admin panel and serves configuration + TLS certificates to workers.
- **Worker nodes**: pull configuration/certificates from the admin node at startup.

### Admin Node

1. Set the role and token in `config.yaml`:
   ```yaml
   cluster_role: "admin"
   cluster_token: "super-secret-token"
   ```

2. Start the admin node normally.

The admin node will expose a sync endpoint at:
`http://<admin-ip>:8080/api/cluster/sync`

### Worker Nodes

1. Set the node role and admin URL:
   ```yaml
   cluster_role: "node"
   cluster_admin_url: "http://<admin-ip>:8080"
   cluster_token: "super-secret-token"
   ```

2. Start the node. It will fetch the cluster config and certificates on boot.

**Notes:**
- Nodes automatically disable their local admin panel.
- Nodes do not run ACME/Let's Encrypt (certs come from admin).
- Certificate generation on the admin node uses self-signed fallback if no certs exist.

### Быстрый деплой (мастер-скрипт)

Для максимально простой установки используйте интерактивный скрипт:

```bash
./easy_cluster_deploy.sh
```

Скрипт попросит роль (admin/node), домен/почту для TLS (если нужно), токен кластера и адрес админ-сервера, затем выполнит деплой на выбранный сервер.


### Полное руководство

Для подробной инструкции (архитектура, синхронизация, ротация сертификатов и проверки) см.  
[`docs/cluster_manual.md`](docs/cluster_manual.md).

=======

---

## 🐳 Docker Deployment

1. **Build the image:**
   ```bash
   docker build -t astracat-dns .
   ```

   ```bash
   docker run -d --name dns -p 5053:53/udp -p 5053:53/tcp astracat-dns
   ```

### 🧩 Docker Compose (docker-compose.yml) — пример для Docker YML

Ниже пример сервиса в формате `docker-compose.yml`, который использует все основные порты и переменные окружения.  
Вы можете вставить блок в свой `services:` и запустить через `docker compose up -d`.

```yaml
services:
  astracat-dns:
    build: .
    image: astracat/astracat-dns
    container_name: astracat-dns

    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "443:443/tcp"
      - "853:853/tcp"
      - "9090:9090/tcp"
      - "8080:8080/tcp"

    environment:
      LISTEN_ADDR: 0.0.0.0:53
      METRICS_ADDR: 0.0.0.0:9090
      ADMIN_ADDR: 0.0.0.0:8080
      DOH_ADDR: 0.0.0.0:443
      DOT_ADDR: 0.0.0.0:853

      CACHE_SIZE: "1024"
      CACHE_RAM_SIZE: "50"
      MAX_WORKERS: "10"
      GOMAXPROCS: "1"

      ADBLOCK_ENABLED: "true"
      HOSTS_ENABLED: "true"

      # ===== SSL CERTIFICATE (FULLCHAIN) =====
      SSL_CERT_CONTENT: |
        -----BEGIN CERTIFICATE-----
        ...ваш fullchain.pem...
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        ...промежуточный сертификат (если есть)...
        -----END CERTIFICATE-----

      # ===== SSL PRIVATE KEY =====
      SSL_KEY_CONTENT: |
        -----BEGIN PRIVATE KEY-----
        ...ваш privkey.pem...
        -----END PRIVATE KEY-----

    restart: always
```

**Запуск:**
```bash
docker compose up -d
```

**Примечания:**
- `SSL_CERT_CONTENT` и `SSL_KEY_CONTENT` должны содержать полный текст сертификатов.  
- При запуске контейнера содержимое будет записано в `cert.pem` и `key.pem`.  
- Если вам не нужен DoH/DoT, можно удалить соответствующие порты и переменные (`DOH_ADDR`, `DOT_ADDR`).

---

## ☁️ Pushing to Docker Hub

### Manual Method
1. **Login to Docker Hub:**
   ```bash
   docker login
   ```

2. **Tag your image:**
   Replace `your-username` with your Docker Hub username.
   ```bash
   docker tag astracat-dns your-username/astracat-dns:latest
   ```

3. **Push:**
   ```bash
   docker push your-username/astracat-dns:latest
   ```

### Automated Method (GitHub Actions)
This repository includes a GitHub Action to automatically publish to Docker Hub on release.

1. Go to your GitHub Repository **Settings** -> **Secrets and variables** -> **Actions**.
2. Create two repository secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username.
   - `DOCKERHUB_TOKEN`: Your Docker Hub Access Token.
3. Every time you push a tag (e.g., `v1.0.0`) or push to `main` (if configured), the image will be pushed to Docker Hub.
