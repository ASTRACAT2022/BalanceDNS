# Руководство по кластеру AstracatDNS (Admin + Nodes)

Это руководство описывает полноценный сценарий развертывания кластера: один **Admin‑сервер** (центр управления) и несколько **Node‑серверов** (воркеры).  
Цель — единая точка настройки и автоматическая выдача конфигов/сертификатов на все ноды.

---

## 1. Архитектура

**Admin сервер**:
- Хранит основную конфигурацию (`config.yaml`).
- Раздаёт конфиг и TLS сертификаты через endpoint `/api/cluster/sync`.
- Может использовать **self‑signed** или **ACME/Let’s Encrypt** сертификаты.

**Node сервер**:
- При старте тянет конфиг + сертификаты у Admin.
- Не поднимает локальную админ‑панель.
- Не запускает ACME (сертификаты приходят от Admin).
- Периодически обновляет конфиг по таймеру.

---

## 2. Быстрый старт (рекомендуется)

Используйте интерактивный мастер:

```bash
./easy_cluster_deploy.sh
```

Сценарий:
1. Вводите IP сервера.
2. Выбираете роль (`admin` или `node`).
3. Вводите домен и email (если хотите Let’s Encrypt).
4. Скрипт автоматически деплоит сервер.

---

## 3. Ручная настройка (manual)

### 3.1 Admin сервер

В `config.yaml` укажите:

```yaml
cluster_role: "admin"
cluster_token: "super-secret-token"
```

Если нужен ACME/Let’s Encrypt:

```yaml
acme_enabled: true
acme_email: "admin@example.com"
acme_domains:
  - "dns.example.com"
```

**Запуск:**
```bash
./deploy_prod.sh <ADMIN_IP>
```

---

### 3.2 Node сервер

В `config.yaml` укажите:

```yaml
cluster_role: "node"
cluster_admin_url: "http://<ADMIN_IP>:8080"
cluster_token: "super-secret-token"
cluster_sync_interval: 30s
```

**Запуск:**
```bash
./deploy_prod.sh <NODE_IP>
```

---

## 4. Как работает синхронизация

Node при старте делает запрос:

```
GET http://<ADMIN_IP>:8080/api/cluster/sync
X-Cluster-Token: <token>
```

Ответ:

```json
{
  "config_yaml": "...",
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "key_pem": "-----BEGIN PRIVATE KEY-----..."
}
```

Node записывает конфиг и ключи локально, дальше работает полностью автономно.

---

## 5. Ротация сертификатов

### Если self‑signed:
- Админ автоматически создаёт самоподписанный сертификат.
- При удалении файлов `cert.pem`/`key.pem` он пересоздаётся.

### Если ACME:
- Сертификаты обновляются Let’s Encrypt (обычно каждые ~60 дней).
- Ноды обновят сертификаты при очередной синхронизации.

---

## 6. Рекомендации по стабильности

- **Admin сервер должен быть доступен** для всех Node (открыт порт 8080).
- Используйте firewall‑ограничения (разрешить доступ только вашим IP).
- Для критичных конфигураций увеличьте `cluster_sync_interval` до 5–10 минут.
- Делайте регулярные бэкапы `config.yaml` и `certs-cache/`.

---

## 7. Проверка работоспособности

### Проверка админ‑панели:
```
http://<ADMIN_IP>:8080
```

### Проверка DNS на Node:
```bash
dig @<NODE_IP> -p 53 google.com +short
```

### Проверка синка:
```bash
curl -H "X-Cluster-Token: <token>" http://<ADMIN_IP>:8080/api/cluster/sync
```

---

## 8. Частые ошибки

**Ошибка 401 Unauthorized**  
→ Неверный `cluster_token`.

**Ошибка 404 Cluster sync only for admin**  
→ Admin сервер запущен без `cluster_role: admin`.

**Node не получает конфиг**  
→ Проверьте доступность `cluster_admin_url` и firewall.

---

## 9. Итого

- **Admin сервер** — главный, хранит настройки.
- **Nodes** — получают настройки автоматически.
- Настройка занимает 5 минут.
- Стабильность обеспечивается регулярным sync’ом.
