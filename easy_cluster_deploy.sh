#!/bin/bash
set -euo pipefail

CONFIG_FILE="config.yaml"
TMP_CONFIG=".tmp_cluster_config.yaml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}=== AstracatDNS Easy Cluster Deploy ===${NC}"

read -rp "Введите IP сервера (например, 10.0.0.10): " REMOTE_HOST
if [ -z "${REMOTE_HOST}" ]; then
  echo -e "${RED}Ошибка: IP сервера обязателен.${NC}"
  exit 1
fi

read -rp "Роль (admin/node) [admin]: " ROLE
ROLE=${ROLE:-admin}
if [ "${ROLE}" != "admin" ] && [ "${ROLE}" != "node" ]; then
  echo -e "${RED}Ошибка: роль должна быть admin или node.${NC}"
  exit 1
fi

read -rp "Cluster Token (Enter для авто-генерации): " CLUSTER_TOKEN
if [ -z "${CLUSTER_TOKEN}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    CLUSTER_TOKEN=$(openssl rand -hex 16)
  else
    CLUSTER_TOKEN="change-me-$(date +%s)"
  fi
  echo -e "${YELLOW}Сгенерирован токен: ${CLUSTER_TOKEN}${NC}"
fi

ADMIN_URL=""
ACME_ENABLED="false"
ACME_EMAIL=""
ACME_DOMAIN=""
ADMIN_ADDR=""

if [ "${ROLE}" = "admin" ]; then
  read -rp "Домен для TLS (Enter чтобы оставить self-signed): " ACME_DOMAIN
  if [ -n "${ACME_DOMAIN}" ]; then
    read -rp "Email для Let's Encrypt: " ACME_EMAIL
    ACME_ENABLED="true"
  fi
else
  read -rp "URL админ-сервера (например, http://10.0.0.10:8080): " ADMIN_URL
  if [ -z "${ADMIN_URL}" ]; then
    echo -e "${RED}Ошибка: URL админ-сервера обязателен для node.${NC}"
    exit 1
  fi
  ADMIN_ADDR=""
fi

cat > "${TMP_CONFIG}" <<EOF
cluster_role: "${ROLE}"
cluster_token: "${CLUSTER_TOKEN}"
cluster_admin_url: "${ADMIN_URL}"
cluster_sync_interval: 30s
admin_addr: "${ADMIN_ADDR}"
acme_enabled: ${ACME_ENABLED}
acme_email: "${ACME_EMAIL}"
acme_domains:
  - "${ACME_DOMAIN}"
EOF

BACKUP=""
cleanup() {
  if [ -n "${BACKUP}" ] && [ -f "${BACKUP}" ]; then
    mv "${BACKUP}" "${CONFIG_FILE}"
  else
    rm -f "${CONFIG_FILE}"
  fi
  rm -f "${TMP_CONFIG}"
}

if [ -f "${CONFIG_FILE}" ]; then
  BACKUP="${CONFIG_FILE}.bak.$(date +%s)"
  mv "${CONFIG_FILE}" "${BACKUP}"
fi

mv "${TMP_CONFIG}" "${CONFIG_FILE}"
trap cleanup EXIT

echo -e "${GREEN}Запускаю деплой на ${REMOTE_HOST}...${NC}"
./deploy_prod.sh "${REMOTE_HOST}"
