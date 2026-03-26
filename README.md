# astracat-dns (balanceDNSt)

Высокопроизводительный DNS-прокси/балансировщик на Rust (Tokio) с поддержкой апстримов `udp`/`tcp`/`dot`/`doh`.

Сервис принимает клиентские запросы по `UDP`, `TCP`, `DoT` и `DoH`, а к апстримам может ходить по `UDP`, `TCP`, `DoT` и `DoH`.

## Быстрый старт (локально)

Сгенерировать self-signed TLS для DoT/DoH:

```bash
bash scripts/generate-dev-tls.sh
```

```bash
cargo run --bin astracat-dns -- --config config/config.toml
```

Проверка:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 +tcp example.com A
curl http://127.0.0.1:9100/metrics
```

## Конфигурация (TOML)

Пример: `config/astracat-dns.toml`

Ключевые секции:
- `[server]` — адреса прослушивания UDP/TCP.
- `[hosts_remote]` — загрузка hosts-правил из URL (обновление каждые 5 минут).
- `[[upstreams]]` — список апстримов и их протокол.
- `[security]` — базовые фильтры типов (REFUSED для `ANY`/`DNSKEY`).
- `[metrics]` — адрес HTTP-эндпоинта `/metrics`.

### `[[upstreams]]`

Поддерживаемые `proto`:
- `udp` — классический DNS/UDP
- `tcp` — классический DNS/TCP
- `dot` — DNS-over-TLS (RFC 7858)
- `doh` — DNS-over-HTTPS POST `application/dns-message` (RFC 8484)

Полевая матрица:
- `proto = "udp"|"tcp"` требует `addr = "IP:PORT"`
- `proto = "dot"` требует `addr = "IP:853"` и `server_name = "SNI"`
- `proto = "doh"` требует `url = "https://.../dns-query"`
- `tls_insecure = true` (опционально) отключает проверку TLS-сертификатов для `dot`/`doh` (только для тестов)

## DoT / DoH (входящие)

- DoT: `server.dot_listen`, порт по умолчанию `8853` (в проде обычно `853`).
- DoH: `server.doh_listen`, порт по умолчанию `8443` (в проде обычно `443`), путь `POST /dns-query` (и `GET /dns-query?dns=...`).
- TLS ключи: `[tls].cert_pem` и `[tls].key_pem`.

Пути в `[tls]` можно задавать относительными: они резолвятся относительно директории файла конфига.

## IPv6

Можно слушать на IPv6, например `udp_listen = "[::]:53"`.
На Linux при `net.ipv6.bindv6only=0` это обычно принимает и IPv4-mapped подключения; если нужно гарантированно разделять, сейчас требуется поднимать две инстанции с разными конфигами.

Апстримы IPv6 задаются как `addr = "[2606:4700:4700::1111]:53"`.

## Установка как systemd-сервис (Linux)

Скрипт создаёт:
- бинарник `/usr/local/bin/astracat-dns`
- конфиг `/etc/astracat-dns/config.toml`
- юнит `/etc/systemd/system/astracat-dns.service`

Запуск:

```bash
sudo bash scripts/install-systemd.sh
```

Удаление:

```bash
sudo bash scripts/uninstall-systemd.sh
```

Статус:

```bash
systemctl status astracat-dns
journalctl -u astracat-dns -f
```

## Метрики

`GET /metrics` в формате Prometheus. Базовые метрики:
- `dns_requests_total{proto="udp|tcp"}`
- `dns_denied_total{proto="udp|tcp"}`
- `dns_upstream_errors_total{proto="udp|tcp"}`
- `dns_timeouts_total{proto="udp",upstream="..."}`
- `dns_upstream_latency_ms{proto="udp|tcp",upstream="..."}`

### QPS и полезные PromQL

- Общий QPS (все протоколы):
  - `sum(rate(dns_requests_total[1m]))`
- QPS по протоколам:
  - `sum by (proto) (rate(dns_requests_total[1m]))`
- Блокировки (QPS блокировок):
  - `sum(rate(dns_blocked_total[1m]))`
  - `sum by (proto) (rate(dns_blocked_total[1m]))`
- Хиты hosts (QPS ответов из hosts):
  - `sum(rate(dns_hosts_hits_total[1m]))`
- Ошибки апстрима (включая DoT/DoH):
  - `sum by (proto) (rate(dns_upstream_errors_total[1m]))`
- Размеры списков:
  - `dns_hosts_domains`, `dns_hosts_ips`, `dns_blocklist_domains`
- Обновления списков:
  - `sum(rate(dns_hosts_refresh_total[5m]))`
  - `sum(rate(dns_blocklist_refresh_total[5m]))`

## Remote hosts (GitHub raw)

Секция `[hosts_remote]` заставляет сервис отвечать локально по правилам из файла в формате `/etc/hosts` (строки `IP hostname`).
Пример URL: `https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass`.

Поля:
- `url` — ссылка на raw-файл
- `refresh_seconds` — период обновления (по умолчанию 300)
- `ttl_seconds` — TTL в ответах (по умолчанию 60)

## Blocklist (anti-ads)

Секция `[blocklist_remote]` загружает список блокировок из URL и отвечает `NXDOMAIN` для доменов из списка.
Поддерживаются только безопасные для DNS-уровня правила:
- adblock network filters `||domain^`
- hosts-формат `0.0.0.0 domain`
- строки с чистым доменом

Косметические правила вида `domain##selector` игнорируются.
