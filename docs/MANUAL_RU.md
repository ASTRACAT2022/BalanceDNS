# BalanceDNS: гибкий manual (RU)

## 1. Что это

`BalanceDNS` — DNS-резолвер/форвардер на Go с:
- listener'ами `DNS (UDP/TCP)`, `DoT`, `DoH`;
- маршрутизацией по зонам (`.ru` отдельно, остальное отдельно);
- быстрым шардированным L1-кэшем и persistent L2-кэшем;
- Last Known Good (LKG) и stale-while-revalidate для успешно разрешённых DNS-ответов;
- policy-движком (Lua/go_exec, sandbox);
- supervisor-контролем компонентов;
- метриками Prometheus.

## 2. Один конфиг для всего

В проекте используется **один основной конфиг**:
- `configs/prod.lua`

Запуск по умолчанию:

```bash
go run ./cmd/balancedns -config configs/prod.lua
```

Docker по умолчанию тоже использует `configs/prod.lua`.

## 3. Быстрый старт (Docker)

```bash
cd ~/BalanceDNS
docker compose down --remove-orphans
docker compose up -d --build
docker compose logs -f -t
```

Проверка:

```bash
curl -s http://127.0.0.1:9091/healthz
curl -s http://127.0.0.1:9091/statusz
dig @127.0.0.1 -p 53 example.org A
```

## 4. Главная идея гибкости: env + Lua

`configs/prod.lua` поддерживает переменные окружения:

- `BALANCEDNS_BIND_IP` — IP для DNS/DoT/DoH
- `BALANCEDNS_METRICS_IP` — IP для метрик
- `BALANCEDNS_TLS_CERT` — путь к cert
- `BALANCEDNS_TLS_KEY` — путь к key
- `BALANCEDNS_LOG_LEVEL` — `debug|info|error`

Пример:

```bash
BALANCEDNS_BIND_IP=144.31.151.64 \
BALANCEDNS_METRICS_IP=127.0.0.1 \
BALANCEDNS_TLS_CERT=/etc/balancedns/certs/fullchain.cer \
BALANCEDNS_TLS_KEY=/etc/balancedns/certs/key.key \
BALANCEDNS_LOG_LEVEL=info \
docker compose up -d --build
```

## 5. Что уже настроено в prod.lua

- `53` DNS
- `853` DoT
- `443` DoH (`/dns-query`)
- `.ru` -> `77.88.8.8`
- остальное -> `95.85.95.85` + fallback `2.56.220.2`
- локальные ответы из `hosts.txt`
- низкий шум логов (`log_queries = false`)

## 6. Формат hosts.txt

Файл: `hosts.txt` в корне проекта.

Формат строки:

```text
<ip> <fqdn> [alias1 alias2 ...]
```

Пример:

```text
10.10.10.10 api.internal.example
10.10.10.20 db.internal.example
fd00::10 v6.internal.example
```

Проверка:

```bash
dig @<BIND_IP> -p 53 api.internal.example A
dig @<BIND_IP> -p 53 v6.internal.example AAAA
```

## 7. Типовые сценарии развертывания

### 7.1 Один отдельный IP под DNS

Лучший вариант для production:
- на этом IP слушать `53/853/443`;
- метрики вынести на `127.0.0.1`.

### 7.2 Когда 443 уже занят

Варианты:
1. Выделить отдельный IP под BalanceDNS (рекомендуется).
2. Временно сменить DoH порт на `8443` в `prod.lua`.
3. Поставить reverse-proxy, который будет проксировать `/dns-query` в BalanceDNS.

### 7.3 Когда один инстанс не хватает

Поднимай второй инстанс (второй compose-проект/хост) с другим `BALANCEDNS_BIND_IP`.

## 8. Стабильность и скорость: что крутить

### 8.1 Стабильность

- `control.max_consecutive_failure = 0` (бесконечные попытки перезапуска)
- `control.min_stable_run_ms = 10000`
- `read_timeout_ms`/`write_timeout_ms` не ставить слишком низко

### 8.2 Производительность

- `cache.capacity` задаёт максимальное число записей в RAM L1;
- `cache.max_ttl_seconds` ограничивает сверху время свежести, но не продлевает исходный DNS TTL;
- `reuse_port = true`, `reuse_addr = true`
- держать апстримы географически близко

### 8.3 LKG-кэш и stale-while-revalidate

Положительный успешный ответ (`NOERROR` с записями в `Answer`) сохраняется в L1 и на диск. Пока исходный DNS TTL не истёк, ответ обслуживается из L1 как `fresh`. TTL в ответе клиенту уменьшается со временем.

После истечения TTL запись остаётся как Last Known Good (`stale`). Resolver немедленно возвращает её с коротким клиентским TTL и обновляет данные в фоне. Успешный ответ атомарно заменяет старый. Таймауты, сетевые ошибки, `SERVFAIL`, `NXDOMAIN`, `REFUSED` и ответы без записей не затирают LKG. Отрицательные ответы в этот положительный кэш не записываются.

На промахе L1 resolver лениво проверяет L2; весь диск-кэш при запуске в RAM не загружается. Для одного DNS-ключа одновременно выполняется не более одного refresh. При ошибках refresh действует экспоненциальная задержка с jitter. Популярные записи можно обновлять заранее, когда до конца TTL остаётся заданный процент.

Пример настроек в Lua:

```lua
cache = {
  enabled = true,
  capacity = 250000, -- предел записей L1
  min_ttl_seconds = 5, -- оставлен для совместимости; исходный TTL не увеличивается
  max_ttl_seconds = 1800,
  persistent = {
    enabled = true,
    path = "/var/lib/balancedns/dns-cache",
    max_size_gb = 20,
  },
  stale = {
    enabled = true,
    response_ttl = 30,
  },
  refresh = {
    enabled = true,
    workers = 8,
    min_delay_ms = 1000,
    max_delay_ms = 1800000,
  },
  prefetch = {
    enabled = true,
    threshold_percent = 10,
  },
}
```

`capacity` ограничивает только RAM L1: LRU-вытеснение из L1 не удаляет запись из L2. L2 ограничивается параметром `max_size_gb`; самые давно использованные файлы удаляются при обслуживании дискового лимита. Для Docker Compose production-конфиг использует `/var/lib/balancedns/dns-cache`, каталог сохраняется volume `./data/dns-cache`. При отдельном запуске укажите путь на постоянном диске и выдайте пользователю процесса права записи. Не размещайте L2 на сетевом файловом хранилище.

Чтобы отключить persistent cache, задайте `persistent = { enabled = false, path = "/путь/к/кэшу" }`. Чтобы отключить stale-ответы или фоновые обновления, задайте `stale.enabled = false` или `refresh.enabled = false`.

Новые cache-метрики доступны на `/metrics`: `dns_cache_requests_total`, `dns_cache_l1_hit_total`, `dns_cache_l2_hit_total`, `dns_cache_fresh_hit_total`, `dns_cache_stale_hit_total`, `dns_cache_miss_total`, `dns_cache_refresh_total`, `dns_cache_refresh_success_total`, `dns_cache_refresh_failed_total` и `dns_cache_refresh_duration_seconds`. Также доступны существующие `balancedns_cache_entries`, `balancedns_cache_hits_total`, `balancedns_cache_misses_total` и `balancedns_cache_evictions_total`.

Примеры PromQL для долей попаданий:

```promql
# Общее попадание в L1 или L2
sum(rate(dns_cache_l1_hit_total[5m]) + rate(dns_cache_l2_hit_total[5m])) / sum(rate(dns_cache_requests_total[5m]))
# Доли fresh и stale ответов среди всех запросов к кэшу
sum(rate(dns_cache_fresh_hit_total[5m])) / sum(rate(dns_cache_requests_total[5m]))
sum(rate(dns_cache_stale_hit_total[5m])) / sum(rate(dns_cache_requests_total[5m]))
```

### 8.4 Логи

Минимум шума:

```lua
logging = {
  level = "info",
  log_queries = false,
}
```

## 9. Политики (Lua/go_exec)

Этап policy: `lua_policy` в `routing.chain`.

- Подробно: `docs/POLICIES_RU.md`
- Для чистого резолвера можно держать:

```lua
plugins = {
  enabled = false,
  timeout_ms = 20,
}
```

## 10. Метрики и health

Endpoint'ы (на `listen.metrics`):
- `/healthz`
- `/readyz`
- `/statusz`
- `/metrics`

Проверка:

```bash
curl -s http://127.0.0.1:9091/healthz
curl -s http://127.0.0.1:9091/metrics | rg balancedns_
```

## 11. Systemd (без Docker)

```bash
sudo CONFIG_SRC=configs/prod.lua ./scripts/install-systemd.sh
sudo systemctl status balancedns --no-pager
```

Если сертификаты в `/root/...`, перенеси их в `/etc/balancedns/certs` и выдай права чтения для группы сервиса.
У systemd-пользователя также должны быть права записи в `persistent.path` (в production-конфиге это `/var/lib/balancedns/dns-cache`).

## 12. Частые проблемы и решения

### 12.1 `bind: address already in use`

Порт занят другим сервисом.

Проверка:

```bash
ss -lntup | rg ':53|:443|:853|:9091'
```

### 12.2 `bind: permission denied` на 53/443/853

Для Docker:
- запускать контейнер root (`user: "0:0"`),
- добавить `NET_BIND_SERVICE`.

Для systemd:
- убедиться, что есть `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

### 12.3 `decode lua config ... cannot unmarshal object into []string`

Пустые массивы в Lua-таблицах иногда интерпретируются как object.

Правильно:
- `blacklist = {}` вместо `blacklist = { domains = {} }`
- `plugins = { enabled = false, timeout_ms = 20 }` без `entries = {}`

## 13. Операционный чек-лист

Перед релизом:

```bash
go test ./...
go test -race ./...
go build ./cmd/balancedns
```

После релиза:

```bash
curl -s http://127.0.0.1:9091/healthz
dig @<BIND_IP> -p 53 ya.ru A
dig @<BIND_IP> -p 53 google.com A
```

Если health `ok`, DNS отвечает, а логи без restart-loop — прод готов.
