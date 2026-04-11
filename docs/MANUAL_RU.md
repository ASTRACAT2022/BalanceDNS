# BalanceDNS: руководство (RU)

## 1. Что это

`BalanceDNS` — DNS-резолвер/форвардер с:
- цепочкой обработки запроса,
- кэшем (TTL + LRU),
- плагинами политики (Lua и go_exec),
- маршрутизацией по зонам,
- метриками Prometheus.

## 2. Быстрый старт

### Локально

```bash
go run ./cmd/balancedns -config configs/balancedns.yaml
```

или Lua-конфиг:

```bash
go run ./cmd/balancedns -config configs/balancedns.lua
```

### Проверка

```bash
# DNS (пример для порта 5353 из balancedns.yaml)
dig @127.0.0.1 -p 5353 example.org A

# Метрики
curl -s http://127.0.0.1:9090/metrics | rg balancedns_
```

## 3. Конфиг: форматы и дефолты

Поддерживаются:
- YAML
- JSON
- Lua (`return { ... }`)

Основные дефолты:
- `listen.dns = ":53"`
- `listen.metrics = ":9090"`
- `listen.read_timeout_ms = 2000`
- `listen.write_timeout_ms = 2000`
- `listen.udp_size = 1232`
- `routing.chain = ["blacklist", "cache", "lua_policy", "upstream"]`
- `cache.capacity = 10000`
- `cache.min_ttl_seconds = 5`
- `cache.max_ttl_seconds = 3600`
- `plugins.timeout_ms = 20`
- `upstream.timeout_ms = 2000` (если не задан)

## 4. Lua-конфиг

Файл должен вернуть таблицу:

```lua
return {
  listen = { dns = env("BALANCEDNS_DNS_ADDR", ":5353") },
  upstreams = {
    { name = "google", protocol = "doh", doh_url = "https://dns.google/dns-query", zones = {"."} }
  }
}
```

В Lua-конфиге доступна функция:
- `env("KEY", "default")` — читает переменную окружения.

Готовый пример:
- `configs/balancedns.lua`

## 5. Цепочка обработки (routing.chain)

Поддерживаемые этапы:
- `blacklist`
- `cache`
- `lua_policy` (также алиасы: `plugin`, `plugins`, `lua`)
- `upstream`

Рекомендуемый порядок для production:
1. `blacklist`
2. `cache`
3. `lua_policy`
4. `upstream`

## 6. Политики (плагины)

Подробный practical guide:
- `docs/POLICIES_RU.md`

### 6.1 Lua plugin

Контракт: файл должен экспортировать `handle(question)`.

`question` содержит:
- `question.domain` (FQDN)
- `question.type` (например `"A"`)
- `question.qtype` (число)

Возврат:
- `FORWARD`
- `BLOCK`
- `REWRITE`
- `LOCAL_DATA`

Пример:

```lua
function handle(question)
  local d = string.lower(question.domain or "")

  if d == "blocked.example." then
    return { action = "BLOCK" }
  end

  if d == "rewrite.example." then
    return {
      action = "REWRITE",
      rewrite_domain = "example.org.",
      rewrite_type = "A"
    }
  end

  if d == "local.example." then
    return {
      action = "LOCAL_DATA",
      local_data = {
        ttl = 60,
        ips = {"127.0.0.2", "::1"}
      }
    }
  end

  return { action = "FORWARD" }
end
```

### 6.2 go_exec plugin

`go_exec` запускается как отдельный процесс (sandbox-подход):
- timeout на исполнение,
- stdin/stdout JSON,
- пустое окружение процесса.

Вход (stdin):

```json
{"question":{"domain":"example.org.","type":"A","qtype":1}}
```

Выход (stdout):

```json
{"action":"FORWARD"}
```

Пример исходника go-plugin:
- `scripts/go_policy_example.go`

## 7. Upstream и маршрутизация

Протоколы upstream:
- `udp`
- `tcp`
- `dot`
- `doh`

Маршрутизация по зонам:
- используется longest-suffix match,
- при ошибке автоматически пробуется следующий подходящий upstream.

## 8. Кэш

Реализация:
- шардированный LRU (до 64 шардов),
- потокобезопасный,
- ключ: `FQDN + QType`,
- TTL берется из ответа upstream и ограничивается `min_ttl_seconds/max_ttl_seconds`.

## 9. Метрики

- `balancedns_queries_total`
- `balancedns_cache_hits_total`
- `balancedns_upstream_latency_seconds`
- `balancedns_plugin_execution_errors`
- `balancedns_component_up`
- `balancedns_component_restarts_total`

## 10. Контроль процессов (supervisor)

BalanceDNS запускает компоненты как независимые модули:
- `dns-udp`
- `dns-tcp`
- `metrics-http`

Для каждого модуля есть:
- автоматический перезапуск при падении,
- exponential backoff,
- защита от crash-loop через `max_consecutive_failure`.

Настройки:

```yaml
control:
  restart_backoff_ms: 200
  restart_max_backoff_ms: 5000
  max_consecutive_failure: 0
  min_stable_run_ms: 10000
```

- `max_consecutive_failure: 0` означает бесконечные попытки перезапуска.
- Если указать `>0`, при превышении лимита сервис завершится с ошибкой.

HTTP endpoints (на `listen.metrics`):
- `/healthz`
- `/readyz`
- `/statusz`

## 11. Docker

### 11.1 Через docker compose

```bash
docker compose up -d --build
```

Порты:
- `53/udp`
- `53/tcp`
- `9090/tcp` (metrics)

Файлы:
- `Dockerfile`
- `docker-compose.yml`
- `configs/docker.yaml`

### 11.2 Через docker run

```bash
docker build -t balancedns:local .

docker run -d --name balancedns \
  --cap-add=NET_BIND_SERVICE \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  -v $(pwd)/configs/docker.yaml:/app/configs/docker.yaml:ro \
  -v $(pwd)/scripts:/app/scripts:ro \
  balancedns:local -config /app/configs/docker.yaml
```

## 12. Тесты и диагностика

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/balancedns
```

Проверка DNS:

```bash
dig @127.0.0.1 -p 53 example.org A
```

Проверка метрик:

```bash
curl -s http://127.0.0.1:9090/metrics | rg balancedns_
```

## 13. Ограничения текущей версии

- Локальные listener'ы для клиентов: UDP/TCP DNS.
- DoH/DoT в текущей версии используются как протоколы **upstream**, а не как локальный входной listener.
