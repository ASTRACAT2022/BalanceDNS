# BalanceDNS: политики ответов (RU)

## 1. Где включаются политики

Политики выполняются на этапе `lua_policy` в `routing.chain`:

```yaml
routing:
  chain: ["blacklist", "cache", "lua_policy", "upstream"]
```

Конфиг плагинов:

```yaml
plugins:
  enabled: true
  timeout_ms: 20
  entries:
    - name: "lua-policy"
      runtime: "lua"
      path: "scripts/policy.lua"
```

Плагины идут по порядку в `entries`.

## 2. Контракт политики

Вход в policy:
- `question.domain` (FQDN)
- `question.type` (например `A`, `AAAA`, `MX`)
- `question.qtype` (число)

Допустимые действия:
- `FORWARD` — отправить в upstream
- `BLOCK` — отказ (`REFUSED`)
- `REWRITE` — изменить домен и/или тип, затем продолжить цепочку
- `LOCAL_DATA` — отдать локальный ответ (A/AAAA)

## 3. Lua: базовые рецепты

### 3.1 Блокировка доменов

```lua
function handle(question)
  local d = string.lower(question.domain or "")
  if d == "ads.example." then
    return { action = "BLOCK" }
  end
  return { action = "FORWARD" }
end
```

### 3.2 Переписывание домена

```lua
function handle(question)
  if question.domain == "old.example." then
    return {
      action = "REWRITE",
      rewrite_domain = "new.example.",
      rewrite_type = "A"
    }
  end
  return { action = "FORWARD" }
end
```

### 3.3 Локальный ответ (spoof)

```lua
function handle(question)
  if question.domain == "internal.example." then
    return {
      action = "LOCAL_DATA",
      local_data = {
        ttl = 60,
        ips = {"10.0.0.10", "fd00::10"}
      }
    }
  end
  return { action = "FORWARD" }
end
```

## 4. go_exec policy

Можно писать policy как отдельный бинарник.

### 4.1 Конфиг

```yaml
plugins:
  enabled: true
  timeout_ms: 20
  entries:
    - name: "go-policy"
      runtime: "go_exec"
      path: "/opt/balancedns/plugins/go-policy"
      timeout_ms: 10
```

### 4.2 I/O формат

stdin:

```json
{"question":{"domain":"example.org.","type":"A","qtype":1}}
```

stdout:

```json
{"action":"FORWARD"}
```

или:

```json
{"action":"LOCAL_DATA","local_data":{"ips":["127.0.0.2"],"ttl":30}}
```

## 5. Рекомендуемые шаблоны политики

1. Security-first:
- Сначала BLOCK для явных вредных доменов
- Потом REWRITE для нормализации/канареек
- Потом LOCAL_DATA для внутренних хостов
- Иначе FORWARD

2. Split DNS:
- Для внутренних зон (`corp.local.`) отдавать LOCAL_DATA
- Для остального FORWARD

3. Gradual rollout:
- По части доменов делать REWRITE на canary backend
- Быстро отключать правилом BLOCK/REWRITE rollback

## 6. Ограничения и best practices

- Всегда используйте FQDN с точкой: `example.org.`
- Учитывайте timeout плагина (`plugins.timeout_ms`)
- Для тяжелой логики лучше `go_exec`, для быстрых правил — Lua
- Избегайте больших списков прямо в коде Lua: лучше читать из файлов при старте и кешировать в таблицах

## 7. Тестирование политик

Локально:

```bash
go run ./cmd/balancedns -config configs/balancedns.yaml

# проверка BLOCK
dig @127.0.0.1 -p 5353 ads.example A

# проверка LOCAL_DATA
dig @127.0.0.1 -p 5353 internal.example A
```

Диагностика состояния сервиса:

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s http://127.0.0.1:9090/statusz
```
