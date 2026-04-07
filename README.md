# BalanceDNS

BalanceDNS — DNS-прокси и кэширующий балансировщик на Rust с поддержкой UDP, TCP, DoT, DoH, remote hosts, remote blocklist, метрик Prometheus и подключаемых плагинов.

# Что умеет

- Принимать DNS-запросы по UDP и TCP
- Принимать DNS-over-TLS
- Принимать DNS-over-HTTPS
- Отправлять запросы в UDP-upstream и DoH-upstream
- Балансировать трафик между upstream-серверами по round robin с учетом weight
- Кэшировать ответы
- Применять локальные DNS-переопределения
- Загружать remote hosts из HTTP(S)-источника
- Загружать remote blocklist из HTTP(S)-источника
- Отдавать метрики в формате Prometheus
- Расширяться через внешние плагины в виде динамических библиотек
- Поддерживать новый конфиг BalanceDNS и legacy-конфиг старого формата

# Ограничения текущей реализации

- Server-side TLS требуется для DoT и DoH, поэтому нужно указать `tls.cert_pem` и `tls.key_pem`
- DoH-upstream сейчас используется через POST `application/dns-message`
- Для `https://8.8.8.8/dns-query` нельзя слать пустой GET без параметра `dns`; сервер ожидает корректное DNS-сообщение
- Плагинный ABI низкоуровневый и работает через экспорт C-символов
- Внутри репозитория остались legacy-модули исходного ядра, но основной запуск идет через runtime BalanceDNS

# Быстрый старт

```bash
cargo run -- -c ./balancedns.toml
```

Если нужен релизный бинарник:

```bash
cargo build --release
./target/release/balancedns -c ./balancedns.toml
```

# Автонастройка

Есть интерактивный скрипт, который сам собирает конфиг из твоих ответов, включает Prometheus и предлагает сборку/установку:

```bash
./scripts/autosetup.sh
```

Полный конструктор конфигурации + автоинсталлер/deploy:

```bash
./scripts/install-wizard.sh
```

Миграция с Knot Resolver (`kresd.conf`) в BalanceDNS:

```bash
./scripts/migrate-from-knot.sh --knot-config /etc/knot-resolver/kresd.conf --output ./balancedns.migrated.toml
./scripts/migrate-from-knot.sh --knot-config /etc/knot-resolver/kresd.conf --output ./balancedns.migrated.toml --deploy --config-path /etc/balancedns.toml
```

Примечание: скрипт миграции поддерживает Knot Resolver (forwarding/recursive). Конфиг Knot DNS authoritative напрямую не конвертируется.

# Admin CLI

Добавлен админский CLI с live-графиками и техстатусом:

```bash
cargo run --bin astracatdnscli -- status -c ./balancedns.toml
cargo run --bin astracatdnscli -- watch -c ./balancedns.toml -i 2
```

Для установленного сервера команда обычно доступна как:

```bash
astracatdnscli watch -c /etc/balancedns.toml
```

# Конфиг

Пример рабочего конфига находится в файле `balancedns.toml`.

Полный пример:

```toml
[server]
udp_listen = "0.0.0.0:5353"
tcp_listen = "0.0.0.0:5353"
dot_listen = "0.0.0.0:8853"
doh_listen = "0.0.0.0:8443"

[tls]
cert_pem = "tls/server.crt"
key_pem = "tls/server.key"

[balancing]
algorithm = "round_robin"

[security]
deny_any = true
deny_dnskey = true
request_timeout_ms = 1500

[cache]
enabled = true
max_size = 20000
ttl_seconds = 600

[metrics]
listen = "127.0.0.1:9100"

[hosts_local]
# "example.com." = "1.2.3.4"

[hosts_remote]
url = "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass"
refresh_seconds = 300
ttl_seconds = 60

[blocklist_remote]
url = "https://raw.githubusercontent.com/Zalexanninev15/NoADS_RU/main/ads_list.txt"
refresh_seconds = 300

[plugins]
libraries = []

[lua]
scripts = []

[global]
threads_udp = 8
threads_tcp = 4
max_tcp_clients = 4096

[[upstreams]]
name = "cloudflare-doh"
proto = "doh"
url = "https://1.1.1.1/dns-query"
pool = "default"
weight = 5

[[upstreams]]
name = "google-doh"
proto = "doh"
url = "https://8.8.8.8/dns-query"
pool = "default"
weight = 5

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1

[[upstreams]]
name = "google-udp"
proto = "udp"
addr = "8.8.8.8:53"
pool = "default"
weight = 1
```

# Разделы конфига

## [server]

- `udp_listen` — адрес UDP listener
- `tcp_listen` — адрес TCP listener
- `dot_listen` — адрес DoT listener
- `doh_listen` — адрес DoH listener

Можно включать только нужные слушатели. Если секция не задана, listener не поднимается.

## [tls]

- `cert_pem` — путь к PEM-сертификату
- `key_pem` — путь к PEM-ключу

Обязателен для DoT и DoH.

## [balancing]

- `algorithm = "round_robin"` — циклический выбор upstream с учетом `weight`

Если weights заданы как `5, 5, 1, 1`, DoH-upstream будут выбираться чаще UDP-upstream.

## [security]

- `deny_any` — блокировать ANY-запросы ответом REFUSED
- `deny_dnskey` — блокировать DNSKEY-запросы ответом REFUSED
- `request_timeout_ms` — таймаут запроса к upstream

## [cache]

- `enabled` — включить или отключить кэш
- `max_size` — максимальное число записей
- `ttl_seconds` — TTL по умолчанию, который используется в ряде локальных сценариев и fallback-логике

## [metrics]

- `listen` — адрес HTTP endpoint для Prometheus

Метрики доступны по пути:

```text
http://127.0.0.1:9100/metrics
```

## [hosts_local]

Локальные переопределения доменов:

```toml
[hosts_local]
"router.home." = "192.168.1.1"
"service.internal." = "10.10.10.5"
```

Поддерживаются IPv4 и IPv6. Для IPv4 формируется A-ответ, для IPv6 — AAAA-ответ.

## [hosts_remote]

Загрузка внешнего списка доменов по HTTP(S):

- `url` — адрес файла
- `refresh_seconds` — период обновления
- `ttl_seconds` — TTL для ответов из remote hosts

Для сценария "отвечать из удаленного hosts-файла и обновлять его каждый час"
используй именно `[hosts_remote]`, а не Lua или native plugin. Этот путь уже
встроен в runtime, работает в fast path и обновляет карту доменов в фоне.

Пример production-конфига под публичный сервер:

- [production-144.31.151.64.toml](/Users/astracat/BalanceDNS/examples/configs/production-144.31.151.64.toml)

Поддерживаются типичные форматы:

- `1.2.3.4 example.com`
- `example.com 1.2.3.4`
- `/etc/hosts`-подобные записи

## [blocklist_remote]

Загрузка доменных блоклистов:

- `url` — адрес файла
- `refresh_seconds` — период обновления

Если домен попадает в blocklist, BalanceDNS возвращает NXDOMAIN.

## [plugins]

- `libraries` — список `.so`, `.dylib` или `.dll`

Пример:

```toml
[plugins]
libraries = [
  "plugins/libbalancedns_filter.dylib"
]
```

## [lua]

- `scripts` — список Lua-компонентов, которые загружаются при старте

Пример:

```toml
[lua]
scripts = [
  "examples/lua/query_logger.lua"
]
```

Lua-компоненты выполняются внутри встроенного Lua runtime и предназначены для безопасной кастомной логики на hot path.

## [global]

- `threads_udp` — число UDP worker-потоков
- `threads_tcp` — число TCP acceptor-потоков (legacy/совместимость)
- `max_tcp_clients` — лимит одновременных TCP/DoT/DoH-соединений

Для высокой нагрузки обычно полезно ставить `threads_udp` примерно `2 x CPU cores`.

## [[upstreams]]

Поддерживаются два типа:

### UDP upstream

```toml
[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1
```

### DoH upstream

```toml
[[upstreams]]
name = "cloudflare-doh"
proto = "doh"
url = "https://1.1.1.1/dns-query"
pool = "default"
weight = 5
```

Поля:

- `name` — имя upstream
- `proto` — `udp` или `doh`
- `addr` — адрес для UDP
- `url` — URL для DoH
- `pool` — логическая группа
- `weight` — относительный вес

# Протоколы

## UDP

Подходит для локальных резолверов, роутеров, встроенных устройств и большинства стандартных клиентов.

## TCP

Используется для крупных DNS-ответов, строгих клиентов и совместимости с классическим DNS-over-TCP.

## DoT

DoT поднимается на отдельном TCP/TLS listener и работает с обычным DNS wire format внутри TLS-сессии.

## DoH

Поддерживаются:

- `GET /dns-query?dns=...`
- `POST /dns-query` c `Content-Type: application/dns-message`

Ответы возвращаются как `application/dns-message`.

# Как работает обработка запроса

1. Входящий запрос принимается на UDP, TCP, DoT или DoH
2. Если есть pre-query плагины, они могут изменить пакет или сразу вернуть готовый ответ
3. Если есть Lua pre-query компоненты, они тоже могут изменить пакет или вернуть готовый ответ
4. Запрос нормализуется и проверяется
5. Применяются правила `deny_any` и `deny_dnskey`
6. Проверяется blocklist
7. Проверяются локальные и remote hosts overrides
8. Проверяется кэш
9. Если кэш пуст, запрос идет в upstream
10. Ответ проходит через post-response плагины и Lua-компоненты
11. Ответ может быть сохранен в кэш и возвращается клиенту

# Плагины

BalanceDNS загружает плагины как динамические библиотеки. Плагин может:

- изменить входящий DNS-пакет до основной обработки
- вернуть готовый DNS-ответ без обращения к upstream
- модифицировать исходящий DNS-ответ

## Экспортируемые символы

Плагин может экспортировать:

- `balancedns_plugin_pre_query`
- `balancedns_plugin_post_response`
- `balancedns_plugin_free`

## ABI

Сигнатуры ожидаются такие:

```c
int balancedns_plugin_pre_query(const uint8_t *input, size_t input_len, PluginOutput *output);
int balancedns_plugin_post_response(const uint8_t *input, size_t input_len, PluginOutput *output);
void balancedns_plugin_free(uint8_t *ptr, size_t len);
```

Где:

- `0` — пакет не перехвачен; если `output` заполнен, пакет считается модифицированным
- `1` — плагин вернул готовый ответ

Структура результата:

```c
typedef struct {
    uint8_t *ptr;
    size_t len;
} PluginOutput;
```

## Минимальный каркас плагина на Rust

```rust
#[repr(C)]
pub struct PluginOutput {
    pub ptr: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub extern "C" fn balancedns_plugin_pre_query(
    input: *const u8,
    input_len: usize,
    output: *mut PluginOutput,
) -> i32 {
    let _ = (input, input_len, output);
    0
}

#[no_mangle]
pub extern "C" fn balancedns_plugin_post_response(
    input: *const u8,
    input_len: usize,
    output: *mut PluginOutput,
) -> i32 {
    let _ = (input, input_len, output);
    0
}

#[no_mangle]
pub extern "C" fn balancedns_plugin_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}
```

# Lua-компоненты

Lua-компоненты нужны для безопасной кастомизации без сборки `.so/.dylib`.

Поддерживаются хуки:

- `balancedns_pre_query(packet)`
- `balancedns_post_response(packet)`

Возврат:

- `return nil, false` — ничего не менять
- `return raw_packet, false` — заменить пакет и продолжить обработку
- `return raw_packet, true` — сразу вернуть этот пакет как готовый ответ

В Lua доступны helper-функции:

- `balancedns.qname(packet)`
- `balancedns.qtype(packet)`
- `balancedns.tid(packet)`
- `balancedns.rcode(packet)`
- `balancedns.len(packet)`
- `balancedns.hex(packet)`
- `balancedns.from_hex(hex)`
- `balancedns.log(message)`

Пример боевого скрипта:

- [query_logger.lua](/Users/astracat/BalanceDNS/examples/lua/query_logger.lua)

Подробный мануал по Lua и sandbox:

- [LUA_SANDBOX_MANUAL.md](/Users/astracat/BalanceDNS/LUA_SANDBOX_MANUAL.md)

# Метрики

Экспортируются метрики с префиксом `balancedns_`, включая:

- `balancedns_client_queries`
- `balancedns_client_queries_udp`
- `balancedns_client_queries_tcp`
- `balancedns_client_queries_dot`
- `balancedns_client_queries_doh`
- `balancedns_client_queries_cached`
- `balancedns_client_queries_expired`
- `balancedns_client_queries_dropped`
- `balancedns_client_queries_errors`
- `balancedns_client_connections_rejected`
- `balancedns_upstream_sent`
- `balancedns_upstream_received`
- `balancedns_upstream_timeout`
- `balancedns_cache_frequent_len`
- `balancedns_cache_recent_len`
- `balancedns_cache_test_len`

# systemd

Пример unit-файла находится в `balancedns.service`.

Минимальный запуск:

```ini
[Service]
ExecStart=/usr/sbin/balancedns --config /etc/balancedns.toml
Restart=always
```

# Legacy-конфиг

BalanceDNS все еще умеет читать старый формат с секциями:

- `[upstream]`
- `[network]`
- `[cache]`
- `[global]`
- `[dnstap]`
- `[webservice]`

Это полезно для мягкой миграции, но для новых инсталляций рекомендуется использовать только `balancedns.toml`.

# Проверка

Базовые команды для проверки:

```bash
cargo check
cargo test
cargo fmt -- --check
```

# Практические рекомендации

- Для публичного DoT и DoH используй отдельные порты и валидный TLS-сертификат
- Для production лучше держать одновременно DoH и UDP-upstream, чтобы был запасной путь
- Для aggressive-блокировки рекламы используй `blocklist_remote`
- Для локальных внутренних сервисов используй `hosts_local`
- Для кастомной фильтрации, телеметрии или policy routing используй плагины
- Для безопасной логики и быстрых экспериментов на hot path предпочитай Lua-компоненты вместо native plugins
- Для высоких нагрузок следи за `balancedns_client_queries_dropped` и `balancedns_client_connections_rejected`

# Структура проекта

- `src/main.rs` — CLI-вход
- `src/bin/astracatdnscli.rs` — admin CLI (status/watch, live-графики)
- `src/libbalancedns/src/config.rs` — парсинг нового и legacy-конфига
- `src/libbalancedns/src/balancedns_runtime.rs` — runtime, listeners, upstream, cache, hosts, blocklist, DoT, DoH, metrics
- `src/libbalancedns/src/plugins.rs` — загрузка и вызов плагинов
- `src/libbalancedns/src/lua_plugin.rs` — встроенный Lua runtime и Lua sandbox
- `balancedns.toml` — пример конфигурации
- `balancedns.service` — пример unit-файла
- `LUA_SANDBOX_MANUAL.md` — продвинутый мануал по Lua и sandbox
- `scripts/autosetup.sh` — интерактивная автонастройка конфига/сборки
- `scripts/install-wizard.sh` — конструктор конфига + автоинсталлер/deploy
- `scripts/migrate-from-knot.sh` — миграция с Knot Resolver в BalanceDNS
