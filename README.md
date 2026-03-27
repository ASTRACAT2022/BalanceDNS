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
request_timeout_ms = 3000

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
3. Запрос нормализуется и проверяется
4. Применяются правила `deny_any` и `deny_dnskey`
5. Проверяется blocklist
6. Проверяются локальные и remote hosts overrides
7. Проверяется кэш
8. Если кэш пуст, запрос идет в upstream
9. Ответ проходит через post-response плагины
10. Ответ может быть сохранен в кэш и возвращается клиенту

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

# Метрики

Экспортируются метрики с префиксом `balancedns_`, включая:

- `balancedns_client_queries`
- `balancedns_client_queries_udp`
- `balancedns_client_queries_tcp`
- `balancedns_client_queries_cached`
- `balancedns_client_queries_expired`
- `balancedns_client_queries_errors`
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

# Структура проекта

- `src/main.rs` — CLI-вход
- `src/libbalancedns/src/config.rs` — парсинг нового и legacy-конфига
- `src/libbalancedns/src/balancedns_runtime.rs` — runtime, listeners, upstream, cache, hosts, blocklist, DoT, DoH, metrics
- `src/libbalancedns/src/plugins.rs` — загрузка и вызов плагинов
- `balancedns.toml` — пример конфигурации
- `balancedns.service` — пример unit-файла
