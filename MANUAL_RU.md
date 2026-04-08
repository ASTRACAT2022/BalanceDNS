# BalanceDNS: Полное руководство пользователя

BalanceDNS — это высокопроизводительный DNS-прокси и кэширующий балансировщик, написанный на Rust. Он поддерживает UDP, TCP, DNS-over-TLS (DoT) и DNS-over-HTTPS (DoH).

## 🚀 Деплой и установка

### Автоматическая установка

Самый простой способ установить BalanceDNS — использовать скрипт `install.sh`. Он выполнит компиляцию, создаст пользователя в системе, настроит права доступа и установит `systemd` сервис.

```bash
git clone https://github.com/ВашРепозиторий/BalanceDNS.git
cd BalanceDNS
sudo ./install.sh
```

Во время установки скрипт запросит:
1. **IP-адрес сервера** (по умолчанию определяется автоматически).
2. **Основной upstream DNS** (например, 1.1.1.1).
3. **Резервный upstream DNS**.
4. **Специальный DNS для .ru зоны** (например, Яндекс.DNS).

### Ручная сборка

Если вы хотите собрать бинарный файл без установки в систему:

```bash
cargo build --release
./target/release/balancedns -c balancedns.lua
```

## ⚙️ Настройка (Lua)

Все настройки BalanceDNS теперь задаются исключительно в формате **Lua**. Файл конфигурации по умолчанию находится в `/etc/balancedns.lua`.

### Пример конфигурации

Конфигурационный файл должен возвращать таблицу:

```lua
return {
    server = {
        udp_listen = "0.0.0.0:53",
        tcp_listen = "0.0.0.0:53",
        dot_listen = "0.0.0.0:853",
        doh_listen = "0.0.0.0:443",
    },

    tls = {
        cert_pem = "/var/lib/balancedns/tls/server.crt",
        key_pem = "/var/lib/balancedns/tls/server.key",
    },

    balancing = {
        algorithm = "fastest", -- fastest, round_robin, consistent_hash
    },

    cache = {
        enabled = true,
        max_size = 100000,
        ttl_seconds = 7200,
    },

    upstreams = {
        {
            name = "cloudflare-udp",
            proto = "udp",
            addr = "1.1.1.1:53",
            pool = "default",
            weight = 5,
        },
        {
            name = "google-doh",
            proto = "doh",
            url = "https://8.8.8.8/dns-query",
            pool = "default",
            weight = 5,
        },
    },

    routing_rules = {
        {
            suffix = ".",
            upstreams = { "cloudflare-udp", "google-doh" },
        },
        {
            suffix = ".ru.",
            upstreams = { "yandex-dns" },
        },
    },
}
```

### Основные разделы

- `server`: Настройка сетевых слушателей (UDP, TCP, DoT, DoH).
- `tls`: Пути к сертификатам (необходимы для DoT и DoH).
- `balancing.algorithm`: Алгоритм выбора вышестоящего сервера. `fastest` выбирает сервер с наименьшей задержкой.
- `cache`: Настройки кэширования ответов.
- `upstreams`: Список серверов, куда будут пересылаться запросы. Поддерживаются протоколы `udp` и `doh`.
- `routing_rules`: Гибкие правила маршрутизации на основе суффикса домена.
- `hosts_local`: Локальные переопределения (аналог `/etc/hosts`).
- `hosts_remote` / `blocklist_remote`: Списки доменов, загружаемые из внешних источников (например, для блокировки рекламы).

## 📊 Мониторинг и обслуживание

### Статус сервиса

```bash
systemctl status balancedns
```

### Просмотр логов

```bash
journalctl -u balancedns -f
```

### Проверка работы DNS

```bash
dig @127.0.0.1 google.com
```

### Метрики (Prometheus)

Метрики доступны в формате Prometheus по адресу, указанному в `metrics.listen` (по умолчанию `http://127.0.0.1:9100/metrics`).

## 🛡️ Безопасность и надежность

- **Watchdog**: Сервис автоматически перезагружается при критических сбоях.
- **Health Check**: Скрипт в `scripts/healthcheck.sh` периодически проверяет отзывчивость сервера.
- **Privilege Drop**: Если запущен от root, сервер сбрасывает привилегии до указанного пользователя.
- **Sandbox**: Lua-плагины выполняются в защищенной песочнице с ограничениями по памяти и инструкциям.

## 🗑️ Удаление

```bash
sudo ./uninstall.sh
```
