# Astracat DNS Resolver (Rust Version)

Высокопроизводительный, многофункциональный DNS-резолвер, написанный на Rust.

## Возможности
-   🚀 **Высокая производительность**: Построен на Tokio, Rust и **Hyper** для асинхронного I/O.
-   💾 **Умное кэширование**:
    -   **Sharded Cache**: Шардированный in-memory/LMDB кэш для максимальной параллельности.
    -   **Smart Prefetch**: Фоновое обновление популярных записей (zero-latency для клиента).
    -   **Serve-Stale**: Отдача устаревших данных при сбоях апстрима (повышенная надежность).
-   📊 **Метрики Prometheus**: Встроенный сервер метрик на порту `:9090` для мониторинга QPS, задержек, prefetch-операций.
-   🛡️ **Приватность и Безопасность**:
    -   **ODoH (Oblivious DoH)**: Полная поддержка анонимных запросов через встроенный Go-прокси.
    -   **DoH / DoT**: Поддержка DNS-over-HTTPS и DNS-over-TLS.
    -   **QNAME Minimization**: Минимизация передаваемых данных (через Unbound).
-   🛡️ **Система плагинов**:
    -   **Hosts**: Поддержка пользовательских файлов hosts.
    -   **AdBlock**: Встроенная блокировка рекламных доменов.
    -   **Rate Limiting**: Защита от DDoS и злоупотреблений.
-   💻 **Гибридная архитектура**: Core на Rust + Proxy на Go для максимальной гибкости.

## Установка

### Предварительные требования
-   Установленный Rust (Cargo): [https://rustup.rs/](https://rustup.rs/)
-   **Linux**: `build-essential`, `libssl-dev`, `liblmdb-dev`
-   **macOS**: Xcode Command Line Tools

### Быстрый старт
1.  Клонируйте репозиторий:
    ```bash
    git clone https://github.com/your-repo/astracat-dns-resolver.git
    cd astracat-dns-resolver
    ```

2.  Запустите установщик:
    ```bash
    ./install.sh
    ```
    Этот скрипт выполнит следующие действия:
    -   Соберет проект в режиме release.
    -   Установит бинарный файл в `/usr/local/bin/astracat-dns`.
    -   Установит конфигурацию в `/etc/astracat-dns/config.yaml`.
    -   Настроит и запустит системную службу (Systemd на Linux, Launchd на macOS).

## Конфигурация
Основной файл конфигурации находится по пути `/etc/astracat-dns/config.yaml`.

Пример конфигурации:
```yaml
# Адреса для прослушивания
listen_addr: "0.0.0.0:53"
metrics_addr: "0.0.0.0:9090"
admin_addr: "0.0.0.0:8080"

# Настройки резолвера
resolver:
  type: "godns"
  upstream_timeout: 5s
  max_workers: 10

# Плагины
adblock:
  enabled: true
  blocklist_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

## Использование ODoH (Oblivious DoH)
Сервер автоматически генерирует ключи шифрования при запуске.

-   **Endpoint**: `https://your-domain/dns-query` (принимает `application/oblivious-dns-message`)
-   **Config Endpoint**: `https://your-domain/odohconfigs` (возвращает публичный ключ)

### Пример клиента (Go)
Пример клиента находится в директории `tools/odoh-client`.

## Мониторинг
Метрики доступны по адресу `http://localhost:9090/metrics`.
Вы можете собирать их с помощью Prometheus.

## Разработка
Запуск локально для разработки:
```bash
cargo run
```
Примечание: Для прослушивания порта 53 требуются права `sudo`.

## Лицензия
MIT
