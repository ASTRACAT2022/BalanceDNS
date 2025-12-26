# Astracat DNS Resolver (Rust Version)

Высокопроизводительный, многофункциональный DNS-резолвер, написанный на Rust.

## Возможности
-   🚀 **Высокая производительность**: Построен на Tokio и Rust для асинхронного I/O и безопасности.
-   💾 **Постоянный кэш**: Использует LMDB для быстрого и постоянного кэширования DNS-записей.
-   📊 **Метрики Prometheus**: Встроенный сервер метрик на порту `:9090` для мониторинга QPS, задержек, попаданий в кэш и многого другого.
-   🛡️ **Система плагинов**:
    -   **Hosts**: Поддержка пользовательских файлов hosts.
    -   **AdBlock**: Встроенная блокировка рекламных доменов с использованием внешних списков.
    -   **HTTPS RR**: Поддержка HTTPS resource records (ECH).
    -   **Rate Limiting**: Защита от злоупотреблений (ограничение частоты запросов).
-   🔒 **Безопасный DNS**: Поддержка DNS-over-HTTPS (DoH) и DNS-over-TLS (DoT).
-   💻 **Кроссплатформенность**: Поддержка Linux (Systemd) и macOS (Launchd).

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
