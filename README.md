# 🐱 ASTRACAT DNS Resolver

A high-performance DNS resolver with caching, prefetching, and metrics.

### Features

- Recursive DNS resolution
- SLRU cache with prefetching
- Stale-while-revalidate caching strategy
- DNSSEC validation
- Prometheus metrics
- Worker pool for concurrent resolution

### Installation

```bash
./install.sh
```

### Usage

```bash
./astracat-dns
```

The resolver will listen on port 5053 by default.

### Configuration

Configuration is currently hardcoded in `internal/config/config.go`. Future versions will support configuration files.

### Prometheus и Grafana интеграция

DNS-резолвер имеет встроенную поддержку Prometheus для мониторинга производительности и состояния. Метрики доступны по адресу `http://localhost:9090/metrics`.

#### Настройка Prometheus

1. Установите Prometheus, если он еще не установлен:
   ```bash
   # Для macOS
   brew install prometheus
   
   # Для Ubuntu/Debian
   sudo apt-get install prometheus
   ```

2. Добавьте следующую конфигурацию в ваш файл `prometheus.yml`:
   ```yaml
   scrape_configs:
     - job_name: 'astracat-dns'
       scrape_interval: 15s
       static_configs:
         - targets: ['localhost:9090']
   ```

3. Запустите Prometheus:
   ```bash
   prometheus --config.file=prometheus.yml
   ```

#### Настройка Grafana

1. Установите Grafana, если она еще не установлена:
   ```bash
   # Для macOS
   brew install grafana
   
   # Для Ubuntu/Debian
   sudo apt-get install grafana
   ```

2. Запустите Grafana:
   ```bash
   # Для macOS
   brew services start grafana
   
   # Для Ubuntu/Debian
   sudo systemctl start grafana-server
   ```

3. Откройте Grafana в браузере по адресу `http://localhost:3000` (логин/пароль по умолчанию: admin/admin)

4. Добавьте Prometheus как источник данных:
   - Перейдите в "Configuration" -> "Data Sources" -> "Add data source"
   - Выберите "Prometheus"
   - Укажите URL: `http://localhost:9100` (или другой порт, на котором запущен Prometheus)
   - Нажмите "Save & Test"

5. Импортируйте дашборд:
   - Перейдите в "Create" -> "Import"
   - Создайте новый дашборд с панелями для следующих метрик:
     - `dns_resolver_qps` - запросы в секунду
     - `dns_resolver_total_queries` - общее количество запросов
     - `dns_resolver_cache_probation_size` и `dns_resolver_cache_protected_size` - размер кэша
     - `dns_resolver_query_types_total` - типы запросов
     - `dns_resolver_response_codes_total` - коды ответов
     - `dns_resolver_top_latency_domains_ms` - домены с наибольшей задержкой
     - `dns_resolver_cpu_usage_percent` и `dns_resolver_memory_usage_percent` - использование ресурсов

### Доступные метрики

- **Основные метрики**:
  - `dns_resolver_qps` - запросы в секунду
  - `dns_resolver_total_queries` - общее количество запросов
  - `dns_resolver_cache_probation_size` - размер пробного сегмента кэша
  - `dns_resolver_cache_protected_size` - размер защищенного сегмента кэша

- **Метрики производительности**:
  - `dns_resolver_cpu_usage_percent` - использование CPU
  - `dns_resolver_memory_usage_percent` - использование памяти
  - `dns_resolver_goroutine_count` - количество горутин
  - `dns_resolver_network_sent_bytes` - отправлено байт по сети
  - `dns_resolver_network_recv_bytes` - получено байт по сети

- **DNS-специфичные метрики**:
  - `dns_resolver_top_nx_domains` - домены с NXDOMAIN ответами
  - `dns_resolver_top_latency_domains_ms` - домены с наибольшей задержкой
  - `dns_resolver_query_types_total` - типы запросов
  - `dns_resolver_response_codes_total` - коды ответов

### License

MIT
<img width="1980" height="1180" alt="cd118a5a-a7a2-402d-9159-960b177a241b" src="https://github.com/user-attachments/assets/9a05ce2e-16ae-4f55-9074-117002e3f09f" />

---

## ✨ Преимущества

- ⚡ **Скорость** — оптимизирован под высокую производительность, сравнимую с Cloudflare и Google DNS.  
- 🧠 **Умный кэш** — многоуровневый хэш-кэш (L1/L2) с поддержкой TTL, negative caching и агрессивного хранения.  
- 🔁 **Полная рекурсия и DNSSEC** — резолвер ходит к корневым серверам и сам выполняет процесс разрешения, без внешних форвардеров.  
- 🧩 **Лёгкая расширяемость** — простая структура, под которую легко писать плагины и новые модули.  
- 🤫 **Без лишних логов** — работает тихо, без перегрузки системы ненужной информацией.  
- 🛠 **Простая установка** — достаточно `git clone` + `./install.sh`, и резолвер готов к работе.  
- 🖥 **Работает из коробки** — по умолчанию слушает порт **5053** на `127.0.0.1`.  

---

## 🚀 Установка

Установить **ASTRACAT DNS Resolver** очень просто:  

```bash
# Скачиваем репозиторий
git clone https://github.com/ASTRACAT2022/The-ASTRACAT-DNS-Resolver.git

# Переходим в директорию проекта
cd The-ASTRACAT-DNS-Resolver

# Запускаем установку и потом еще раз после генерацыии ключей 
./install.sh

---

## 📊 Metrics

ASTRACAT DNS Resolver exposes a Prometheus metrics endpoint at `/metrics` on the address specified by `MetricsAddr` in your configuration (defaulting to port 9090).

### Available Metrics

| Metric Name                               | Description                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------- |
| `dns_resolver_qps`                        | Queries per second.                                                         |
| `dns_resolver_total_queries`              | Total number of DNS queries.                                                |
| `dns_resolver_cache_probation_size`       | Size of the probation segment of the cache.                                 |
| `dns_resolver_cache_protected_size`       | Size of the protected segment of the cache.                                 |
| `dns_resolver_cpu_usage_percent`          | Current CPU usage percentage.                                               |
| `dns_resolver_memory_usage_percent`       | Current memory usage percentage.                                            |
| `dns_resolver_goroutine_count`            | Current number of goroutines.                                               |
| `dns_resolver_network_sent_bytes`         | Total network bytes sent.                                                   |
| `dns_resolver_network_recv_bytes`         | Total network bytes received.                                               |
| `dns_resolver_top_nx_domains`             | Top domains with NXDOMAIN responses.                                        |
| `dns_resolver_top_latency_domains_ms`     | Top domains by average query latency in milliseconds.                       |
| `dns_resolver_query_types_total`          | Total number of queries by type.                                            |
| `dns_resolver_response_codes_total`       | Total number of responses by code.                                          |
| `dns_resolver_unbound_errors_total`       | Total number of errors from the Unbound resolver.                           |
| `dns_resolver_dnssec_validation_total`    | Total number of DNSSEC validation results by type (bogus, secure, insecure). |
| `dns_resolver_cache_revalidations_total`  | Total number of cache revalidations.                                        |
| `dns_resolver_cache_hits_total`           | Total number of cache hits.                                                 |
| `dns_resolver_cache_misses_total`         | Total number of cache misses.                                               |
| `dns_resolver_cache_evictions_total`      | Total number of cache evictions.                                            |
| `dns_resolver_lmdb_loads_total`           | Total number of items loaded from LMDB.                                     |
| `dns_resolver_lmdb_errors_total`          | Total number of LMDB errors.                                                |
| `dns_resolver_prefetches_total`           | Total number of cache prefetches.                                           |
