

* `github.com/miekg/dns` — для реализации протокола DNS (серверная часть)
* `github.com/nsmithuk/resolver` — для рекурсивного разрешения и DNSSEC




# DNS Resolver

Полноценный рекурсивный DNS Resolver, созданный как аналог PowerDNS, с высокой производительностью, многоуровневым кэшированием и поддержкой **DNSSEC**.  

## Особенности

- ⚡ **Высокая производительность**: обработка запросов за микросекунды  
- 🗄️ **Многоуровневое кэширование**:  
  - Встроенный кэш в библиотеке `resolver`  
  - Дополнительный кэш приложения с TTL (по умолчанию 5 минут)  
- 🔒 **Поддержка DNSSEC** (валидация подписей)  
- 🌐 Поддержка всех основных типов записей: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`  
- 🧵 **Конкурентная обработка**: каждый запрос обслуживается в отдельной горутине  
- 🔁 **Автоматическое повторение по TCP** при усечении UDP-пакетов  
- 📊 **Логирование**: статистика кэша, время обработки, ошибки  

---

## Требования

- Go **1.25.0+**  
- Доступ в интернет для рекурсивного разрешения  

---

## Установка и запуск

### Автоматическая установка (рекомендуется)

```bash
curl -sSL https://raw.githubusercontent.com/ASTRACAT2022/dns-g/main/install.sh | sudo bash
````

### Ручная установка

```bash
# Клонируем репозиторий
git clone https://github.com/ASTRACAT2022/dns-g.git
cd dns-g

# Ставим зависимости
go mod tidy

# Сборка
go build -o dns_resolver main.go

# Запуск
./dns_resolver
```

По умолчанию сервер запускается на порту **5454** (чтобы не конфликтовать с mDNS).

---

## Использование

### Проверка через `dig`

```bash
# A записи
dig @localhost -p 5454 google.com A +short

# AAAA записи
dig @localhost -p 5454 ipv6.google.com AAAA +short

# MX записи
dig @localhost -p 5454 gmail.com MX +short

# TXT записи
dig @localhost -p 5454 example.com TXT +short

# CNAME записи
dig @localhost -p 5454 www.example.com CNAME +short
```

### Проверка DNSSEC

```bash
dig @localhost -p 5454 gov.ru DNSKEY +dnssec +adflag
```

---

## Производительность

* Первый запрос: **\~300–800ms** (разрешение через интернет)
* Кэшированный запрос: **\~40–100µs** (в тысячи раз быстрее)

Пример теста:

```
Testing example.com A record...
  First query:  OK (Time: .910319000s)
  Second query: OK (Time: .007494000s)
```

---

## Архитектура

* **UDP-сервер** — слушает порт `5454`
* **resolver.Resolver** (`github.com/nsmithuk/resolver`) — выполняет рекурсивное разрешение с DNSSEC
* **Кэш приложения** — дополнительный уровень хранения записей
* **Горутины** — каждая DNS-запрос обрабатывается конкурентно

---

## Конфигурация (фрагмент кода)

```go
const (
    listenPort = 5454
    cacheTTL   = 5 * time.Minute
)

var (
    cache = sync.Map{} // кэш приложения
)

// Пример инициализации резолвера
r := resolver.New([]string{"8.8.8.8:53"}, &resolver.Options{
    DNSSEC: true, // включаем DNSSEC
    TCPFallback: true,
    Timeout: 5 * time.Second,
})
```

---

## Логирование

Пример логов:

```
2025/09/07 13:36:16 Cache miss for example.com A from [::1]:50366
2025/09/07 13:36:17 Resolved example.com A: 8 records
2025/09/07 13:36:17 Request from [::1]:50366 processed in 891.9ms
2025/09/07 13:36:17 Cache hit for example.com A from [::1]:51216
2025/09/07 13:36:17 Request from [::1]:51216 processed in 65.2µs
```

---

## Поддерживаемые типы записей

| Тип   | Описание         | Поддержка            |
| ----- | ---------------- | -------------------- |
| A     | IPv4 адреса      | ✅                    |
| AAAA  | IPv6 адреса      | ✅                    |
| CNAME | Каноническое имя | ✅                    |
| MX    | Mail exchange    | ✅                    |
| NS    | Name servers     | ✅                    |
| TXT   | Текстовые записи | ✅                    |
| SOA   | Authority        | ⏭️ (не используется) |

---

## Файлы проекта

* `main.go` — основной код сервера
* `main_test.go` — юнит-тесты
* `test_dns_resolver.sh` — интеграционное тестирование
* `go.mod` / `go.sum` — зависимости Go
* `README.md` — документация

---

## Лицензия

MIT License

---

## Автор

Разработано как высокопроизводительная альтернатива PowerDNS с использованием Go и современных библиотек.
Для использования в инфраструктуры ASTRACAT 

