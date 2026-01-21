# Этап 1: Сборка приложения Go
FROM golang:1.24-alpine AS builder

# Установка зависимостей для сборки
RUN apk add --no-cache build-base gcc unbound-dev lmdb-dev

WORKDIR /app

COPY go.mod go.sum ./
# Загрузка зависимостей
RUN go mod download

COPY . .

# Сборка приложения с поддержкой CGO для unbound
RUN CGO_ENABLED=1 go build -o /dns-resolver -tags="unbound cgo" -ldflags "-s -w" .

# Этап 2: Создание финального легковесного образа
FROM alpine:latest

# Установка зависимостей времени выполнения
RUN apk add --no-cache unbound ca-certificates lmdb-dev

# Установка переменной окружения для ограничения использования CPU
ENV GOMAXPROCS=1

# Получение корневого ключа для валидации DNSSEC
# Получение корневого ключа для валидации DNSSEC (используем из пакета dnssec-root)
RUN mkdir -p /etc/unbound && cp /usr/share/dnssec-root/trusted-key.key /etc/unbound/root.key

# Копирование скомпилированного бинарного файла из этапа сборки
COPY --from=builder /dns-resolver /dns-resolver

# Создание директории для кэша
RUN mkdir -p /tmp/dns_cache.lmdb

# Открытие порта DNS (UDP и TCP) и порта метрик (TCP)
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 9090/tcp

# Установка точки входа для контейнера
ENTRYPOINT ["/dns-resolver"]
