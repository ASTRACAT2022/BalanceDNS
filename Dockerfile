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
# unbound-anchor возвращает код 1 при успешном создании ключа (bootstrap), поэтому игнорируем ошибку
RUN mkdir -p /etc/unbound && (unbound-anchor -a /etc/unbound/root.key || true)

# Создание директории для кэша и конфигов
RUN mkdir -p /app/cache

# Копирование скомпилированного бинарного файла из этапа сборки
COPY --from=builder /dns-resolver /app/dns-resolver

# Копирование конфигурации и сертификатов (чтобы образ был самодостаточным)
# WARNING: Baking secrets (certificates) into the image is a security risk.
# This is done per specific user request for a self-contained artifact.
COPY config.yaml /app/config.yaml
COPY hosts /app/hosts
COPY cert /app/cert

WORKDIR /app

# Открытие порта DNS (UDP и TCP) и порта метрик (TCP)
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 9090/tcp

# Установка точки входа для контейнера
ENTRYPOINT ["/app/dns-resolver"]
