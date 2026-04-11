FROM golang:1.23-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/balancedns ./cmd/balancedns

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S balancedns && adduser -S -G balancedns balancedns

WORKDIR /app
COPY --from=builder /out/balancedns /usr/local/bin/balancedns
COPY configs ./configs
COPY scripts ./scripts

USER balancedns
EXPOSE 53/udp 53/tcp 9090
ENTRYPOINT ["/usr/local/bin/balancedns"]
CMD ["-config", "/app/configs/docker.yaml"]
