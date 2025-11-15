# Stage 1: Build the Go binary
FROM golang:1.20-bullseye AS builder

WORKDIR /app

# Install dependencies for unbound
RUN apt-get update && apt-get install -y unbound-anchor

# Generate root.key
RUN unbound-anchor -a /app/root.key

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -tags="unbound cgo" -o /dns-resolver .

# Stage 2: Create the final image
FROM debian:bullseye-slim

WORKDIR /

COPY --from=builder /dns-resolver /dns-resolver
COPY --from=builder /app/root.key /app/root.key
COPY config.yaml /config.yaml

EXPOSE 5053/udp 5053/tcp 9090/tcp

ENTRYPOINT ["/dns-resolver"]
