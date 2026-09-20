# BalanceDNS — dev fork build (multi-stage, static Go binary).
# Matches the prod fork layout: WORKDIR /app, binary at /usr/local/bin/balancedns,
# configs/ and scripts/ copied under /app so Lua-relative paths resolve.

FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/balancedns ./cmd/balancedns

FROM scratch
# CA certificates for HTTPS threat feeds (scratch ships none; the golang build
# stage has them). Go honors SSL_CERT_FILE / the standard /etc/ssl/certs path.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs
# WORKDIR must come BEFORE the relative COPYs so ./scripts and ./configs land
# under /app (Docker resolves COPY dest against the current WORKDIR).
WORKDIR /app
COPY --from=build /out/balancedns /usr/local/bin/balancedns
COPY scripts ./scripts
COPY configs ./configs
ENTRYPOINT ["/usr/local/bin/balancedns"]
