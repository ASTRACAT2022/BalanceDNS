FROM golang:1.21-alpine as builder

WORKDIR /app

COPY go.mod ./
# COPY go.sum ./ # If exists
RUN go mod download

COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o go-proxy main.go

FROM scratch
COPY --from=builder /app/go-proxy /go-proxy
ENTRYPOINT ["/go-proxy"]
