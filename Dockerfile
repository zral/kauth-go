FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kauth ./cmd/kauth

FROM scratch
COPY --from=builder /build/kauth /kauth
COPY --from=builder /build/templates /templates
COPY --from=builder /build/static /static
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["/kauth"]
