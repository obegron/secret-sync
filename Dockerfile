# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /app

RUN apk add --no-cache ca-certificates \
    && echo "secret-sync:x:10001:10001:secret-sync:/:" > /etc/passwd_scratch

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /app/secret-sync-controller ./cmd/secret-sync-controller

FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd_scratch /etc/passwd
COPY --from=builder /app/secret-sync-controller /app/secret-sync-controller

USER 10001
EXPOSE 8080
ENTRYPOINT ["/app/secret-sync-controller"]
