# syntax=docker/dockerfile:1

FROM golang:1.26 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/secret-sync-controller ./cmd/secret-sync-controller

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/secret-sync-controller /usr/local/bin/secret-sync-controller
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/secret-sync-controller"]
