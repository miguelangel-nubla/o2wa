# Local build from source. Releases are built by goreleaser with Dockerfile.goreleaser.
FROM golang:1 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o o2wa .

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/o2wa /bin/o2wa
COPY entrypoint.sh /entrypoint.sh

ENV TRUSTED_CA_PATH=/trusted-ca-certs

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/o2wa"]
