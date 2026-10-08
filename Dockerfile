FROM golang:1.27.1-alpine AS builder
ARG VERSION=dev
ARG GO_BUILD_TAGS=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags="${GO_BUILD_TAGS}" -ldflags="-s -w -X main.version=${VERSION}" -o /bouncer .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates libcap \
    && addgroup -S -g 10001 bouncer \
    && adduser -S -D -H -u 10001 -G bouncer bouncer \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 0700 /data
COPY --from=builder /bouncer /usr/local/bin/bouncer
# Set after COPY so the final binary retains permission to bind CLI defaults 80/443.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/bouncer \
    && getcap /usr/local/bin/bouncer | grep -q cap_net_bind_service=ep
# Existing volumes/bind mounts must be migrated to UID/GID 10001 before upgrading.
VOLUME ["/data"]
WORKDIR /data
USER 10001:10001
EXPOSE 80 443 8080
ENTRYPOINT ["bouncer"]
