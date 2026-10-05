FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /bouncer .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=builder /bouncer /usr/local/bin/bouncer
EXPOSE 80 443 8080
ENTRYPOINT ["bouncer"]
