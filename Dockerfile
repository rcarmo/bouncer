FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bouncer .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /bouncer /usr/local/bin/bouncer
EXPOSE 443 8080
ENTRYPOINT ["bouncer"]
