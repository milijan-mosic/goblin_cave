FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

RUN go install github.com/air-verse/air@latest
RUN go mod tidy

FROM alpine:latest

WORKDIR /app

COPY . .

COPY --from=builder /go/bin/air /usr/local/bin/air
COPY --from=builder /app /app

EXPOSE 10000
CMD ["air", "server", "--port", "10000", "-c", "src/air.toml"]
