FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod ./
COPY go.sum ./
RUN go mod download

RUN go install github.com/air-verse/air@latest
RUN go mod tidy

FROM golang:1.23-alpine

WORKDIR /code

COPY . .

COPY --from=builder /go/bin/air /usr/local/bin/air
COPY --from=builder /build /code

EXPOSE 10000
CMD ["air", "server", "--port", "10000"]
