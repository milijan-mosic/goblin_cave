FROM golang:1.23-alpine

WORKDIR /app
COPY . /app

RUN go install github.com/air-verse/air@latest
RUN go mod download
RUN go mod tidy

EXPOSE 10000
RUN cd src/
CMD air server --port 10000 -c air.toml
