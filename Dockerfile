FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /scanner ./cmd/scanner

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git
COPY --from=builder /scanner /usr/local/bin/scanner
ENTRYPOINT ["scanner"]
