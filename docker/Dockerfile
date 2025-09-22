# Minimal Dockerfile for Pat (Go-only)

FROM golang:1.21-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/pat-fortress ./

FROM alpine:3.18
RUN addgroup -g 1000 pat && adduser -D -u 1000 -G pat pat \
    && apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/pat-fortress /app/pat-fortress
COPY web /app/web
USER pat
EXPOSE 1025 8025
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/app/pat-fortress", "--version"]
ENTRYPOINT ["/app/pat-fortress"]
