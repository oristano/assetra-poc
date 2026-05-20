FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy go.mod first and pre-download the module graph.
# This layer is cached as long as go.mod doesn't change.
COPY go.mod ./
RUN go mod download all

# Copy source, generate a complete go.sum, then build.
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o assetra-poc ./cmd/assetra-poc

# ---

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/assetra-poc .

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT ["./assetra-poc"]
