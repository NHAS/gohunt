# Builder
FROM golang:1.23 AS builder

WORKDIR /app/
COPY . /app

RUN go mod download -x
RUN go build

# Runtime
FROM redhat/ubi9-micro AS runtime

RUN mkdir /config
WORKDIR /app
COPY --from=builder /app/gohunt .

ENTRYPOINT [ "/app/gohunt", "-config", "/config/config.yaml" ]