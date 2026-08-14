# Сборка статического бинарника.
# CGO выключен намеренно: драйвер SQLite здесь на чистом Go, поэтому
# образ не тянет системные библиотеки и одинаково работает везде.
FROM golang:1.26-alpine AS build

ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=

WORKDIR /src

# Слой зависимостей отдельно: он меняется редко и хорошо кэшируется.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
      -X github.com/qwe8nxtroud/multigate/internal/version.Version=${VERSION} \
      -X github.com/qwe8nxtroud/multigate/internal/version.Commit=${COMMIT} \
      -X github.com/qwe8nxtroud/multigate/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/multigate ./cmd/multigate

# Итоговый образ на alpine, а не на distroless: реестр gcr.io бывает
# недоступен из РФ, а alpine тянется отовсюду. Внутри всё те же
# корневые сертификаты и часовые пояса, ничего лишнего.
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -g 10001 -S multigate && \
    adduser -u 10001 -S -G multigate -h /var/lib/multigate multigate && \
    mkdir -p /var/lib/multigate && \
    chown -R multigate:multigate /var/lib/multigate

COPY --from=build /out/multigate /usr/local/bin/multigate

USER multigate
WORKDIR /var/lib/multigate
VOLUME ["/var/lib/multigate"]

ENV MULTIGATE_LISTEN=0.0.0.0:8080 \
    MULTIGATE_DATA_DIR=/var/lib/multigate

EXPOSE 8080

# Проверка живости: свой лёгкий эндпоинт, он не ходит в панель и не пишет в базу.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/multigate"]
