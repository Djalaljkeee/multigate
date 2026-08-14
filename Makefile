BINARY   := multigate
PKG      := github.com/qwe8nxtroud/multigate
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "")
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.BuildDate=$(DATE)

# CGO не нужен: драйвер SQLite на чистом Go, поэтому бинарник статический
# и одинаково работает на любой машине с нужной архитектурой.
export CGO_ENABLED := 0

.PHONY: build
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/multigate

.PHONY: run
run:
	go run ./cmd/multigate --listen 127.0.0.1:8080 --data ./data --log-level debug

.PHONY: test
test:
	go test ./... -count=1

.PHONY: cover
cover:
	go test ./... -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet:
	go vet ./...

.PHONY: check
check: vet test

.PHONY: dist
dist:
	rm -rf dist && mkdir -p dist
	@for target in linux/amd64 linux/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		echo "сборка $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/multigate; \
		tar -czf dist/$(BINARY)_$(VERSION:v%=%)_$${os}_$${arch}.tar.gz -C dist $(BINARY); \
		rm -f dist/$(BINARY); \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt
	@ls -1 dist

.PHONY: docker
docker:
	docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		-t ghcr.io/qwe8nxtroud/multigate:$(VERSION) .

.PHONY: clean
clean:
	rm -rf dist coverage.out $(BINARY)
