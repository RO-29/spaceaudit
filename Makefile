VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/RO-29/spaceaudit/internal/scan.Version=$(VERSION)
PREFIX ?= $(HOME)/.local

.PHONY: build test app install report docs clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/spaceaudit ./cmd/spaceaudit

test:
	go vet ./...
	go test ./...

app:
	VERSION=$(VERSION) sh scripts/build-app.sh

install: build
	mkdir -p $(PREFIX)/bin
	cp bin/spaceaudit $(PREFIX)/bin/spaceaudit
	@echo "Installed $(PREFIX)/bin/spaceaudit"

report: build
	./bin/spaceaudit html

docs: build
	./bin/spaceaudit rules > docs/RULES.md

clean:
	rm -rf bin dist
