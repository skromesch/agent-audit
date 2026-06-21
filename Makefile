.PHONY: build test lint clean install

BINARY := agent-audit
CMD := ./cmd/agent-audit

build:
	go build -o $(BINARY) $(CMD)

install:
	go install $(CMD)

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep total

lint:
	golangci-lint run ./...

bench:
	go test -bench=. -benchmem ./...

clean:
	rm -f $(BINARY) coverage.out report.json report.md report.html

.DEFAULT_GOAL := build
