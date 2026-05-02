GOLANGCI_LINT := $(shell go env GOPATH)/bin/golangci-lint

lint:
	@test -f $(GOLANGCI_LINT) || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOLANGCI_LINT) run

test:
	go test ./castleio/...

install:
	go mod download 