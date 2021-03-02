lint:
	docker run --rm -v ${PWD}:/app -w /app golangci/golangci-lint:v1.37.1 golangci-lint run -v \
	-E gosec \
	-E misspell \
	-E maligned \
	-E interfacer \
	-E goconst \
	-E sqlclosecheck \
	-E rowserrcheck \
	-E gomnd \
	-E bodyclose \
	-e w.Write

test:
	go test ./castleio/...

install:
	go mod download 