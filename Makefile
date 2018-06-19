LINT_FLAGS :=--disable-all --enable=vet --enable=vetshadow --enable=golint --enable=ineffassign --enable=goconst --enable=gofmt
LINTER_EXE := gometalinter.v1
LINTER := $(GOPATH)/bin/$(LINTER_EXE)

LEXC :=
ifdef LINT_EXCLUDE
	LEXC := $(call join-with,|,$(LINT_EXCLUDE))
endif

$(LINTER):
	go get -u gopkg.in/alecthomas/$(LINTER_EXE)
	$(LINTER) --install

lint: $(LINTER)
ifdef LEXC
	$(LINTER) --exclude '$(LEXC)' $(LINT_FLAGS) ./castleio/...
else
	$(LINTER) $(LINT_FLAGS) ./castleio/...
endif

test:
	go test ./castleio/...

install:
	go get -t ./castleio/...