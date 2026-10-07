BINARY  := hellhound
VERSION ?= 0.1.0
LDFLAGS := -s -w -X github.com/brerabineth/hellhound/internal/cli.Version=$(VERSION)
GO      ?= go

.PHONY: build test vet fmt cross install clean

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

cross:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-windows-amd64.exe .

install:
	$(GO) install -ldflags '$(LDFLAGS)' .

clean:
	rm -rf dist
