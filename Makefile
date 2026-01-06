# Makefile for DNS Resolver with Knot integration

.PHONY: all build clean test run

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=dns-resolver
BINARY_UNIX=$(BINARY_NAME)_unix

# CGO parameters
export CGO_ENABLED=1
export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

# Build flags
LDFLAGS=-ldflags "-s -w"
CGO_LDFLAGS=-lknot -ldnssec -lgnutls -lm

all: clean deps build

deps:
	$(GOMOD) download
	$(GOMOD) tidy

build:
	@echo "Building with CGO enabled..."
	@echo "PKG_CONFIG_PATH: $(PKG_CONFIG_PATH)"
	@echo "CGO_LDFLAGS: $(CGO_LDFLAGS)"
	CGO_LDFLAGS="$(CGO_LDFLAGS)" $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v .

build-unix:
	@echo "Building for Unix..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CGO_LDFLAGS="$(CGO_LDFLAGS)" $(GOBUILD) $(LDFLAGS) -o $(BINARY_UNIX) -v .

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

run: build
	./$(BINARY_NAME)

install-deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y libknot-dev pkg-config

check-deps:
	@echo "Checking dependencies..."
	@echo "PKG_CONFIG_PATH: $(PKG_CONFIG_PATH)"
	pkg-config --cflags --libs libknot
	@echo "Checking libknot installation..."
	@if [ -f /usr/lib/x86_64-linux-gnu/libknot.so.15 ]; then \
		echo "libknot found: /usr/lib/x86_64-linux-gnu/libknot.so.15"; \
	else \
		echo "ERROR: libknot not found!"; \
		exit 1; \
	fi

help:
	@echo "Available targets:"
	@echo "  all         - Clean, install deps, and build"
	@echo "  build       - Build the binary"
	@echo "  build-unix  - Build for Unix/Linux"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  run         - Build and run"
	@echo "  install-deps- Install system dependencies"
	@echo "  check-deps  - Check if dependencies are installed"
	@echo "  help        - Show this help"