.PHONY: build run test clean migrate-up migrate-down lint security-check

BINARY_NAME=go-cms
BUILD_DIR=./bin
MIGRATIONS_DIR=./migrations

# Build the application
build:
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Run the application
run:
	go run ./cmd/server

# Run tests
test:
	go test ./... -v -cover

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean

# Run database migrations up
migrate-up:
	go run ./cmd/server migrate up

# Run database migrations down
migrate-down:
	go run ./cmd/server migrate down

# Run linter
lint:
	golangci-lint run ./...

# Security check
security-check:
	gosec ./...
	govulncheck ./...

# Generate swagger docs
swagger:
	swag init -g ./cmd/server/main.go

# Install dependencies
deps:
	go mod download
	go mod verify

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# Create migration
create-migration:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $${name}

# Docker build (optional)
docker-build:
	docker build -t $(BINARY_NAME) .

# Docker run (optional)
docker-run:
	docker run -p 8080:8080 --env-file .env $(BINARY_NAME)

# Live reload with air (development)
dev:
	air

# Create production build with optimizations
production-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Create release package
release: production-build
	tar czf $(BINARY_NAME)-$(VERSION).tar.gz -C $(BUILD_DIR) $(BINARY_NAME)

# Help
help:
	@echo "Available commands:"
	@echo "  build           - Build the application"
	@echo "  run             - Run the application"
	@echo "  test            - Run tests"
	@echo "  clean           - Clean build artifacts"
	@echo "  migrate-up      - Run database migrations up"
	@echo "  migrate-down    - Run database migrations down"
	@echo "  lint            - Run linter"
	@echo "  security-check  - Run security checks"
	@echo "  deps            - Download dependencies"
	@echo "  install-tools   - Install development tools"
	@echo "  dev             - Run with live reload"
	@echo "  production-build - Build for production"
	@echo "  release         - Create release package"