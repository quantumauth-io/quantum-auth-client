APP_NAME := quantum-auth-client
MAIN_PKG := ./cmd/quantum-auth-client
BUILD_DIR := dist

# Default build for your current platform
.PHONY: build
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PKG)

.PHONY: run
run: build
	$(BUILD_DIR)/$(APP_NAME)

# --- Cross builds (no CGO, pure Go) ---

# Linux (x86_64 + arm64)
.PHONY: build-linux
build-linux:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PKG)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PKG)

# macOS
.PHONY: build-darwin
build-darwin:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_PKG)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_PKG)

# Windows
.PHONY: build-windows
build-windows:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN_PKG)

# All common platforms
.PHONY: build-all
build-all: build-linux build-darwin build-windows

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
