.PHONY: build build-all build-gui clean

# Build for current platform
build:
	go build -o bin/mesh ./cmd/mesh
	go build -o bin/meshd ./cmd/meshd

# Build GUI app for macOS and Windows (wife-friendly)
build-gui:
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build -o bin/meshgui-darwin-arm64 ./cmd/meshgui
	# macOS Intel
	GOOS=darwin GOARCH=amd64 go build -o bin/meshgui-darwin-amd64 ./cmd/meshgui
	# Windows
	GOOS=windows GOARCH=amd64 go build -o bin/meshgui-windows-amd64.exe ./cmd/meshgui

# Cross-compile for macOS (home) and Windows (office)
build-all:
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build -o bin/mesh-darwin-arm64 ./cmd/mesh
	# macOS Intel
	GOOS=darwin GOARCH=amd64 go build -o bin/mesh-darwin-amd64 ./cmd/mesh
	# Windows
	GOOS=windows GOARCH=amd64 go build -o bin/mesh-windows-amd64.exe ./cmd/mesh
	# Linux (relay server)
	GOOS=linux GOARCH=amd64 go build -o bin/meshd-linux-amd64 ./cmd/meshd
	GOOS=linux GOARCH=amd64 go build -o bin/mesh-linux-amd64 ./cmd/mesh
	# GUI apps
	GOOS=darwin GOARCH=arm64 go build -o bin/meshgui-darwin-arm64 ./cmd/meshgui
	GOOS=darwin GOARCH=amd64 go build -o bin/meshgui-darwin-amd64 ./cmd/meshgui
	GOOS=windows GOARCH=amd64 go build -o bin/meshgui-windows-amd64.exe ./cmd/meshgui

clean:
	rm -rf bin/
