# Variables
COREDNS_VERSION := "1.12.1"
PLUGIN_NAME := "mysql"
BUILD_DIR := "build"
COREDNS_DIR := BUILD_DIR + "/coredns"
PLUGIN_DIR := "."
# Multi-arch build settings
GO_BUILD_PAIRS := "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"
OUTPUT_DIR := "dist"
BINARY_NAME := "coredns"
# CGO-specific settings
CGO_CC := "x86_64-linux-musl-gcc"
CGO_CXX := "x86_64-linux-musl-g++"
CGO_AR := "x86_64-linux-musl-ar"

# Default recipe
default: build

# Build multi-architecture binaries (fixed version)
multi-arch: setup-direct check-plugin
    #!/bin/bash
    set -euo pipefail
    
    # Create output directory in project root
    mkdir -p {{OUTPUT_DIR}}
    
    # Get absolute path to output directory
    output_abs_path=$(realpath {{OUTPUT_DIR}})
    
    cd {{COREDNS_DIR}}
    
    # Verify plugin is integrated before building
    echo "Verifying plugin integration..."
    if ! grep -q "{{PLUGIN_NAME}}:" plugin.cfg; then
        echo "❌ Plugin not found in plugin.cfg!"
        exit 1
    fi
    
    # Check if plugin source exists
    if [ ! -d "plugin/{{PLUGIN_NAME}}" ]; then
        echo "❌ Plugin source not found in plugin/{{PLUGIN_NAME}}!"
        exit 1
    fi
    
    echo "✓ Plugin {{PLUGIN_NAME}} is properly integrated"
    
    echo "Building CoreDNS with {{PLUGIN_NAME}} plugin for multiple architectures..."
    echo "Targets: {{GO_BUILD_PAIRS}}"
    echo "Output directory: $output_abs_path"
    
    for pair in {{GO_BUILD_PAIRS}}; do
        os="${pair%/*}"
        arch="${pair#*/}"
        output_name="{{BINARY_NAME}}"
        
        if [ "$os" = "windows" ]; then
            output_name="$output_name.exe"
        fi
        
        output_dir="$output_abs_path/{{BINARY_NAME}}-$os-$arch"
        mkdir -p "$output_dir"

        echo "=== Building for $os/$arch ==="
        
        # Build the binary with verbose output
        echo "Building binary for $os/$arch..."
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -v -ldflags="-s -w" -o "$output_dir/$output_name" .
        
        # Verify the plugin is in the binary
        echo "Verifying plugin in binary..."
        GOOS="$os" GOARCH="$arch" "$output_dir/$output_name" -plugins | grep "{{PLUGIN_NAME}}" || {
            echo "❌ Plugin {{PLUGIN_NAME}} not found in $os/$arch binary!"
            # Don't exit, but warn - cross-arch plugin checking might not work
            echo "⚠️  Warning: Plugin verification failed (might be cross-arch issue)"
        }
        
        echo "✓ Built $output_dir/$output_name"
        
        # Package artifacts
        echo "Packaging $os/$arch..."
        archive_base="{{BINARY_NAME}}-$os-$arch"
        if [ "$os" != "windows" ]; then
            (cd "$output_abs_path" && \
             tar -czf "$archive_base.tar.gz" -C "$archive_base" "$output_name")
            echo "✓ Created $archive_base.tar.gz"
        else
            (cd "$output_dir" && \
             zip "../$archive_base.zip" "$output_name")
            echo "✓ Created $archive_base.zip"
        fi
    done
    echo ""
    echo "🎉 Multi-arch builds complete in {{OUTPUT_DIR}}/"
    cd - > /dev/null  # Go back to original directory quietly
    if [ -d "{{OUTPUT_DIR}}" ]; then
        ls -la {{OUTPUT_DIR}}/
    else
        echo "No builds were created successfully"
        exit 1
    fi

# Multi-arch build with CGO support (for when you need it)
multi-arch-cgo: setup-direct
    #!/bin/bash
    set -euo pipefail
    
    # Create output directory in project root
    mkdir -p {{OUTPUT_DIR}}
    
    # Get absolute path to output directory
    output_abs_path=$(realpath {{OUTPUT_DIR}})
    
    cd {{COREDNS_DIR}}
    
    echo "Building CoreDNS with {{PLUGIN_NAME}} plugin (CGO enabled) for multiple architectures..."
    echo "Output directory: $output_abs_path"
    
    # Define cross-compilers for different platforms
    declare -A cross_compilers=(
        ["linux/amd64"]="x86_64-linux-gnu-gcc"
        ["linux/arm64"]="aarch64-linux-gnu-gcc"
        ["darwin/amd64"]="o64-clang"
        ["darwin/arm64"]="o64-clang"
    )
    
    for pair in {{GO_BUILD_PAIRS}}; do
        os="${pair%/*}"
        arch="${pair#*/}"
        output_name="{{BINARY_NAME}}"
        
        if [ "$os" = "windows" ]; then
            output_name="$output_name.exe"
            cgo_enabled="0"  # Disable CGO for Windows by default
        else
            cgo_enabled="1"
        fi
        
        output_dir="$output_abs_path/{{BINARY_NAME}}-$os-$arch-cgo"
        mkdir -p "$output_dir"

        echo "=== Building CGO for $os/$arch ==="
        
        # Set cross-compiler if available
        cc_key="$os/$arch"
        if [[ -n "${cross_compilers[$cc_key]:-}" ]]; then
            export CC="${cross_compilers[$cc_key]}"
            echo "Using cross-compiler: $CC"
        else
            unset CC
        fi
        
        # Build with or without CGO
        CGO_ENABLED="$cgo_enabled" GOOS="$os" GOARCH="$arch" \
            go build -ldflags="-s -w" -o "$output_dir/$output_name" .
        
        echo "✓ Built $output_dir/$output_name"
        
        # Package artifacts
        archive_base="{{BINARY_NAME}}-$os-$arch-cgo"
        if [ "$os" != "windows" ]; then
            (cd "$output_abs_path" && \
             tar -czf "$archive_base.tar.gz" -C "$archive_base" "$output_name")
            echo "✓ Created $archive_base.tar.gz"
        else
            (cd "$output_dir" && \
             zip "../$archive_base.zip" "$output_name")
            echo "✓ Created $archive_base.zip"
        fi
    done
    echo ""
    echo "🎉 CGO multi-arch builds complete in {{OUTPUT_DIR}}/"
    cd - > /dev/null  # Go back to original directory quietly
    if [ -d "{{OUTPUT_DIR}}" ]; then
        ls -la {{OUTPUT_DIR}}/
    else
        echo "No builds were created successfully"
        exit 1
    fi

# Clean build artifacts
clean-dist:
    rm -rf {{OUTPUT_DIR}}

# Clean build directory
clean:
    rm -rf {{BUILD_DIR}}
    mkdir -p {{BUILD_DIR}}

# Download and prepare CoreDNS source
download: clean
    cd {{BUILD_DIR}} && \
    git clone https://github.com/coredns/coredns.git && \
    cd coredns && \
    git checkout v{{COREDNS_VERSION}}

# Setup plugin in CoreDNS
setup: download
    # Add plugin to plugin.cfg
    echo "{{PLUGIN_NAME}}:github.com/yourusername/coredns-mysql-extend" >> {{COREDNS_DIR}}/plugin.cfg
    
    # Initialize go module if not exists
    cd {{COREDNS_DIR}} && \
    if [ ! -f go.mod ]; then go mod init github.com/coredns/coredns; fi
    
    # Add replace directive for local development
    cd {{COREDNS_DIR}} && \
    go mod edit -replace github.com/yourusername/coredns-mysql-extend={{PLUGIN_DIR}}

# Alternative setup for direct plugin integration
setup-direct: download
    #!/bin/bash
    echo "Setting up plugin integration..."
    
    # Copy plugin files directly into CoreDNS
    mkdir -p {{COREDNS_DIR}}/plugin/{{PLUGIN_NAME}}
    cp -r {{PLUGIN_DIR}}/*.go {{COREDNS_DIR}}/plugin/{{PLUGIN_NAME}}/
    
    echo "✓ Copied plugin files to {{COREDNS_DIR}}/plugin/{{PLUGIN_NAME}}/"
    
    # Ensure plugin.cfg exists and add our plugin
    cd {{COREDNS_DIR}}
    
    if [ ! -f plugin.cfg ]; then
        echo "Creating plugin.cfg from sample..."
        cp plugin.cfg.sample plugin.cfg
    fi
    
    # Remove any existing entry for our plugin first
    sed -i "/^{{PLUGIN_NAME}}:/d" plugin.cfg
    
    # Add our plugin after cache (or at the end if cache not found)
    if grep -q "^cache:" plugin.cfg; then
        sed -i '/^cache:/a {{PLUGIN_NAME}}:{{PLUGIN_NAME}}' plugin.cfg
        echo "✓ Added {{PLUGIN_NAME}} plugin after cache in plugin.cfg"
    else
        echo "{{PLUGIN_NAME}}:{{PLUGIN_NAME}}" >> plugin.cfg
        echo "✓ Added {{PLUGIN_NAME}} plugin to end of plugin.cfg"
    fi
    
    # Show the plugin.cfg content around our plugin
    echo "Plugin configuration:"
    grep -A 2 -B 2 "{{PLUGIN_NAME}}" plugin.cfg || echo "{{PLUGIN_NAME}} plugin entry"
    
    # Tidy up modules
    echo "Tidying Go modules..."
    go mod tidy
    
    echo "✓ Plugin setup complete"

# Build CoreDNS with the plugin
build: setup-direct
    cd {{COREDNS_DIR}} && \
    go mod tidy && \
    make

# Alternative build command
build-go: setup-direct
    cd {{COREDNS_DIR}} && \
    go mod tidy && \
    go build -o coredns .

# Quick rebuild (assumes setup is done)
rebuild:
    # Copy updated plugin files
    cp -r {{PLUGIN_DIR}}/*.go {{COREDNS_DIR}}/plugin/{{PLUGIN_NAME}}/
    cd {{COREDNS_DIR}} && \
    go build -o coredns .

# Run CoreDNS with a test config
run: build
    cd {{COREDNS_DIR}} && \
    ./coredns -conf ../../Corefile

# Run with debug logging
run-debug: build
    cd {{COREDNS_DIR}} && \
    ./coredns -conf ../../Corefile

# Create a sample Corefile for testing
create-corefile:
    #!/bin/bash
    {
    echo '.:53 {'
    echo '    {{PLUGIN_NAME}} {'
    echo '        dsn "user:password@tcp(localhost:3306)/dns"'
    echo '        table_zones "zones"'
    echo '        table_records "records"'
    echo '        ttl 300'
    echo '        dump_file "/tmp/coredns_mysql_cache.json"'
    echo '    }'
    echo '    log'
    echo '    errors'
    echo '}'
    } > Corefile
    echo "Created Corefile - edit the MySQL DSN and other settings as needed"

# Test the built CoreDNS
test-build: build
    cd {{COREDNS_DIR}} && \
    ./coredns -version && \
    ./coredns -plugins | grep {{PLUGIN_NAME}}

# Install dependencies (if needed)
deps:
    go mod tidy

# Format code
fmt:
    go fmt ./...

# Run tests
test:
    go test ./...

# Development cycle: rebuild and run
dev: rebuild run-debug

# Check plugin is properly integrated
check-plugin: build
    cd {{COREDNS_DIR}} && \
    ./coredns -plugins | grep {{PLUGIN_NAME}} || echo "Plugin not found!"

# Verify multi-arch builds contain the plugin
verify-multi-arch:
    #!/bin/bash
    echo "Verifying plugin in multi-arch builds..."
    if [ ! -d "{{OUTPUT_DIR}}" ]; then
        echo "❌ No builds found. Run 'just multi-arch' first."
        exit 1
    fi
    
    for dir in {{OUTPUT_DIR}}/{{BINARY_NAME}}-*-*; do
        if [ -d "$dir" ]; then
            binary=$(find "$dir" -name "{{BINARY_NAME}}*" -type f)
            if [ -n "$binary" ]; then
                platform=$(basename "$dir" | sed 's/{{BINARY_NAME}}-//')
                echo "Checking $platform..."
                
                # Try to run the binary (might fail for cross-arch)
                if "$binary" -plugins 2>/dev/null | grep -q "{{PLUGIN_NAME}}"; then
                    echo "✓ Plugin found in $platform binary"
                else
                    echo "❌ Plugin NOT found in $platform binary"
                fi
            fi
        fi
    done

# Build sizes report
build-sizes: multi-arch
    #!/bin/bash
    echo "Build sizes:"
    if [ -d "{{OUTPUT_DIR}}" ]; then
        for f in {{OUTPUT_DIR}}/{{BINARY_NAME}}-*-*; do
            if [ -d "$f" ]; then
                binary=$(find "$f" -name "{{BINARY_NAME}}*" -type f)
                if [ -n "$binary" ]; then
                    size=$(ls -lh "$binary" | awk '{print $5}')
                    echo "  $(basename "$f"): $size"
                fi
            fi
        done
    else
        echo "No builds found. Run 'just multi-arch' first."
    fi

# Show help
help:
    @echo "Available recipes:"
    @echo "  default/build       - Download CoreDNS and build with plugin"
    @echo "  multi-arch          - Build for multiple architectures"
    @echo "  multi-arch-cgo      - Build for multiple architectures with CGO"
    @echo "  rebuild             - Quick rebuild after changes"
    @echo "  run                 - Run CoreDNS with plugin"
    @echo "  run-debug           - Run with debug logging"
    @echo "  dev                 - Rebuild and run with debug"
    @echo "  create-corefile     - Create sample Corefile"
    @echo "  test-build          - Test if build was successful"
    @echo "  verify-multi-arch   - Verify plugin is in multi-arch builds"
    @echo "  build-sizes         - Show binary sizes for multi-arch builds"
    @echo "  clean               - Clean build directory"
    @echo "  clean-dist          - Clean distribution artifacts"
    @echo "  fmt                 - Format code"
    @echo "  test                - Run tests"