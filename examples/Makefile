# Makefile for SPDX-Zen examples

.PHONY: all clean spdx-lister test

# Build all examples
all: spdx-lister

# Build spdx-lister example
spdx-lister:
	@echo "Building spdx-lister..."
	@cd spdx-lister && go build -o spdx-lister

# Run spdx-lister with sample file
test-lister: spdx-lister
	@echo "Testing spdx-lister with sample document..."
	@cd spdx-lister && ./spdx-lister sample.spdx.json

# Run spdx-lister in verbose mode
test-lister-verbose: spdx-lister
	@echo "Testing spdx-lister with verbose output..."
	@cd spdx-lister && ./spdx-lister sample.spdx.json --verbose

# Clean built binaries
clean:
	@echo "Cleaning built binaries..."
	@rm -f spdx-lister/spdx-lister

# Help
help:
	@echo "Available targets:"
	@echo "  all                - Build all examples"
	@echo "  spdx-lister        - Build the spdx-lister example"
	@echo "  test-lister        - Run spdx-lister with sample document"
	@echo "  test-lister-verbose - Run spdx-lister with verbose output"
	@echo "  clean              - Remove built binaries"
	@echo "  help               - Show this help message"