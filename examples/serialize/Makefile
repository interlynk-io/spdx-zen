.PHONY: run run-pretty clean roundtrip

# Run the serialize demo with default minimal example
run:
	go run main.go -input minimal.spdx3.json -output output.spdx3.json
	@echo ""
	@echo "Output written to output.spdx3.json"

# Run with pretty-printed output to stdout
run-pretty:
	go run main.go -input minimal.spdx3.json -pretty

# Clean generated files
clean:
	rm -f output.spdx3.json

# Full round-trip: parse → serialize → parse again, then diff (should be identical)
roundtrip:
	@echo "=== Round-trip test ==="
	go run main.go -input minimal.spdx3.json -output /tmp/roundtrip.spdx3.json
	@echo ""
	@echo "First parse + serialize complete. Re-parsing output..."
	go run main.go -input /tmp/roundtrip.spdx3.json -output /dev/null
	@echo ""
	@echo "Round-trip complete!"
