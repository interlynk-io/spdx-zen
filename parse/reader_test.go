package parse_test

import (
	"errors"
	"testing"

	"github.com/interlynk-io/spdx-zen/parse"
)

// mockFileReader returns a function that returns preset data or error.
func mockFileReader(data []byte, err error) func(string) ([]byte, error) {
	return func(_ string) ([]byte, error) {
		return data, err
	}
}

func TestNewReader(t *testing.T) {
	t.Run("creates reader with defaults", func(t *testing.T) {
		reader := parse.NewReader()
		if reader == nil {
			t.Fatal("expected reader to be created")
		}
	})

	t.Run("creates reader with custom file reader", func(t *testing.T) {
		called := false
		customReader := func(_ string) ([]byte, error) {
			called = true
			return nil, errors.New("mock error")
		}

		reader := parse.NewReader(parse.WithFileReader(customReader))
		_, err := reader.ReadFile("test.json")

		if !called {
			t.Error("expected custom file reader to be called")
		}
		if err == nil {
			t.Error("expected error from mock reader")
		}
	})
}

func TestReader_Read(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "invalid JSON",
			input:       `{invalid}`,
			wantErr:     true,
			errContains: "parsing JSON",
		},
		{
			name:        "non-object document",
			input:       `"string"`,
			wantErr:     true,
			errContains: "not a JSON object",
		},
		{
			name:        "missing @graph",
			input:       `{"@context": "https://example.com"}`,
			wantErr:     true,
			errContains: "@graph",
		},
		{
			name: "minimal valid document",
			input: `{
				"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
				"@graph": []
			}`,
			wantErr: false,
		},
		{
			name: "document with package",
			input: `{
				"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
				"@graph": [
					{
						"type": "software_Package",
						"spdxId": "SPDXRef-Package-1",
						"name": "test-package",
						"software_packageVersion": "1.0.0"
					}
				]
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := parse.NewReader()
			doc, err := reader.Read([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if doc == nil {
				t.Error("expected document, got nil")
			}
		})
	}
}

func TestReader_ReadFile(t *testing.T) {
	validDoc := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test Document"
			}
		]
	}`

	t.Run("reads file successfully", func(t *testing.T) {
		reader := parse.NewReader(
			parse.WithFileReader(mockFileReader([]byte(validDoc), nil)),
		)

		doc, err := reader.ReadFile("test.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if doc.GetName() != "Test Document" {
			t.Errorf("expected name %q, got %q", "Test Document", doc.GetName())
		}
	})

	t.Run("returns error on file read failure", func(t *testing.T) {
		reader := parse.NewReader(
			parse.WithFileReader(mockFileReader(nil, errors.New("file not found"))),
		)

		_, err := reader.ReadFile("nonexistent.json")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestDocument_GetMethods(t *testing.T) {
	docJSON := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test SBOM",
				"profileConformance": ["core", "software"]
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package-1",
				"name": "package-a",
				"software_packageVersion": "1.0.0"
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package-2",
				"name": "package-a",
				"software_packageVersion": "2.0.0"
			},
			{
				"type": "Relationship",
				"spdxId": "SPDXRef-Rel-1",
				"from": "SPDXRef-DOCUMENT",
				"to": ["SPDXRef-Package-1"],
				"relationshipType": "DESCRIBES"
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("GetName", func(t *testing.T) {
		if got := doc.GetName(); got != "Test SBOM" {
			t.Errorf("GetName() = %q, want %q", got, "Test SBOM")
		}
	})

	t.Run("GetSpdxID", func(t *testing.T) {
		if got := doc.GetSpdxID(); got != "SPDXRef-DOCUMENT" {
			t.Errorf("GetSpdxID() = %q, want %q", got, "SPDXRef-DOCUMENT")
		}
	})

	t.Run("GetPackageByID", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Package-1")
		if pkg == nil {
			t.Fatal("expected package, got nil")
		}
		if pkg.Name != "package-a" {
			t.Errorf("package name = %q, want %q", pkg.Name, "package-a")
		}
	})

	t.Run("GetPackageByID returns nil for unknown ID", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Unknown")
		if pkg != nil {
			t.Error("expected nil for unknown package ID")
		}
	})

	t.Run("GetPackageByName returns multiple packages", func(t *testing.T) {
		packages := doc.GetPackageByName("package-a")
		if len(packages) != 2 {
			t.Errorf("expected 2 packages, got %d", len(packages))
		}
	})
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
