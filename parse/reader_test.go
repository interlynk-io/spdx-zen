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
			return
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

func TestReader_SoftwareArtifact(t *testing.T) {
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
				"type": "software_SoftwareArtifact",
				"spdxId": "SPDXRef-SourceArtifact",
				"name": "source-artifact",
				"software_primaryPurpose": "source",
				"software_additionalPurpose": ["archive"],
				"software_copyrightText": "Copyright 2024 Example",
				"software_attributionText": ["Attribution line 1"],
				"verifiedUsing": [
					{
						"type": "Hash",
						"algorithm": "sha512",
						"hashValue": "abc123"
					}
				]
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package",
				"name": "my-package",
				"software_packageVersion": "1.0.0"
			},
			{
				"type": "Relationship",
				"from": "SPDXRef-SourceArtifact",
				"to": ["SPDXRef-Package"],
				"relationshipType": "generates",
				"completeness": "complete"
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("SoftwareArtifacts parsed", func(t *testing.T) {
		if len(doc.SoftwareArtifacts) == 0 {
			t.Fatal("expected SoftwareArtifacts, got none")
		}
	})

	t.Run("SoftwareArtifact fields", func(t *testing.T) {
		sa := doc.GetSoftwareArtifactByID("SPDXRef-SourceArtifact")
		if sa == nil {
			t.Fatal("expected SoftwareArtifact by ID, got nil")
		}
		if sa.Name != "source-artifact" {
			t.Errorf("name = %q, want %q", sa.Name, "source-artifact")
		}
		if string(sa.PrimaryPurpose) != "source" {
			t.Errorf("primaryPurpose = %q, want %q", sa.PrimaryPurpose, "source")
		}
		if len(sa.AdditionalPurpose) != 1 || string(sa.AdditionalPurpose[0]) != "archive" {
			t.Errorf("additionalPurpose = %v, want [archive]", sa.AdditionalPurpose)
		}
		if sa.CopyrightText != "Copyright 2024 Example" {
			t.Errorf("copyrightText = %q, want %q", sa.CopyrightText, "Copyright 2024 Example")
		}
		if len(sa.AttributionText) != 1 || sa.AttributionText[0] != "Attribution line 1" {
			t.Errorf("attributionText = %v, want [Attribution line 1]", sa.AttributionText)
		}
	})

	t.Run("SoftwareArtifact verifiedUsing", func(t *testing.T) {
		sa := doc.GetSoftwareArtifactByID("SPDXRef-SourceArtifact")
		if sa == nil {
			t.Fatal("expected SoftwareArtifact by ID, got nil")
		}
		if len(sa.VerifiedUsing) == 0 {
			t.Fatal("expected VerifiedUsing, got none")
		}
	})
}

func TestReader_ExternalIdentifiersPlural(t *testing.T) {
	docJSON := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test SBOM"
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package",
				"name": "my-package",
				"software_packageVersion": "1.0.0",
				"externalIdentifiers": [
					{
						"externalIdentifierType": "packageUrl",
						"identifier": "pkg:npm/my-package@1.0.0"
					},
					{
						"externalIdentifierType": "cpe22",
						"identifier": "cpe:/a:example:my-package:1.0.0"
					}
				]
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("externalIdentifiers plural parsed", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Package")
		if pkg == nil {
			t.Fatal("expected package, got nil")
		}
		if len(pkg.ExternalIdentifier) != 2 {
			t.Errorf("expected 2 externalIdentifiers, got %d", len(pkg.ExternalIdentifier))
		}
	})

	t.Run("externalIdentifiers values", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Package")
		if pkg == nil {
			t.Fatal("expected package, got nil")
		}
		if len(pkg.ExternalIdentifier) < 2 {
			t.Fatal("expected at least 2 externalIdentifiers")
		}
		if string(pkg.ExternalIdentifier[0].ExternalIdentifierType) != "packageUrl" {
			t.Errorf("first type = %q, want %q", pkg.ExternalIdentifier[0].ExternalIdentifierType, "packageUrl")
		}
		if pkg.ExternalIdentifier[0].Identifier != "pkg:npm/my-package@1.0.0" {
			t.Errorf("first identifier = %q, want %q", pkg.ExternalIdentifier[0].Identifier, "pkg:npm/my-package@1.0.0")
		}
		if string(pkg.ExternalIdentifier[1].ExternalIdentifierType) != "cpe22" {
			t.Errorf("second type = %q, want %q", pkg.ExternalIdentifier[1].ExternalIdentifierType, "cpe22")
		}
	})
}

func TestReader_ExternalRef(t *testing.T) {
	docJSON := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test SBOM"
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package",
				"name": "my-package",
				"software_packageVersion": "1.0.0",
				"externalRef": [
					{
						"externalRefType": "securityOther",
						"locator": ["https://example.com/.well-known/security.txt"],
						"contentType": "text/plain",
						"comment": "Security contact information"
					},
					{
						"externalRefType": "binaryArtifact",
						"locator": ["https://example.com/download/my-package-1.0.0.tar.gz"]
					}
				]
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("externalRef parsed", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Package")
		if pkg == nil {
			t.Fatal("expected package, got nil")
		}
		if len(pkg.ExternalRef) != 2 {
			t.Errorf("expected 2 externalRefs, got %d", len(pkg.ExternalRef))
		}
	})

	t.Run("externalRef fields", func(t *testing.T) {
		pkg := doc.GetPackageByID("SPDXRef-Package")
		if pkg == nil {
			t.Fatal("expected package, got nil")
		}
		if len(pkg.ExternalRef) < 2 {
			t.Fatal("expected at least 2 externalRefs")
		}
		// First: securityOther
		if string(pkg.ExternalRef[0].ExternalRefType) != "securityOther" {
			t.Errorf("first type = %q, want %q", pkg.ExternalRef[0].ExternalRefType, "securityOther")
		}
		if len(pkg.ExternalRef[0].Locator) != 1 || pkg.ExternalRef[0].Locator[0] != "https://example.com/.well-known/security.txt" {
			t.Errorf("first locator = %v, want [https://example.com/.well-known/security.txt]", pkg.ExternalRef[0].Locator)
		}
		if pkg.ExternalRef[0].ContentType != "text/plain" {
			t.Errorf("first contentType = %q, want %q", pkg.ExternalRef[0].ContentType, "text/plain")
		}
		if pkg.ExternalRef[0].Comment != "Security contact information" {
			t.Errorf("first comment = %q, want %q", pkg.ExternalRef[0].Comment, "Security contact information")
		}
		// Second: binaryArtifact
		if string(pkg.ExternalRef[1].ExternalRefType) != "binaryArtifact" {
			t.Errorf("second type = %q, want %q", pkg.ExternalRef[1].ExternalRefType, "binaryArtifact")
		}
		if len(pkg.ExternalRef[1].Locator) != 1 || pkg.ExternalRef[1].Locator[0] != "https://example.com/download/my-package-1.0.0.tar.gz" {
			t.Errorf("second locator = %v, want [https://example.com/download/my-package-1.0.0.tar.gz]", pkg.ExternalRef[1].Locator)
		}
	})
}

func TestReader_SbomLifecycle(t *testing.T) {
	docJSON := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.json",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test SBOM",
				"profileConformance": ["core", "software"],
				"creationInfo": "_:creationinfo"
			},
			{
				"type": "CreationInfo",
				"@id": "_:creationinfo",
				"specVersion": "3.0.1",
				"created": "2024-01-15T10:30:00Z",
				"createdBy": ["_:author"]
			},
			{
				"type": "Person",
				"@id": "_:author",
				"name": "Test Author"
			},
			{
				"type": "software_Sbom",
				"spdxId": "SPDXRef-SBOM",
				"name": "My Application SBOM",
				"sbomType": ["build", "analyzed"]
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("Sboms parsed", func(t *testing.T) {
		if len(doc.Sboms) == 0 {
			t.Fatal("expected Sboms, got none")
		}
	})

	t.Run("sbomType parsed", func(t *testing.T) {
		sbom := doc.Sboms[0]
		if len(sbom.SbomType) != 2 {
			t.Errorf("expected 2 sbomTypes, got %d", len(sbom.SbomType))
		}
		if string(sbom.SbomType[0]) != "build" {
			t.Errorf("first sbomType = %q, want %q", sbom.SbomType[0], "build")
		}
		if string(sbom.SbomType[1]) != "analyzed" {
			t.Errorf("second sbomType = %q, want %q", sbom.SbomType[1], "analyzed")
		}
	})

	t.Run("Boms also contains Sbom", func(t *testing.T) {
		if len(doc.Boms) == 0 {
			t.Fatal("expected Boms, got none")
		}
		if doc.Boms[0].Name != "My Application SBOM" {
			t.Errorf("bom name = %q, want %q", doc.Boms[0].Name, "My Application SBOM")
		}
	})
}

func TestReader_LicensingElements(t *testing.T) {
	docJSON := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{
				"type": "SpdxDocument",
				"spdxId": "SPDXRef-DOCUMENT",
				"name": "Test SBOM"
			},
			{
				"type": "software_Package",
				"spdxId": "SPDXRef-Package",
				"name": "my-package",
				"software_packageVersion": "1.0.0"
			},
			{
				"type": "simplelicensing_LicenseExpression",
				"spdxId": "SPDXRef-License-MIT",
				"licenseExpression": "MIT"
			},
			{
				"type": "Relationship",
				"spdxId": "SPDXRef-Rel-1",
				"from": "SPDXRef-Package",
				"to": ["SPDXRef-License-MIT"],
				"relationshipType": "hasDeclaredLicense",
				"completeness": "complete"
			}
		]
	}`

	reader := parse.NewReader()
	doc, err := reader.Read([]byte(docJSON))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	t.Run("LicenseExpression parsed with simplelicensing_ prefix", func(t *testing.T) {
		if len(doc.LicenseExpressions) == 0 {
			t.Fatal("expected LicenseExpressions, got none")
		}
		le := doc.LicenseExpressions[0]
		if le.SpdxID != "SPDXRef-License-MIT" {
			t.Errorf("spdxId = %q, want %q", le.SpdxID, "SPDXRef-License-MIT")
		}
		if le.LicenseExpression != "MIT" {
			t.Errorf("licenseExpression = %q, want %q", le.LicenseExpression, "MIT")
		}
	})

	t.Run("LicenseExpression indexed by ID", func(t *testing.T) {
		le := doc.LicenseExpressionsByID["SPDXRef-License-MIT"]
		if le == nil {
			t.Fatal("expected LicenseExpression by ID, got nil")
		}
		if le.LicenseExpression != "MIT" {
			t.Errorf("licenseExpression = %q, want %q", le.LicenseExpression, "MIT")
		}
	})

	t.Run("GetAnyLicenseInfoByID resolves LicenseExpression", func(t *testing.T) {
		info := doc.GetAnyLicenseInfoByID("SPDXRef-License-MIT")
		if info == nil {
			t.Fatal("expected AnyLicenseInfo by ID, got nil")
		}
		if info.Name != "MIT" {
			t.Errorf("name = %q, want %q", info.Name, "MIT")
		}
		if info.SpdxID != "SPDXRef-License-MIT" {
			t.Errorf("spdxId = %q, want %q", info.SpdxID, "SPDXRef-License-MIT")
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
