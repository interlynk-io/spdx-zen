package spdx_test

import (
	"testing"
	"time"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

func TestSpecVersion(t *testing.T) {
	if spdx.SpecVersion != "3.0.1" {
		t.Errorf("SpecVersion = %q, want %q", spdx.SpecVersion, "3.0.1")
	}
}

func TestNewCreationInfo(t *testing.T) {
	agents := []spdx.Agent{
		{Element: spdx.Element{SpdxID: "urn:spdx:agent-1", Name: "Test Agent"}},
	}

	ci := spdx.NewCreationInfo(agents)

	if ci.SpecVersion != spdx.SpecVersion {
		t.Errorf("SpecVersion = %q, want %q", ci.SpecVersion, spdx.SpecVersion)
	}

	if ci.Created.IsZero() {
		t.Error("Created should not be zero")
	}

	if len(ci.CreatedBy) != 1 {
		t.Errorf("CreatedBy length = %d, want 1", len(ci.CreatedBy))
	}
}

func TestNewElement(t *testing.T) {
	ci := spdx.CreationInfo{
		SpecVersion: spdx.SpecVersion,
		Created:     time.Now(),
	}

	elem := spdx.NewElement("urn:spdx:elem-1", "Test Element", ci)

	if elem.SpdxID != "urn:spdx:elem-1" {
		t.Errorf("SpdxID = %q, want %q", elem.SpdxID, "urn:spdx:elem-1")
	}

	if elem.Name != "Test Element" {
		t.Errorf("Name = %q, want %q", elem.Name, "Test Element")
	}
}

func TestNewPackage(t *testing.T) {
	ci := spdx.CreationInfo{
		SpecVersion: spdx.SpecVersion,
		Created:     time.Now(),
	}

	pkg := spdx.NewPackage("urn:spdx:pkg-1", "test-package", "1.0.0", ci)

	if pkg.GetSpdxID() != "urn:spdx:pkg-1" {
		t.Errorf("GetSpdxID() = %q, want %q", pkg.GetSpdxID(), "urn:spdx:pkg-1")
	}

	if pkg.GetName() != "test-package" {
		t.Errorf("GetName() = %q, want %q", pkg.GetName(), "test-package")
	}

	if pkg.GetPackageVersion() != "1.0.0" {
		t.Errorf("GetPackageVersion() = %q, want %q", pkg.GetPackageVersion(), "1.0.0")
	}
}

func TestNewRelationship(t *testing.T) {
	ci := spdx.CreationInfo{
		SpecVersion: spdx.SpecVersion,
		Created:     time.Now(),
	}

	from := spdx.Element{SpdxID: "urn:spdx:from"}
	to := []spdx.Element{{SpdxID: "urn:spdx:to"}}

	rel := spdx.NewRelationship("urn:spdx:rel-1", from, to, spdx.RelationshipTypeDependsOn, ci)

	if rel.GetRelationshipType() != spdx.RelationshipTypeDependsOn {
		t.Errorf("GetRelationshipType() = %v, want %v", rel.GetRelationshipType(), spdx.RelationshipTypeDependsOn)
	}

	if !rel.IsDependency() {
		t.Error("IsDependency() should return true for DEPENDS_ON")
	}
}

func TestElement_WithPURL(t *testing.T) {
	elem := &spdx.Element{SpdxID: "urn:spdx:elem-1"}
	elem.WithPURL("pkg:golang/github.com/test/pkg@v1.0.0")

	if !elem.HasPURL() {
		t.Error("HasPURL() should return true after WithPURL")
	}

	if purl := elem.GetPURL(); purl != "pkg:golang/github.com/test/pkg@v1.0.0" {
		t.Errorf("GetPURL() = %q, want %q", purl, "pkg:golang/github.com/test/pkg@v1.0.0")
	}
}

func TestElement_WithCPE(t *testing.T) {
	tests := []struct {
		name    string
		cpe     string
		wantCPE string
	}{
		{
			name:    "CPE 2.3",
			cpe:     "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			wantCPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "CPE 2.2",
			cpe:     "cpe:/a:vendor:product:1.0",
			wantCPE: "cpe:/a:vendor:product:1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elem := &spdx.Element{SpdxID: "urn:spdx:elem-1"}
			elem.WithCPE(tt.cpe)

			if got := elem.GetCPE(); got != tt.wantCPE {
				t.Errorf("GetCPE() = %q, want %q", got, tt.wantCPE)
			}
		})
	}
}

func TestRelationship_IsDependency(t *testing.T) {
	tests := []struct {
		relType spdx.RelationshipType
		wantDep bool
	}{
		{spdx.RelationshipTypeDependsOn, true},
		{spdx.RelationshipTypeHasOptionalDependency, true},
		{spdx.RelationshipTypeHasProvidedDependency, true},
		{spdx.RelationshipTypeHasPrerequisite, true},
		{spdx.RelationshipTypeContains, false},
		{spdx.RelationshipTypeDescribes, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.relType), func(t *testing.T) {
			rel := &spdx.Relationship{RelationshipType: tt.relType}
			if got := rel.IsDependency(); got != tt.wantDep {
				t.Errorf("IsDependency() = %v, want %v", got, tt.wantDep)
			}
		})
	}
}

func TestRelationship_IsContainment(t *testing.T) {
	rel := &spdx.Relationship{RelationshipType: spdx.RelationshipTypeContains}
	if !rel.IsContainment() {
		t.Error("IsContainment() should return true for CONTAINS")
	}

	rel2 := &spdx.Relationship{RelationshipType: spdx.RelationshipTypeDependsOn}
	if rel2.IsContainment() {
		t.Error("IsContainment() should return false for DEPENDS_ON")
	}
}

func TestRelationshipType_IsValid(t *testing.T) {
	tests := []struct {
		relType spdx.RelationshipType
		valid   bool
	}{
		{spdx.RelationshipTypeDependsOn, true},
		{spdx.RelationshipTypeContains, true},
		{spdx.RelationshipType("invalid"), false},
		{spdx.RelationshipType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.relType), func(t *testing.T) {
			if got := tt.relType.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestHashAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		algo  spdx.HashAlgorithm
		valid bool
	}{
		{spdx.HashAlgorithmSha256, true},
		{spdx.HashAlgorithmSha512, true},
		{spdx.HashAlgorithmMd5, true},
		{spdx.HashAlgorithm("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := tt.algo.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSoftwarePurpose_IsValid(t *testing.T) {
	tests := []struct {
		purpose spdx.SoftwarePurpose
		valid   bool
	}{
		{spdx.SoftwarePurposeApplication, true},
		{spdx.SoftwarePurposeLibrary, true},
		{spdx.SoftwarePurposeContainer, true},
		{spdx.SoftwarePurpose("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestNewExternalIdentifier(t *testing.T) {
	ei := spdx.NewExternalIdentifier(spdx.ExternalIdentifierTypePackageUrl, "pkg:golang/test@v1.0.0")

	if ei.ExternalIdentifierType != spdx.ExternalIdentifierTypePackageUrl {
		t.Errorf("ExternalIdentifierType = %v, want %v", ei.ExternalIdentifierType, spdx.ExternalIdentifierTypePackageUrl)
	}

	if ei.Identifier != "pkg:golang/test@v1.0.0" {
		t.Errorf("Identifier = %q, want %q", ei.Identifier, "pkg:golang/test@v1.0.0")
	}
}

func TestNewHash(t *testing.T) {
	hash := spdx.NewHash(spdx.HashAlgorithmSha256, "abc123def456")

	if hash.Algorithm != spdx.HashAlgorithmSha256 {
		t.Errorf("Algorithm = %v, want %v", hash.Algorithm, spdx.HashAlgorithmSha256)
	}

	if hash.HashValue != "abc123def456" {
		t.Errorf("HashValue = %q, want %q", hash.HashValue, "abc123def456")
	}
}

// Test interface implementations
func TestElementInterface(_ *testing.T) {
	var _ spdx.ElementInterface = &spdx.Element{}
	var _ spdx.ElementInterface = &spdx.Package{}
	var _ spdx.ElementInterface = &spdx.File{}
	var _ spdx.ElementInterface = &spdx.Relationship{}
}

func TestArtifactInterface(_ *testing.T) {
	var _ spdx.ArtifactInterface = &spdx.Artifact{}
}

func TestSoftwareArtifactInterface(_ *testing.T) {
	var _ spdx.SoftwareArtifactInterface = &spdx.SoftwareArtifact{}
}

func TestPackageInterface(_ *testing.T) {
	var _ spdx.PackageInterface = &spdx.Package{}
}

func TestRelationshipInterface(_ *testing.T) {
	var _ spdx.RelationshipInterface = &spdx.Relationship{}
}

func TestRelationship_IsLicenseRelationship(t *testing.T) {
	tests := []struct {
		relType spdx.RelationshipType
		want    bool
	}{
		{spdx.RelationshipTypeHasConcludedLicense, true},
		{spdx.RelationshipTypeHasDeclaredLicense, true},
		{spdx.RelationshipTypeDependsOn, false},
		{spdx.RelationshipTypeContains, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.relType), func(t *testing.T) {
			rel := &spdx.Relationship{RelationshipType: tt.relType}
			if got := rel.IsLicenseRelationship(); got != tt.want {
				t.Errorf("IsLicenseRelationship() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelationship_IsSecurityRelationship(t *testing.T) {
	tests := []struct {
		relType spdx.RelationshipType
		want    bool
	}{
		{spdx.RelationshipTypeAffects, true},
		{spdx.RelationshipTypeDoesNotAffect, true},
		{spdx.RelationshipTypeFixedIn, true},
		{spdx.RelationshipTypeHasAssociatedVulnerability, true},
		{spdx.RelationshipTypeDependsOn, false},
		{spdx.RelationshipTypeContains, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.relType), func(t *testing.T) {
			rel := &spdx.Relationship{RelationshipType: tt.relType}
			if got := rel.IsSecurityRelationship(); got != tt.want {
				t.Errorf("IsSecurityRelationship() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelationship_IsBuildRelationship(t *testing.T) {
	tests := []struct {
		relType spdx.RelationshipType
		want    bool
	}{
		{spdx.RelationshipTypeHasInput, true},
		{spdx.RelationshipTypeHasOutput, true},
		{spdx.RelationshipTypeHasHost, true},
		{spdx.RelationshipTypeInvokedBy, true},
		{spdx.RelationshipTypeGenerates, true},
		{spdx.RelationshipTypeDependsOn, false},
		{spdx.RelationshipTypeContains, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.relType), func(t *testing.T) {
			rel := &spdx.Relationship{RelationshipType: tt.relType}
			if got := rel.IsBuildRelationship(); got != tt.want {
				t.Errorf("IsBuildRelationship() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeRelationshipType(t *testing.T) {
	tests := []struct {
		input string
		want  spdx.RelationshipType
	}{
		// Already valid camelCase
		{"dependsOn", spdx.RelationshipTypeDependsOn},
		{"contains", spdx.RelationshipTypeContains},
		{"describes", spdx.RelationshipTypeDescribes},
		{"hasOptionalDependency", spdx.RelationshipTypeHasOptionalDependency},

		// Uppercase underscore format
		{"DEPENDS_ON", spdx.RelationshipTypeDependsOn},
		{"CONTAINS", spdx.RelationshipTypeContains},
		{"DESCRIBES", spdx.RelationshipTypeDescribes},
		{"HAS_OPTIONAL_DEPENDENCY", spdx.RelationshipTypeHasOptionalDependency},
		{"HAS_CONCLUDED_LICENSE", spdx.RelationshipTypeHasConcludedLicense},
		{"HAS_DECLARED_LICENSE", spdx.RelationshipTypeHasDeclaredLicense},
		{"HAS_PREREQUISITE", spdx.RelationshipTypeHasPrerequisite},
		{"HAS_PROVIDED_DEPENDENCY", spdx.RelationshipTypeHasProvidedDependency},

		// Invalid - should return as-is
		{"invalid", spdx.RelationshipType("invalid")},
		{"", spdx.RelationshipType("")},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := spdx.NormalizeRelationshipType(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeRelationshipType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
