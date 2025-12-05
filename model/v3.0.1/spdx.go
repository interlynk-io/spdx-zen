// Copyright 2025 Interlynk Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spdx

import "time"

//go:generate go run ../../cmd/spdx-gen -spec ../../docs/spdx-model.json-ld -out . -pkg spdx

const (
	// SpecVersion is the SPDX specification version this package implements.
	SpecVersion = "3.0.1"

	// ContextURL is the JSON-LD context URL for SPDX 3.0.1.
	ContextURL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
)

// ElementInterface defines the common interface for all SPDX elements.
// This interface is implemented by all Element types and can be used
// for version-agnostic code.
type ElementInterface interface {
	GetSpdxID() string
	GetName() string
	GetCreationInfo() *CreationInfo
}

// GetSpdxID returns the SPDX identifier of the element.
func (e *Element) GetSpdxID() string {
	return e.SpdxID
}

// GetName returns the name of the element.
func (e *Element) GetName() string {
	return e.Name
}

// GetCreationInfo returns the creation information of the element.
func (e *Element) GetCreationInfo() *CreationInfo {
	return &e.CreationInfo
}

// ArtifactInterface defines the interface for artifact elements.
type ArtifactInterface interface {
	ElementInterface
	GetOriginatedBy() []Agent
	GetSuppliedBy() *Agent
}

// GetOriginatedBy returns the agents that originated this artifact.
func (a *Artifact) GetOriginatedBy() []Agent {
	return a.OriginatedBy
}

// GetSuppliedBy returns the agent that supplied this artifact.
func (a *Artifact) GetSuppliedBy() *Agent {
	return a.SuppliedBy
}

// SoftwareArtifactInterface defines the interface for software artifact elements.
type SoftwareArtifactInterface interface {
	ArtifactInterface
	GetPrimaryPurpose() *SoftwarePurpose
	GetAdditionalPurpose() []SoftwarePurpose
	GetCopyrightText() string
}

// GetPrimaryPurpose returns the primary purpose of the software artifact.
func (sa *SoftwareArtifact) GetPrimaryPurpose() *SoftwarePurpose {
	return sa.PrimaryPurpose
}

// GetAdditionalPurpose returns additional purposes of the software artifact.
func (sa *SoftwareArtifact) GetAdditionalPurpose() []SoftwarePurpose {
	return sa.AdditionalPurpose
}

// GetCopyrightText returns the copyright text of the software artifact.
func (sa *SoftwareArtifact) GetCopyrightText() string {
	return sa.CopyrightText
}

// PackageInterface defines the interface for package elements.
type PackageInterface interface {
	SoftwareArtifactInterface
	GetPackageVersion() string
	GetPackageURL() string
	GetDownloadLocation() string
}

// GetPackageVersion returns the version of the package.
func (p *Package) GetPackageVersion() string {
	return p.PackageVersion
}

// GetPackageURL returns the package URL (PURL) of the package.
func (p *Package) GetPackageURL() string {
	return p.PackageUrl
}

// GetDownloadLocation returns the download location of the package.
func (p *Package) GetDownloadLocation() string {
	return p.DownloadLocation
}

// RelationshipInterface defines the interface for relationship elements.
type RelationshipInterface interface {
	ElementInterface
	GetFrom() Element
	GetTo() []Element
	GetRelationshipType() RelationshipType
}

// GetFrom returns the source element of the relationship.
func (r *Relationship) GetFrom() Element {
	return r.From
}

// GetTo returns the target elements of the relationship.
func (r *Relationship) GetTo() []Element {
	return r.To
}

// GetRelationshipType returns the type of the relationship.
func (r *Relationship) GetRelationshipType() RelationshipType {
	return r.RelationshipType
}

// NewCreationInfo creates a new CreationInfo with required fields.
func NewCreationInfo(createdBy []Agent) CreationInfo {
	return CreationInfo{
		SpecVersion: SpecVersion,
		Created:     time.Now(),
		CreatedBy:   createdBy,
	}
}

// NewElement creates a new Element with required fields.
func NewElement(spdxID, name string, creationInfo CreationInfo) Element {
	return Element{
		SpdxID:       spdxID,
		Name:         name,
		CreationInfo: creationInfo,
	}
}

// NewPackage creates a new Package with required fields.
func NewPackage(spdxID, name, version string, creationInfo CreationInfo) *Package {
	return &Package{
		SoftwareArtifact: SoftwareArtifact{
			Artifact: Artifact{
				Element: NewElement(spdxID, name, creationInfo),
			},
		},
		PackageVersion: version,
	}
}

// NewFile creates a new File with required fields.
func NewFile(spdxID, name string, creationInfo CreationInfo) *File {
	return &File{
		SoftwareArtifact: SoftwareArtifact{
			Artifact: Artifact{
				Element: NewElement(spdxID, name, creationInfo),
			},
		},
	}
}

// NewRelationship creates a new Relationship with required fields.
func NewRelationship(spdxID string, from Element, to []Element, relType RelationshipType, creationInfo CreationInfo) *Relationship {
	return &Relationship{
		Element:          NewElement(spdxID, "", creationInfo),
		From:             from,
		To:               to,
		RelationshipType: relType,
	}
}

// NewSpdxDocument creates a new SpdxDocument with required fields.
func NewSpdxDocument(spdxID, name string, creationInfo CreationInfo) *SpdxDocument {
	return &SpdxDocument{
		ElementCollection: ElementCollection{
			Element: NewElement(spdxID, name, creationInfo),
		},
	}
}

// NewAgent creates a new Agent with required fields.
func NewAgent(spdxID, name string, creationInfo CreationInfo) *Agent {
	return &Agent{
		Element: NewElement(spdxID, name, creationInfo),
	}
}

// NewTool creates a new Tool with required fields.
func NewTool(spdxID, name string, creationInfo CreationInfo) *Tool {
	return &Tool{
		Element: NewElement(spdxID, name, creationInfo),
	}
}

// NewHash creates a new Hash with the given algorithm and value.
func NewHash(algorithm HashAlgorithm, hashValue string) Hash {
	return Hash{
		Algorithm: algorithm,
		HashValue: hashValue,
	}
}

// NewExternalIdentifier creates a new ExternalIdentifier with required fields.
func NewExternalIdentifier(idType ExternalIdentifierType, identifier string) ExternalIdentifier {
	return ExternalIdentifier{
		ExternalIdentifierType: idType,
		Identifier:             identifier,
	}
}

// WithPURL adds a PURL external identifier to the element.
func (e *Element) WithPURL(purl string) *Element {
	e.ExternalIdentifier = append(e.ExternalIdentifier, NewExternalIdentifier(
		ExternalIdentifierTypePackageUrl,
		purl,
	))
	return e
}

// WithCPE adds a CPE external identifier to the element.
func (e *Element) WithCPE(cpe string) *Element {
	idType := ExternalIdentifierTypeCpe23
	if len(cpe) > 4 && cpe[:5] == "cpe:/" {
		idType = ExternalIdentifierTypeCpe22
	}
	e.ExternalIdentifier = append(e.ExternalIdentifier, NewExternalIdentifier(
		idType,
		cpe,
	))
	return e
}

// AddHash adds a hash to the element's verification methods.
// TODO: Implement properly when VerifiedUsing supports Hash type.
func (e *Element) AddHash(_ HashAlgorithm, _ string) *Element {
	e.VerifiedUsing = append(e.VerifiedUsing, IntegrityMethod{})
	return e
}

// HasPURL returns true if the element has a PURL external identifier.
func (e *Element) HasPURL() bool {
	for _, ei := range e.ExternalIdentifier {
		if ei.ExternalIdentifierType == ExternalIdentifierTypePackageUrl {
			return true
		}
	}
	return false
}

// GetPURL returns the PURL external identifier if present.
func (e *Element) GetPURL() string {
	for _, ei := range e.ExternalIdentifier {
		if ei.ExternalIdentifierType == ExternalIdentifierTypePackageUrl {
			return ei.Identifier
		}
	}
	return ""
}

// GetCPE returns the CPE external identifier if present.
func (e *Element) GetCPE() string {
	for _, ei := range e.ExternalIdentifier {
		if ei.ExternalIdentifierType == ExternalIdentifierTypeCpe22 ||
			ei.ExternalIdentifierType == ExternalIdentifierTypeCpe23 {
			return ei.Identifier
		}
	}
	return ""
}

// IsDependency returns true if this relationship represents a dependency.
func (r *Relationship) IsDependency() bool {
	switch r.RelationshipType {
	case RelationshipTypeDependsOn,
		RelationshipTypeHasOptionalDependency,
		RelationshipTypeHasProvidedDependency,
		RelationshipTypeHasPrerequisite:
		return true
	}
	return false
}

// IsContainment returns true if this relationship represents containment.
func (r *Relationship) IsContainment() bool {
	return r.RelationshipType == RelationshipTypeContains
}

// IsDescription returns true if this relationship describes an element.
func (r *Relationship) IsDescription() bool {
	return r.RelationshipType == RelationshipTypeDescribes
}

// IsLicenseRelationship returns true if this relationship is license-related.
func (r *Relationship) IsLicenseRelationship() bool {
	switch r.RelationshipType {
	case RelationshipTypeHasConcludedLicense,
		RelationshipTypeHasDeclaredLicense:
		return true
	}
	return false
}

// IsConcludedLicense returns true if this is a concluded license relationship.
func (r *Relationship) IsConcludedLicense() bool {
	return r.RelationshipType == RelationshipTypeHasConcludedLicense
}

// IsDeclaredLicense returns true if this is a declared license relationship.
func (r *Relationship) IsDeclaredLicense() bool {
	return r.RelationshipType == RelationshipTypeHasDeclaredLicense
}

// IsSecurityRelationship returns true if this relationship is security/vulnerability-related.
func (r *Relationship) IsSecurityRelationship() bool {
	switch r.RelationshipType {
	case RelationshipTypeAffects,
		RelationshipTypeDoesNotAffect,
		RelationshipTypeFixedIn,
		RelationshipTypeUnderInvestigationFor,
		RelationshipTypeHasAssessmentFor,
		RelationshipTypeHasAssociatedVulnerability,
		RelationshipTypeFoundBy,
		RelationshipTypeFixedBy,
		RelationshipTypeExploitCreatedBy,
		RelationshipTypePublishedBy,
		RelationshipTypeReportedBy,
		RelationshipTypeRepublishedBy,
		RelationshipTypeCoordinatedBy:
		return true
	}
	return false
}

// IsBuildRelationship returns true if this relationship is build-related.
func (r *Relationship) IsBuildRelationship() bool {
	switch r.RelationshipType {
	case RelationshipTypeHasInput,
		RelationshipTypeHasOutput,
		RelationshipTypeHasHost,
		RelationshipTypeInvokedBy,
		RelationshipTypeGenerates:
		return true
	}
	return false
}

// relationshipTypeMap maps uppercase underscore format to camelCase format.
var relationshipTypeMap = map[string]RelationshipType{
	"AFFECTS":                      RelationshipTypeAffects,
	"AMENDED_BY":                   RelationshipTypeAmendedBy,
	"ANCESTOR_OF":                  RelationshipTypeAncestorOf,
	"AVAILABLE_FROM":               RelationshipTypeAvailableFrom,
	"CONFIGURES":                   RelationshipTypeConfigures,
	"CONTAINS":                     RelationshipTypeContains,
	"COORDINATED_BY":               RelationshipTypeCoordinatedBy,
	"COPIED_TO":                    RelationshipTypeCopiedTo,
	"DELEGATED_TO":                 RelationshipTypeDelegatedTo,
	"DEPENDS_ON":                   RelationshipTypeDependsOn,
	"DESCENDANT_OF":                RelationshipTypeDescendantOf,
	"DESCRIBES":                    RelationshipTypeDescribes,
	"DOES_NOT_AFFECT":              RelationshipTypeDoesNotAffect,
	"EXPANDS_TO":                   RelationshipTypeExpandsTo,
	"EXPLOIT_CREATED_BY":           RelationshipTypeExploitCreatedBy,
	"FIXED_BY":                     RelationshipTypeFixedBy,
	"FIXED_IN":                     RelationshipTypeFixedIn,
	"FOUND_BY":                     RelationshipTypeFoundBy,
	"GENERATES":                    RelationshipTypeGenerates,
	"HAS_ADDED_FILE":               RelationshipTypeHasAddedFile,
	"HAS_ASSESSMENT_FOR":           RelationshipTypeHasAssessmentFor,
	"HAS_ASSOCIATED_VULNERABILITY": RelationshipTypeHasAssociatedVulnerability,
	"HAS_CONCLUDED_LICENSE":        RelationshipTypeHasConcludedLicense,
	"HAS_DATA_FILE":                RelationshipTypeHasDataFile,
	"HAS_DECLARED_LICENSE":         RelationshipTypeHasDeclaredLicense,
	"HAS_DELETED_FILE":             RelationshipTypeHasDeletedFile,
	"HAS_DEPENDENCY_MANIFEST":      RelationshipTypeHasDependencyManifest,
	"HAS_DISTRIBUTION_ARTIFACT":    RelationshipTypeHasDistributionArtifact,
	"HAS_DOCUMENTATION":            RelationshipTypeHasDocumentation,
	"HAS_DYNAMIC_LINK":             RelationshipTypeHasDynamicLink,
	"HAS_EVIDENCE":                 RelationshipTypeHasEvidence,
	"HAS_EXAMPLE":                  RelationshipTypeHasExample,
	"HAS_HOST":                     RelationshipTypeHasHost,
	"HAS_INPUT":                    RelationshipTypeHasInput,
	"HAS_METADATA":                 RelationshipTypeHasMetadata,
	"HAS_OPTIONAL_COMPONENT":       RelationshipTypeHasOptionalComponent,
	"HAS_OPTIONAL_DEPENDENCY":      RelationshipTypeHasOptionalDependency,
	"HAS_OUTPUT":                   RelationshipTypeHasOutput,
	"HAS_PREREQUISITE":             RelationshipTypeHasPrerequisite,
	"HAS_PROVIDED_DEPENDENCY":      RelationshipTypeHasProvidedDependency,
	"HAS_REQUIREMENT":              RelationshipTypeHasRequirement,
	"HAS_SPECIFICATION":            RelationshipTypeHasSpecification,
	"HAS_STATIC_LINK":              RelationshipTypeHasStaticLink,
	"HAS_TEST":                     RelationshipTypeHasTest,
	"HAS_TEST_CASE":                RelationshipTypeHasTestCase,
	"HAS_VARIANT":                  RelationshipTypeHasVariant,
	"INVOKED_BY":                   RelationshipTypeInvokedBy,
	"MODIFIED_BY":                  RelationshipTypeModifiedBy,
	"OTHER":                        RelationshipTypeOther,
	"PACKAGED_BY":                  RelationshipTypePackagedBy,
	"PATCHED_BY":                   RelationshipTypePatchedBy,
	"PUBLISHED_BY":                 RelationshipTypePublishedBy,
	"REPORTED_BY":                  RelationshipTypeReportedBy,
	"REPUBLISHED_BY":               RelationshipTypeRepublishedBy,
	"SERIALIZED_IN_ARTIFACT":       RelationshipTypeSerializedInArtifact,
	"TESTED_ON":                    RelationshipTypeTestedOn,
	"TRAINED_ON":                   RelationshipTypeTrainedOn,
	"UNDER_INVESTIGATION_FOR":      RelationshipTypeUnderInvestigationFor,
	"USES_TOOL":                    RelationshipTypeUsesTool,
}

// NormalizeRelationshipType converts a relationship type string to the canonical
// camelCase format used in the SPDX 3.0.1 model. It accepts both the camelCase
// format (e.g., "dependsOn") and the uppercase underscore format (e.g., "DEPENDS_ON").
func NormalizeRelationshipType(s string) RelationshipType {
	// First check if it's already a valid camelCase type
	rt := RelationshipType(s)
	if rt.IsValid() {
		return rt
	}

	// Try to map from uppercase underscore format
	if normalized, ok := relationshipTypeMap[s]; ok {
		return normalized
	}

	// Return as-is (will be invalid but preserves the original value)
	return rt
}
