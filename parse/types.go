package parse

// ElementType represents the type of an SPDX element in JSON-LD format.
type ElementType string

// Core SPDX element types.
const (
	TypeElement                 ElementType = "Element"
	TypeSpdxDocument            ElementType = "SpdxDocument"
	TypeRelationship            ElementType = "Relationship"
	TypeAnnotation              ElementType = "Annotation"
	TypeBundle                  ElementType = "Bundle"
	TypeExternalMap             ElementType = "ExternalMap"
	TypeExternalIdentifier      ElementType = "ExternalIdentifier"
	TypeExternalRef             ElementType = "ExternalRef"
	TypeHash                    ElementType = "Hash"
	TypeCreationInfo            ElementType = "CreationInfo"
	TypeAgent                   ElementType = "Agent"
	TypePerson                  ElementType = "Person"
	TypeOrganization            ElementType = "Organization"
	TypeSoftwareAgent           ElementType = "SoftwareAgent"
	TypeTool                    ElementType = "Tool"
	TypeArtifact                ElementType = "Artifact"
	TypeNamespaceMap            ElementType = "NamespaceMap"
	TypeDictionaryEntry         ElementType = "DictionaryEntry"
	TypePositiveIntegerRange    ElementType = "PositiveIntegerRange"
	TypeIntegrityMethod         ElementType = "IntegrityMethod"
	TypePackageVerificationCode ElementType = "PackageVerificationCode"
)

// Software-related element types.
const (
	TypeSoftwarePackage  ElementType = "software_Package"
	TypeSoftwareFile     ElementType = "software_File"
	TypeSoftwareSnippet  ElementType = "software_Snippet"
	TypeSoftwareSbom     ElementType = "software_Sbom"
	TypeSoftwareArtifact ElementType = "software_SoftwareArtifact"
)

// Licensing-related element types.
const (
	TypeAnyLicenseInfo             ElementType = "AnyLicenseInfo"
	TypeLicense                    ElementType = "License"
	TypeListedLicense              ElementType = "ListedLicense"
	TypeCustomLicense              ElementType = "CustomLicense"
	TypeLicenseExpression          ElementType = "LicenseExpression"
	TypeSimpleLicensingExpression ElementType = "simplelicensing_LicenseExpression"
	TypeConjunctiveLicenseSet      ElementType = "ConjunctiveLicenseSet"
	TypeDisjunctiveLicenseSet      ElementType = "DisjunctiveLicenseSet"
	TypeWithAdditionOperator       ElementType = "WithAdditionOperator"
	TypeLicenseAddition            ElementType = "LicenseAddition"
)

// Security-related element types.
const (
	TypeVulnerability                ElementType = "security_Vulnerability"
	TypeVulnAssessmentRelationship   ElementType = "security_VulnAssessmentRelationship"
	TypeCvssV2VulnAssessment         ElementType = "security_CvssV2VulnAssessmentRelationship"
	TypeCvssV3VulnAssessment         ElementType = "security_CvssV3VulnAssessmentRelationship"
	TypeCvssV4VulnAssessment         ElementType = "security_CvssV4VulnAssessmentRelationship"
	TypeEpssVulnAssessment           ElementType = "security_EpssVulnAssessmentRelationship"
	TypeSsvcVulnAssessment           ElementType = "security_SsvcVulnAssessmentRelationship"
	TypeVexVulnAssessment            ElementType = "security_VexVulnAssessmentRelationship"
	TypeExploitCatalogVulnAssessment ElementType = "security_ExploitCatalogVulnAssessmentRelationship"
)

// AI/ML element types.
const (
	TypeAIPackage ElementType = "ai_AIPackage"
)

// Dataset element types.
const (
	TypeDataset ElementType = "dataset_Dataset"
)

// Build element types.
const (
	TypeBuild ElementType = "build_Build"
)

// String returns the string representation of the ElementType.
func (t ElementType) String() string {
	return string(t)
}

// IsCore returns true if this is a core SPDX element type.
func (t ElementType) IsCore() bool {
	switch t {
	case TypeElement, TypeSpdxDocument, TypeRelationship, TypeAnnotation,
		TypeBundle, TypeExternalMap, TypeExternalIdentifier, TypeExternalRef,
		TypeHash, TypeCreationInfo, TypeAgent, TypePerson, TypeOrganization,
		TypeSoftwareAgent, TypeTool, TypeArtifact, TypeNamespaceMap,
		TypeDictionaryEntry, TypePositiveIntegerRange, TypeIntegrityMethod,
		TypePackageVerificationCode:
		return true
	}
	return false
}

// IsSoftware returns true if this is a software-related element type.
func (t ElementType) IsSoftware() bool {
	switch t {
	case TypeSoftwarePackage, TypeSoftwareFile, TypeSoftwareSnippet,
		TypeSoftwareSbom, TypeSoftwareArtifact:
		return true
	}
	return false
}

// IsLicensing returns true if this is a licensing-related element type.
func (t ElementType) IsLicensing() bool {
	switch t {
	case TypeAnyLicenseInfo, TypeLicense, TypeListedLicense, TypeCustomLicense,
		TypeLicenseExpression, TypeSimpleLicensingExpression, TypeConjunctiveLicenseSet, TypeDisjunctiveLicenseSet,
		TypeWithAdditionOperator, TypeLicenseAddition:
		return true
	}
	return false
}

// IsSecurity returns true if this is a security-related element type.
func (t ElementType) IsSecurity() bool {
	switch t {
	case TypeVulnerability, TypeVulnAssessmentRelationship, TypeCvssV2VulnAssessment,
		TypeCvssV3VulnAssessment, TypeCvssV4VulnAssessment, TypeEpssVulnAssessment,
		TypeSsvcVulnAssessment, TypeVexVulnAssessment, TypeExploitCatalogVulnAssessment:
		return true
	}
	return false
}
