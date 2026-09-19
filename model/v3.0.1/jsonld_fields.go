// SPDX JSON-LD Field Prefix Registry
//
// This file is the single source of truth for profile-specific field prefixes
// in SPDX 3.0 JSON-LD serialization. Both the parse.Reader and the
// serialize.Writer use this registry so that field names stay consistent across
// read and write.
//
// When adding a new profile or field, update this file and both parser and
// serializer will automatically pick up the change.

package spdx

// ElementType represents the type of an SPDX element in JSON-LD format.
type ElementType string

// Core SPDX element types.
const (
	TypeElement                     ElementType = "Element"
	TypeSpdxDocument                ElementType = "SpdxDocument"
	TypeRelationship                ElementType = "Relationship"
	TypeLifecycleScopedRelationship ElementType = "LifecycleScopedRelationship"
	TypeAnnotation                  ElementType = "Annotation"
	TypeBom                         ElementType = "Bom"
	TypeBundle                      ElementType = "Bundle"
	TypeExternalMap                 ElementType = "ExternalMap"
	TypeExternalIdentifier          ElementType = "ExternalIdentifier"
	TypeExternalRef                 ElementType = "ExternalRef"
	TypeHash                        ElementType = "Hash"
	TypeCreationInfo                ElementType = "CreationInfo"
	TypeAgent                       ElementType = "Agent"
	TypePerson                      ElementType = "Person"
	TypeOrganization                ElementType = "Organization"
	TypeSoftwareAgent               ElementType = "SoftwareAgent"
	TypeTool                        ElementType = "Tool"
	TypeArtifact                    ElementType = "Artifact"
	TypeNamespaceMap                ElementType = "NamespaceMap"
	TypeDictionaryEntry             ElementType = "DictionaryEntry"
	TypePositiveIntegerRange        ElementType = "PositiveIntegerRange"
	TypeIntegrityMethod             ElementType = "IntegrityMethod"
	TypePackageVerificationCode     ElementType = "PackageVerificationCode"
	TypeIndividualElement           ElementType = "IndividualElement"
)

// Software-related element types.
const (
	TypeSoftwarePackage       ElementType = "software_Package"
	TypeSoftwareFile          ElementType = "software_File"
	TypeSoftwareSnippet       ElementType = "software_Snippet"
	TypeSoftwareSbom          ElementType = "software_Sbom"
	TypeSoftwareArtifact      ElementType = "software_SoftwareArtifact"
)

// Licensing-related element types.
const (
	TypeAnyLicenseInfo            ElementType = "AnyLicenseInfo"
	TypeLicense                   ElementType = "License"
	TypeListedLicense             ElementType = "ListedLicense"
	TypeCustomLicense             ElementType = "CustomLicense"
	TypeLicenseExpression         ElementType = "LicenseExpression"
	TypeSimpleLicensingExpression ElementType = "simplelicensing_LicenseExpression"
	TypeConjunctiveLicenseSet     ElementType = "ConjunctiveLicenseSet"
	TypeDisjunctiveLicenseSet     ElementType = "DisjunctiveLicenseSet"
	TypeWithAdditionOperator      ElementType = "WithAdditionOperator"
	TypeLicenseAddition           ElementType = "LicenseAddition"
	TypeIndividualLicensingInfo   ElementType = "IndividualLicensingInfo"
	TypeSimpleLicensingText       ElementType = "simplelicensing_SimpleLicensingText"
	TypeOrLaterOperator           ElementType = "expandedlicensing_OrLaterOperator"
	TypeListedLicenseException    ElementType = "expandedlicensing_ListedLicenseException"
	TypeCustomLicenseAddition     ElementType = "CustomLicenseAddition"
)

// Security-related element types.
const (
	TypeVulnerability                       ElementType = "security_Vulnerability"
	TypeVulnAssessmentRelationship          ElementType = "security_VulnAssessmentRelationship"
	TypeCvssV2VulnAssessment                ElementType = "security_CvssV2VulnAssessmentRelationship"
	TypeCvssV3VulnAssessment                ElementType = "security_CvssV3VulnAssessmentRelationship"
	TypeCvssV4VulnAssessment                ElementType = "security_CvssV4VulnAssessmentRelationship"
	TypeEpssVulnAssessment                  ElementType = "security_EpssVulnAssessmentRelationship"
	TypeSsvcVulnAssessment                  ElementType = "security_SsvcVulnAssessmentRelationship"
	TypeVexVulnAssessment                   ElementType = "security_VexVulnAssessmentRelationship"
	TypeVexAffectedVulnAssessment           ElementType = "security_VexAffectedVulnAssessmentRelationship"
	TypeVexFixedVulnAssessment              ElementType = "security_VexFixedVulnAssessmentRelationship"
	TypeVexNotAffectedVulnAssessment        ElementType = "security_VexNotAffectedVulnAssessmentRelationship"
	TypeVexUnderInvestigationVulnAssessment ElementType = "security_VexUnderInvestigationVulnAssessmentRelationship"
	TypeExploitCatalogVulnAssessment        ElementType = "security_ExploitCatalogVulnAssessmentRelationship"
)

// AI/ML element types.
const (
	TypeAIPackage                    ElementType = "ai_AIPackage"
	TypeEnergyConsumption            ElementType = "ai_EnergyConsumption"
	TypeEnergyConsumptionDescription ElementType = "ai_EnergyConsumptionDescription"
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
	case TypeElement, TypeSpdxDocument, TypeRelationship, TypeLifecycleScopedRelationship, TypeAnnotation,
		TypeBom, TypeBundle, TypeExternalMap, TypeExternalIdentifier, TypeExternalRef,
		TypeHash, TypeCreationInfo, TypeAgent, TypePerson, TypeOrganization,
		TypeSoftwareAgent, TypeTool, TypeArtifact, TypeNamespaceMap,
		TypeDictionaryEntry, TypePositiveIntegerRange, TypeIntegrityMethod,
		TypePackageVerificationCode, TypeIndividualElement:
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
		TypeWithAdditionOperator, TypeLicenseAddition, TypeSimpleLicensingText, TypeOrLaterOperator, TypeListedLicenseException:
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

// JSONLDFieldPrefixes maps SPDX JSON-LD element types to their profile-specific
// field prefixes.
//
// For each element type, the inner map holds bare field names (as they appear
// in Go struct tags / JSON-LD ontology) and the prefix string that must be
// applied when serializing to JSON-LD.
//
// Core fields inherited from Element, Artifact, Relationship, etc.
// (e.g. name, spdxId, summary, creationInfo) are intentionally omitted because
// they never carry a profile prefix.
//
// This is the single source of truth used by both the parser and the
// serializer so that field names stay consistent across read and write.
var JSONLDFieldPrefixes = map[ElementType]map[string]string{
	// ---------------------------------------
	// Software Profile
	// ---------------------------------------
	TypeSoftwarePackage: {
		"downloadLocation":  "software_",
		"homePage":          "software_",
		"packageUrl":        "software_",
		"packageVersion":    "software_",
		"sourceInfo":        "software_",
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
	},
	TypeSoftwareFile: {
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
		"fileKind":          "software_",
		"contentType":       "software_",
	},
	TypeSoftwareSnippet: {
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
		"byteRange":         "software_",
		"lineRange":         "software_",
	},
	TypeSoftwareArtifact: {
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
	},
	TypeSoftwareSbom: {
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
		"sbomType":          "software_",
	},

	// ---------------------------------------
	// Security Profile
	// ---------------------------------------
	TypeVulnerability: {
		"publishedTime": "security_",
		"modifiedTime":  "security_",
		"withdrawnTime": "security_",
	},
	TypeCvssV2VulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"score":           "security_",
		"vectorString":    "security_",
	},
	TypeCvssV3VulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"score":           "security_",
		"severity":        "security_",
		"vectorString":    "security_",
	},
	TypeCvssV4VulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"score":           "security_",
		"severity":        "security_",
		"vectorString":    "security_",
	},
	TypeEpssVulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"probability":     "security_",
		"percentile":      "security_",
	},
	TypeExploitCatalogVulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"catalogType":     "security_",
		"exploited":       "security_",
		"locator":         "security_",
	},
	TypeSsvcVulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"decisionType":    "security_",
	},
	TypeVexAffectedVulnAssessment: {
		"assessedElement":     "security_",
		"publishedTime":       "security_",
		"modifiedTime":        "security_",
		"withdrawnTime":       "security_",
		"vexVersion":          "security_",
		"statusNotes":         "security_",
		"actionStatement":     "security_",
		"actionStatementTime": "security_",
	},
	TypeVexFixedVulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"vexVersion":      "security_",
		"statusNotes":     "security_",
	},
	TypeVexNotAffectedVulnAssessment: {
		"assessedElement":     "security_",
		"publishedTime":       "security_",
		"modifiedTime":        "security_",
		"withdrawnTime":       "security_",
		"vexVersion":          "security_",
		"statusNotes":         "security_",
		"justificationType":   "security_",
		"impactStatement":     "security_",
		"impactStatementTime": "security_",
	},
	TypeVexUnderInvestigationVulnAssessment: {
		"assessedElement": "security_",
		"publishedTime":   "security_",
		"modifiedTime":    "security_",
		"withdrawnTime":   "security_",
		"vexVersion":      "security_",
		"statusNotes":     "security_",
	},

	// ---------------------------------------
	// AI Profile
	// ---------------------------------------
	// AIPackage embeds Package, so Software profile fields are also listed.
	TypeAIPackage: {
		// AI-specific fields
		"autonomyType":                    "ai_",
		"domain":                          "ai_",
		"energyConsumption":               "ai_",
		"hyperparameter":                  "ai_",
		"informationAboutApplication":     "ai_",
		"informationAboutTraining":        "ai_",
		"limitation":                      "ai_",
		"metric":                          "ai_",
		"metricDecisionThreshold":         "ai_",
		"modelDataPreprocessing":          "ai_",
		"modelExplainability":             "ai_",
		"safetyRiskAssessment":            "ai_",
		"standardCompliance":              "ai_",
		"typeOfModel":                     "ai_",
		"useSensitivePersonalInformation": "ai_",
		// Software profile fields (inherited from Package → SoftwareArtifact)
		"downloadLocation":  "software_",
		"homePage":          "software_",
		"packageUrl":        "software_",
		"packageVersion":    "software_",
		"sourceInfo":        "software_",
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
	},

	// ---------------------------------------
	// Dataset Profile
	// ---------------------------------------
	// DatasetPackage embeds Package, so Software profile fields are also listed.
	TypeDataset: {
		// Dataset-specific fields
		"anonymizationMethodUsed":         "dataset_",
		"confidentialityLevel":            "dataset_",
		"dataCollectionProcess":           "dataset_",
		"dataPreprocessing":               "dataset_",
		"datasetAvailability":             "dataset_",
		"datasetNoise":                    "dataset_",
		"datasetSize":                     "dataset_",
		"datasetType":                     "dataset_",
		"datasetUpdateMechanism":          "dataset_",
		"hasSensitivePersonalInformation": "dataset_",
		"intendedUse":                     "dataset_",
		"knownBias":                       "dataset_",
		"sensor":                          "dataset_",
		// Software profile fields (inherited from Package → SoftwareArtifact)
		"downloadLocation":  "software_",
		"homePage":          "software_",
		"packageUrl":        "software_",
		"packageVersion":    "software_",
		"sourceInfo":        "software_",
		"primaryPurpose":    "software_",
		"additionalPurpose": "software_",
		"copyrightText":     "software_",
		"attributionText":   "software_",
	},

	// ---------------------------------------
	// Build Profile
	// ---------------------------------------
	TypeBuild: {
		"buildType":              "build_",
		"buildId":                "build_",
		"configSourceEntrypoint": "build_",
		"configSourceUri":        "build_",
		"configSourceDigest":     "build_",
		"parameter":              "build_",
		"buildStartTime":         "build_",
		"buildEndTime":           "build_",
		"environment":            "build_",
	},
}

// GetJSONLDFieldPrefix returns the prefix for a given element type and bare
// field name. If no prefix is registered, it returns an empty string,
// indicating the field is a Core property and should remain bare.
func GetJSONLDFieldPrefix(elemType ElementType, field string) string {
	if fields, ok := JSONLDFieldPrefixes[elemType]; ok {
		if prefix, ok := fields[field]; ok {
			return prefix
		}
	}
	return ""
}

// PrefixedJSONLDKey returns the full JSON-LD key for a field, applying the
// registered prefix if one exists.
func PrefixedJSONLDKey(elemType ElementType, field string) string {
	prefix := GetJSONLDFieldPrefix(elemType, field)
	return prefix + field
}
