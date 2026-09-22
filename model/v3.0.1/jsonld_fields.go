// SPDX JSON-LD Field Registry
//
// This file is the single source of truth for SPDX 3.0 JSON-LD field metadata.
// It connects each profile-specific field to its official SPDX ontology URI,
// namespace, and JSON-LD prefix. Both the parse.Reader and the serialize.Writer
// use this registry so that field names stay consistent across read and write.
//
// When adding a new profile or field, update this file and both parser and
// serializer will automatically pick up the change.

package spdx

import (
	"fmt"
	"strings"
)

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
	TypeSoftwarePackage  ElementType = "software_Package"
	TypeSoftwareFile     ElementType = "software_File"
	TypeSoftwareSnippet  ElementType = "software_Snippet"
	TypeSoftwareSbom     ElementType = "software_Sbom"
	TypeSoftwareArtifact ElementType = "software_SoftwareArtifact"
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

const spdxBaseURI = "https://spdx.org/rdf/3.0.1/terms/"

// JSONLDFieldInfo holds the complete SPDX ontology metadata for a single
// profile-specific field. It connects the bare property name (as used in the
// ontology and Go struct tags) to its JSON-LD prefix, namespace, and full
// canonical URI.
type JSONLDFieldInfo struct {
	BareName  string // e.g. "downloadLocation"
	Prefix    string // e.g. "software_"
	Namespace string // e.g. "Software"
	FullURI   string // e.g. "https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation"
}

// parseSPDXURI extracts namespace and bareName from an official SPDX
// ontology URI. The URI must follow the pattern:
//
//	https://spdx.org/rdf/3.0.1/terms/{Namespace}/{bareName}
//
// e.g. "https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation"
//
//	→ namespace="Software", bareName="downloadLocation"
func parseSPDXURI(uri string) (namespace, bareName string) {
	rest := strings.TrimPrefix(uri, spdxBaseURI)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// namespaceToPrefix maps SPDX ontology namespace names to their JSON-LD
// prefix strings. The prefix is always lowercase(namespace)+"_".
func namespaceToPrefix(ns string) string {
	return strings.ToLower(ns) + "_"
}

// mustParseURI creates a JSONLDFieldInfo from an official SPDX ontology URI.
// All fields (Namespace, BareName, Prefix, FullURI) are derived from the URI.
//
// Example:
//
//	mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation")
//
//	returns JSONLDFieldInfo{
//	    BareName:  "downloadLocation",
//	    Namespace: "Software",
//	    Prefix:    "software_",
//	    FullURI:   "https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation",
//	}
func mustParseURI(uri string) JSONLDFieldInfo {
	ns, bare := parseSPDXURI(uri)
	if ns == "" || bare == "" {
		panic(fmt.Sprintf("invalid SPDX URI: %s", uri))
	}
	return JSONLDFieldInfo{
		BareName:  bare,
		Namespace: ns,
		Prefix:    namespaceToPrefix(ns),
		FullURI:   uri,
	}
}

// JSONLDFieldRegistry maps SPDX JSON-LD element types to their profile-specific
// field metadata.
//
// For each element type, the inner map holds bare field names (as they appear
// in Go struct tags / JSON-LD ontology) and their complete JSONLDFieldInfo.
//
// Core fields inherited from Element, Artifact, Relationship, etc.
// (e.g. name, spdxId, summary, creationInfo) are intentionally omitted because
// they never carry a profile prefix and live in the Core namespace.
//
// This is the single source of truth used by both the parser and the
// serializer so that field names stay consistent across read and write.
var JSONLDFieldRegistry = map[ElementType]map[string]JSONLDFieldInfo{
	// ---------------------------------------
	// Software Profile
	// ---------------------------------------
	TypeSoftwarePackage: {
		"downloadLocation":  mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation"),
		"homePage":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/homePage"),
		"packageUrl":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageUrl"),
		"packageVersion":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageVersion"),
		"sourceInfo":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/sourceInfo"),
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
	},
	TypeSoftwareFile: {
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
		"fileKind":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/fileKind"),
		"contentType":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/contentType"),
	},
	TypeSoftwareSnippet: {
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
		"byteRange":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/byteRange"),
		"lineRange":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/lineRange"),
	},
	TypeSoftwareArtifact: {
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
	},
	TypeSoftwareSbom: {
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
		"sbomType":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/sbomType"),
	},

	// ---------------------------------------
	// Security Profile
	// ---------------------------------------
	TypeVulnerability: {
		"publishedTime": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":  mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
	},
	TypeCvssV2VulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"score":           mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/score"),
		"vectorString":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vectorString"),
	},
	TypeCvssV3VulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"score":           mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/score"),
		"severity":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/severity"),
		"vectorString":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vectorString"),
	},
	TypeCvssV4VulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"score":           mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/score"),
		"severity":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/severity"),
		"vectorString":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vectorString"),
	},
	TypeEpssVulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"probability":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/probability"),
		"percentile":      mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/percentile"),
	},
	TypeExploitCatalogVulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"catalogType":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/catalogType"),
		"exploited":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/exploited"),
		"locator":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/locator"),
	},
	TypeSsvcVulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"decisionType":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/decisionType"),
	},
	TypeVexAffectedVulnAssessment: {
		"assessedElement":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"vexVersion":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vexVersion"),
		"statusNotes":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/statusNotes"),
		"actionStatement":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/actionStatement"),
		"actionStatementTime": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/actionStatementTime"),
	},
	TypeVexFixedVulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"vexVersion":      mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vexVersion"),
		"statusNotes":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/statusNotes"),
	},
	TypeVexNotAffectedVulnAssessment: {
		"assessedElement":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"vexVersion":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vexVersion"),
		"statusNotes":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/statusNotes"),
		"justificationType":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/justificationType"),
		"impactStatement":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/impactStatement"),
		"impactStatementTime": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/impactStatementTime"),
	},
	TypeVexUnderInvestigationVulnAssessment: {
		"assessedElement": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/assessedElement"),
		"publishedTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/publishedTime"),
		"modifiedTime":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/modifiedTime"),
		"withdrawnTime":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/withdrawnTime"),
		"vexVersion":      mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/vexVersion"),
		"statusNotes":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Security/statusNotes"),
	},

	// ---------------------------------------
	// AI Profile
	// ---------------------------------------
	// AIPackage embeds Package, so Software profile fields are also listed.
	TypeAIPackage: {
		// AI-specific fields
		"autonomyType":                    mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/autonomyType"),
		"domain":                          mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/domain"),
		"energyConsumption":               mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/energyConsumption"),
		"hyperparameter":                  mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/hyperparameter"),
		"informationAboutApplication":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/informationAboutApplication"),
		"informationAboutTraining":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/informationAboutTraining"),
		"limitation":                      mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/limitation"),
		"metric":                          mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/metric"),
		"metricDecisionThreshold":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/metricDecisionThreshold"),
		"modelDataPreprocessing":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/modelDataPreprocessing"),
		"modelExplainability":             mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/modelExplainability"),
		"safetyRiskAssessment":            mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/safetyRiskAssessment"),
		"standardCompliance":              mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/standardCompliance"),
		"typeOfModel":                     mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/typeOfModel"),
		"useSensitivePersonalInformation": mustParseURI("https://spdx.org/rdf/3.0.1/terms/AI/useSensitivePersonalInformation"),
		// Software profile fields (inherited from Package → SoftwareArtifact)
		"downloadLocation":  mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation"),
		"homePage":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/homePage"),
		"packageUrl":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageUrl"),
		"packageVersion":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageVersion"),
		"sourceInfo":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/sourceInfo"),
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
	},

	// ---------------------------------------
	// Dataset Profile
	// ---------------------------------------
	// DatasetPackage embeds Package, so Software profile fields are also listed.
	TypeDataset: {
		// Dataset-specific fields
		"anonymizationMethodUsed":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/anonymizationMethodUsed"),
		"confidentialityLevel":            mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/confidentialityLevel"),
		"dataCollectionProcess":           mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/dataCollectionProcess"),
		"dataPreprocessing":               mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/dataPreprocessing"),
		"datasetAvailability":             mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/datasetAvailability"),
		"datasetNoise":                    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/datasetNoise"),
		"datasetSize":                     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/datasetSize"),
		"datasetType":                     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/datasetType"),
		"datasetUpdateMechanism":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/datasetUpdateMechanism"),
		"hasSensitivePersonalInformation": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/hasSensitivePersonalInformation"),
		"intendedUse":                     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/intendedUse"),
		"knownBias":                       mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/knownBias"),
		"sensor":                          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Dataset/sensor"),
		// Software profile fields (inherited from Package → SoftwareArtifact)
		"downloadLocation":  mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation"),
		"homePage":          mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/homePage"),
		"packageUrl":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageUrl"),
		"packageVersion":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/packageVersion"),
		"sourceInfo":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/sourceInfo"),
		"primaryPurpose":    mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/primaryPurpose"),
		"additionalPurpose": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/additionalPurpose"),
		"copyrightText":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/copyrightText"),
		"attributionText":   mustParseURI("https://spdx.org/rdf/3.0.1/terms/Software/attributionText"),
	},

	// ---------------------------------------
	// Build Profile
	// ---------------------------------------
	TypeBuild: {
		"buildType":              mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/buildType"),
		"buildId":                mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/buildId"),
		"configSourceEntrypoint": mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/configSourceEntrypoint"),
		"configSourceUri":        mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/configSourceUri"),
		"configSourceDigest":     mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/configSourceDigest"),
		"parameter":              mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/parameter"),
		"buildStartTime":         mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/buildStartTime"),
		"buildEndTime":           mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/buildEndTime"),
		"environment":            mustParseURI("https://spdx.org/rdf/3.0.1/terms/Build/environment"),
	},
}

// GetJSONLDFieldInfo returns the full metadata for a given element type and
// bare field name. The second return value is false if no profile-specific
// field is registered, indicating the field is a Core property.
func GetJSONLDFieldInfo(elemType ElementType, field string) (JSONLDFieldInfo, bool) {
	if fields, ok := JSONLDFieldRegistry[elemType]; ok {
		if info, ok := fields[field]; ok {
			return info, true
		}
	}
	return JSONLDFieldInfo{}, false
}

// GetJSONLDFieldPrefix returns the JSON-LD prefix for a given element type
// and bare field name. If no prefix is registered, it returns an empty
// string, indicating the field is a Core property and should remain bare.
func GetJSONLDFieldPrefix(elemType ElementType, field string) string {
	if info, ok := GetJSONLDFieldInfo(elemType, field); ok {
		return info.Prefix
	}
	return ""
}

// GetJSONLDFieldNamespace returns the SPDX ontology namespace for a given
// element type and bare field name. If the field is not registered, it
// returns "Core".
func GetJSONLDFieldNamespace(elemType ElementType, field string) string {
	if info, ok := GetJSONLDFieldInfo(elemType, field); ok {
		return info.Namespace
	}
	return "Core"
}

// GetJSONLDFieldFullURI returns the official SPDX ontology URI for a given
// element type and bare field name. Core fields return the Core namespace URI.
func GetJSONLDFieldFullURI(elemType ElementType, field string) string {
	if info, ok := GetJSONLDFieldInfo(elemType, field); ok {
		return info.FullURI
	}
	return spdxBaseURI + "Core/" + field
}

// PrefixedJSONLDKey returns the full JSON-LD key for a field, applying the
// registered prefix if one exists.
func PrefixedJSONLDKey(elemType ElementType, field string) string {
	if info, ok := GetJSONLDFieldInfo(elemType, field); ok {
		return info.Prefix + field
	}
	return field
}
