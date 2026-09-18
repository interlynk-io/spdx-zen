// Copyright 2026 Interlynk Inc
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

// Package serialize provides JSON-LD serialization capabilities for SPDX 3.0 documents.
//
// The package supports writing SPDX documents to files or io.Writers,
// producing valid SPDX 3.0 JSON-LD output from typed Go structures.
//
// Example usage:
//
//	writer := serialize.NewWriter()
//	err := writer.WriteFile(doc, "out.spdx.json")
package serialize

import (
	"reflect"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

// typeRegistry maps Go struct types to their JSON-LD "type" string.
//
// SPDX 3.0 JSON-LD uses the "type" field to identify the class of each
// element in @graph. During parsing this field was the routing key; during
// serialization we must inject it back.
//
// Most mappings are 1:1. Notable exceptions:
//   - LicenseExpression maps to "simplelicensing_LicenseExpression" (the
//     commonly used JSON-LD type; the bare "LicenseExpression" is also valid)
//   - DatasetPackage maps to "dataset_Dataset" (Go name differs from RDF class)
var typeRegistry = map[reflect.Type]string{
	// Core
	reflect.TypeOf(spdx.Element{}):                     "Element",
	reflect.TypeOf(spdx.SpdxDocument{}):                "SpdxDocument",
	reflect.TypeOf(spdx.Relationship{}):                "Relationship",
	reflect.TypeOf(spdx.LifecycleScopedRelationship{}): "LifecycleScopedRelationship",
	reflect.TypeOf(spdx.Annotation{}):                  "Annotation",
	reflect.TypeOf(spdx.Bom{}):                         "Bom",
	reflect.TypeOf(spdx.Bundle{}):                      "Bundle",
	reflect.TypeOf(spdx.ExternalMap{}):                 "ExternalMap",
	reflect.TypeOf(spdx.ExternalIdentifier{}):          "ExternalIdentifier",
	reflect.TypeOf(spdx.ExternalRef{}):                 "ExternalRef",
	reflect.TypeOf(spdx.Hash{}):                        "Hash",
	reflect.TypeOf(spdx.CreationInfo{}):                "CreationInfo",
	reflect.TypeOf(spdx.Agent{}):                       "Agent",
	reflect.TypeOf(spdx.Person{}):                      "Person",
	reflect.TypeOf(spdx.Organization{}):                "Organization",
	reflect.TypeOf(spdx.SoftwareAgent{}):               "SoftwareAgent",
	reflect.TypeOf(spdx.Tool{}):                        "Tool",
	reflect.TypeOf(spdx.Artifact{}):                    "Artifact",
	reflect.TypeOf(spdx.NamespaceMap{}):                "NamespaceMap",
	reflect.TypeOf(spdx.DictionaryEntry{}):             "DictionaryEntry",
	reflect.TypeOf(spdx.PositiveIntegerRange{}):        "PositiveIntegerRange",
	reflect.TypeOf(spdx.IntegrityMethod{}):             "IntegrityMethod",
	reflect.TypeOf(spdx.PackageVerificationCode{}):     "PackageVerificationCode",
	reflect.TypeOf(spdx.IndividualElement{}):           "IndividualElement",

	// Software
	reflect.TypeOf(spdx.Package{}):          "software_Package",
	reflect.TypeOf(spdx.File{}):             "software_File",
	reflect.TypeOf(spdx.Snippet{}):          "software_Snippet",
	reflect.TypeOf(spdx.Sbom{}):             "software_Sbom",
	reflect.TypeOf(spdx.SoftwareArtifact{}): "software_SoftwareArtifact",

	// Licensing
	reflect.TypeOf(spdx.AnyLicenseInfo{}):          "AnyLicenseInfo",
	reflect.TypeOf(spdx.License{}):                 "License",
	reflect.TypeOf(spdx.ListedLicense{}):           "ListedLicense",
	reflect.TypeOf(spdx.CustomLicense{}):           "CustomLicense",
	reflect.TypeOf(spdx.LicenseExpression{}):       "simplelicensing_LicenseExpression",
	reflect.TypeOf(spdx.ConjunctiveLicenseSet{}):   "ConjunctiveLicenseSet",
	reflect.TypeOf(spdx.DisjunctiveLicenseSet{}):   "DisjunctiveLicenseSet",
	reflect.TypeOf(spdx.WithAdditionOperator{}):    "WithAdditionOperator",
	reflect.TypeOf(spdx.LicenseAddition{}):         "LicenseAddition",
	reflect.TypeOf(spdx.IndividualLicensingInfo{}): "IndividualLicensingInfo",
	reflect.TypeOf(spdx.SimpleLicensingText{}):     "simplelicensing_SimpleLicensingText",
	reflect.TypeOf(spdx.OrLaterOperator{}):         "expandedlicensing_OrLaterOperator",
	reflect.TypeOf(spdx.ListedLicenseException{}):  "expandedlicensing_ListedLicenseException",
	reflect.TypeOf(spdx.CustomLicenseAddition{}):   "CustomLicenseAddition",

	// Security
	reflect.TypeOf(spdx.Vulnerability{}):                                   "security_Vulnerability",
	reflect.TypeOf(spdx.VulnAssessmentRelationship{}):                      "security_VulnAssessmentRelationship",
	reflect.TypeOf(spdx.CvssV2VulnAssessmentRelationship{}):                "security_CvssV2VulnAssessmentRelationship",
	reflect.TypeOf(spdx.CvssV3VulnAssessmentRelationship{}):                "security_CvssV3VulnAssessmentRelationship",
	reflect.TypeOf(spdx.CvssV4VulnAssessmentRelationship{}):                "security_CvssV4VulnAssessmentRelationship",
	reflect.TypeOf(spdx.EpssVulnAssessmentRelationship{}):                  "security_EpssVulnAssessmentRelationship",
	reflect.TypeOf(spdx.SsvcVulnAssessmentRelationship{}):                  "security_SsvcVulnAssessmentRelationship",
	reflect.TypeOf(spdx.ExploitCatalogVulnAssessmentRelationship{}):        "security_ExploitCatalogVulnAssessmentRelationship",
	reflect.TypeOf(spdx.VexVulnAssessmentRelationship{}):                   "security_VexVulnAssessmentRelationship",
	reflect.TypeOf(spdx.VexAffectedVulnAssessmentRelationship{}):           "security_VexAffectedVulnAssessmentRelationship",
	reflect.TypeOf(spdx.VexFixedVulnAssessmentRelationship{}):              "security_VexFixedVulnAssessmentRelationship",
	reflect.TypeOf(spdx.VexNotAffectedVulnAssessmentRelationship{}):        "security_VexNotAffectedVulnAssessmentRelationship",
	reflect.TypeOf(spdx.VexUnderInvestigationVulnAssessmentRelationship{}): "security_VexUnderInvestigationVulnAssessmentRelationship",

	// AI
	reflect.TypeOf(spdx.AIPackage{}):                    "ai_AIPackage",
	reflect.TypeOf(spdx.EnergyConsumption{}):            "ai_EnergyConsumption",
	reflect.TypeOf(spdx.EnergyConsumptionDescription{}): "ai_EnergyConsumptionDescription",

	// Dataset
	// Note: Go type is DatasetPackage but JSON-LD type is dataset_Dataset
	reflect.TypeOf(spdx.DatasetPackage{}): "dataset_Dataset",

	// Build
	reflect.TypeOf(spdx.Build{}): "build_Build",
}

// GetTypeFor returns the JSON-LD type string for a given value.
// It accepts both value and pointer types.
func GetTypeFor(v interface{}) (string, bool) {
	if v == nil {
		return "", false
	}
	t := reflect.TypeOf(v)
	// Dereference pointer types
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	typ, ok := typeRegistry[t]
	return typ, ok
}

// IsRegistered returns true if the given value's type is in the registry.
func IsRegistered(v interface{}) bool {
	_, ok := GetTypeFor(v)
	return ok
}
