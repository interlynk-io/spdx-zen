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

package serialize

import (
	"testing"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

func TestGetJSONLDTypeString(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		wantType string
		wantOk   bool
	}{
		{"Package value", spdx.Package{}, "software_Package", true},
		{"Package pointer", &spdx.Package{}, "software_Package", true},
		{"SpdxDocument value", spdx.SpdxDocument{}, "SpdxDocument", true},
		{"Relationship pointer", &spdx.Relationship{}, "Relationship", true},
		{"Hash value", spdx.Hash{}, "Hash", true},
		{"CreationInfo pointer", &spdx.CreationInfo{}, "CreationInfo", true},
		{"DatasetPackage value", spdx.DatasetPackage{}, "dataset_Dataset", true},
		{"LicenseExpression value", spdx.LicenseExpression{}, "simplelicensing_LicenseExpression", true},
		{"nil value", nil, "", false},
		{"unregistered string", "hello", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotOk := GetJSONLDTypeString(tt.value)
			if gotOk != tt.wantOk {
				t.Errorf("GetJSONLDTypeString(%v) ok = %v, want %v", tt.value, gotOk, tt.wantOk)
			}
			if gotOk && gotType != tt.wantType {
				t.Errorf("GetJSONLDTypeString(%v) type = %q, want %q", tt.value, gotType, tt.wantType)
			}
		})
	}
}

func TestRegistryCompleteness(t *testing.T) {
	// Ensure all types that appear in parse/types.go have a registry entry.
	// This is a smoke test to catch drift.
	requiredTypes := []interface{}{
		spdx.Package{},
		spdx.File{},
		spdx.Snippet{},
		spdx.Sbom{},
		spdx.SoftwareArtifact{},
		spdx.SpdxDocument{},
		spdx.Relationship{},
		spdx.LifecycleScopedRelationship{},
		spdx.Annotation{},
		spdx.Bom{},
		spdx.Bundle{},
		spdx.ExternalMap{},
		spdx.ExternalIdentifier{},
		spdx.ExternalRef{},
		spdx.Hash{},
		spdx.CreationInfo{},
		spdx.Agent{},
		spdx.Person{},
		spdx.Organization{},
		spdx.SoftwareAgent{},
		spdx.Tool{},
		spdx.Artifact{},
		spdx.NamespaceMap{},
		spdx.DictionaryEntry{},
		spdx.PositiveIntegerRange{},
		spdx.IntegrityMethod{},
		spdx.PackageVerificationCode{},
		spdx.IndividualElement{},
		spdx.AnyLicenseInfo{},
		spdx.License{},
		spdx.ListedLicense{},
		spdx.CustomLicense{},
		spdx.LicenseExpression{},
		spdx.ConjunctiveLicenseSet{},
		spdx.DisjunctiveLicenseSet{},
		spdx.WithAdditionOperator{},
		spdx.LicenseAddition{},
		spdx.IndividualLicensingInfo{},
		spdx.SimpleLicensingText{},
		spdx.OrLaterOperator{},
		spdx.ListedLicenseException{},
		spdx.CustomLicenseAddition{},
		spdx.Vulnerability{},
		spdx.VulnAssessmentRelationship{},
		spdx.CvssV2VulnAssessmentRelationship{},
		spdx.CvssV3VulnAssessmentRelationship{},
		spdx.CvssV4VulnAssessmentRelationship{},
		spdx.EpssVulnAssessmentRelationship{},
		spdx.SsvcVulnAssessmentRelationship{},
		spdx.ExploitCatalogVulnAssessmentRelationship{},
		spdx.VexVulnAssessmentRelationship{},
		spdx.VexAffectedVulnAssessmentRelationship{},
		spdx.VexFixedVulnAssessmentRelationship{},
		spdx.VexNotAffectedVulnAssessmentRelationship{},
		spdx.VexUnderInvestigationVulnAssessmentRelationship{},
		spdx.AIPackage{},
		spdx.EnergyConsumption{},
		spdx.EnergyConsumptionDescription{},
		spdx.DatasetPackage{},
		spdx.Build{},
	}

	for _, typ := range requiredTypes {
		if !IsRegistered(typ) {
			t.Errorf("type %T is not registered in goTypeToJSONLDTypeString", typ)
		}
	}
}
