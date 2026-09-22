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
	"bytes"
	"encoding/json"
	"testing"
	"time"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func TestWriter_RoundTrip_Minimal(t *testing.T) {
	// Build a minimal SPDX document in memory.
	ci := spdx.NewCreationInfo([]spdx.Agent{
		{Element: spdx.NewElement("https://example.org/tool", "test-tool", spdx.CreationInfo{})},
	})
	ci.SpecVersion = "SPDX-3.0.1"
	ci.Created = time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)

	docElem := spdx.NewElement("https://example.org/doc1", "My SBOM", ci)
	spdxDoc := &spdx.SpdxDocument{
		ElementCollection: spdx.ElementCollection{
			Element: docElem,
		},
	}

	pkgElem := spdx.NewElement("https://example.org/pkg1", "my-package", ci)
	pkg := &spdx.Package{
		SoftwareArtifact: spdx.SoftwareArtifact{
			Artifact: spdx.Artifact{
				Element: pkgElem,
			},
		},
		PackageVersion: "1.0.0",
	}

	relElem := spdx.NewElement("https://example.org/rel1", "", ci)
	rel := &spdx.Relationship{
		Element:          relElem,
		From:             docElem,
		To:               []spdx.Element{pkgElem},
		RelationshipType: spdx.RelationshipTypeDescribes,
	}

	doc := &parse.Document{
		SpdxDocument:  spdxDoc,
		Packages:      []*spdx.Package{pkg},
		Relationships: []*spdx.Relationship{rel},
		Context:       []string{"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"},
	}

	// Serialize.
	var buf bytes.Buffer
	w := NewWriter()
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Parse the raw JSON to inspect structure.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshaling output: %v", err)
	}

	// Verify top-level keys.
	if raw["@context"] == nil {
		t.Error("missing @context")
	}
	graph, ok := raw["@graph"].([]interface{})
	if !ok {
		t.Fatalf("@graph is not an array, got %T", raw["@graph"])
	}
	if len(graph) != 4 { // SpdxDocument, Package, Relationship, CreationInfo
		t.Fatalf("expected 4 graph elements, got %d", len(graph))
	}

	// Build lookup by spdxId (or @id for blank nodes).
	byID := make(map[string]map[string]interface{})
	for _, item := range graph {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["spdxId"].(string)
		if id == "" {
			id, _ = m["@id"].(string)
		}
		byID[id] = m
	}

	// Verify each element has "type".
	for id, m := range byID {
		if m["type"] == nil || m["type"] == "" {
			t.Errorf("element %q missing type", id)
		}
	}

	// Verify SpdxDocument.
	docMap := byID["https://example.org/doc1"]
	if docMap["type"] != "SpdxDocument" {
		t.Errorf("doc type = %v, want SpdxDocument", docMap["type"])
	}

	// Verify Package.
	pkgMap := byID["https://example.org/pkg1"]
	if pkgMap["type"] != "software_Package" {
		t.Errorf("pkg type = %v, want software_Package", pkgMap["type"])
	}
	if pkgMap["software_packageVersion"] != "1.0.0" {
		t.Errorf("pkg version = %v, want 1.0.0", pkgMap["software_packageVersion"])
	}

	// Verify Relationship has string references for From and To.
	relMap := byID["https://example.org/rel1"]
	if relMap["type"] != "Relationship" {
		t.Errorf("rel type = %v, want Relationship", relMap["type"])
	}
	from, ok := relMap["from"].(string)
	if !ok || from != "https://example.org/doc1" {
		t.Errorf("rel.from = %v, want string ref", relMap["from"])
	}
	toSlice, ok := relMap["to"].([]interface{})
	if !ok || len(toSlice) != 1 {
		t.Fatalf("rel.to = %v, want [string]", relMap["to"])
	}
	if toSlice[0] != "https://example.org/pkg1" {
		t.Errorf("rel.to[0] = %v, want pkg id", toSlice[0])
	}

	// Verify CreationInfo is a shared blank node.
	ciMap := byID["_:creationinfo"]
	if ciMap["type"] != "CreationInfo" {
		t.Errorf("ci type = %v, want CreationInfo", ciMap["type"])
	}
	if ciMap["@id"] != "_:creationinfo" {
		t.Errorf("ci @id = %v", ciMap["@id"])
	}
	createdBy, ok := ciMap["createdBy"].([]interface{})
	if !ok || len(createdBy) != 1 {
		t.Fatalf("ci.createdBy = %v", ciMap["createdBy"])
	}
	if createdBy[0] != "https://example.org/tool" {
		t.Errorf("ci.createdBy[0] = %v, want tool id", createdBy[0])
	}

	// Verify regular elements reference the blank node.
	if docMap["creationInfo"] != "_:creationinfo" {
		t.Errorf("doc.creationInfo = %v, want _:creationinfo", docMap["creationInfo"])
	}
	if pkgMap["creationInfo"] != "_:creationinfo" {
		t.Errorf("pkg.creationInfo = %v, want _:creationinfo", pkgMap["creationInfo"])
	}
	if relMap["creationInfo"] != "_:creationinfo" {
		t.Errorf("rel.creationInfo = %v, want _:creationinfo", relMap["creationInfo"])
	}
}

func TestWriter_WithIndent(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})
	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
	}

	var buf bytes.Buffer
	w := NewWriter(WithIndent("  "))
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("\n  ")) {
		t.Error("expected indented output")
	}
	if len(output) == 0 {
		t.Error("output is empty")
	}
}

func TestWriter_PrettyPrint(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})
	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
	}

	// Compact output (no indent).
	var compact bytes.Buffer
	if err := NewWriter().Write(doc, &compact); err != nil {
		t.Fatalf("compact Write failed: %v", err)
	}

	// Pretty output.
	var pretty bytes.Buffer
	if err := NewWriter(WithIndent("\t")).Write(doc, &pretty); err != nil {
		t.Fatalf("pretty Write failed: %v", err)
	}

	// Pretty should be larger (contains whitespace).
	if pretty.Len() <= compact.Len() {
		t.Error("pretty output should be larger than compact")
	}

	// Both should parse successfully.
	var c, p map[string]interface{}
	if err := json.Unmarshal(compact.Bytes(), &c); err != nil {
		t.Errorf("compact unmarshal: %v", err)
	}
	if err := json.Unmarshal(pretty.Bytes(), &p); err != nil {
		t.Errorf("pretty unmarshal: %v", err)
	}
}

func TestWriter_File(t *testing.T) {
	tmpFile := t.TempDir() + "/test.spdx.json"

	ci := spdx.NewCreationInfo([]spdx.Agent{})
	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
	}

	w := NewWriter()
	if err := w.WriteFile(doc, tmpFile); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Read it back with parse.Reader.
	reader := parse.NewReader()
	parsed, err := reader.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if parsed.GetSpdxID() != "https://example.org/doc" {
		t.Errorf("round-trip spdxId = %q", parsed.GetSpdxID())
	}
	if parsed.GetName() != "doc" {
		t.Errorf("round-trip name = %q", parsed.GetName())
	}
}

// TestWriter_SecurityProfilePrefixes verifies that Security profile fields
// are prefixed with "security_" in the JSON-LD output.
func TestWriter_SecurityProfilePrefixes(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})

	// Build a Vulnerability element.
	vuln := &spdx.Vulnerability{
		Artifact: spdx.Artifact{
			Element: spdx.NewElement("https://example.org/vuln1", "CVE-2024-1234", ci),
		},
	}
	vuln.PublishedTime = time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	vuln.ModifiedTime = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	// Build a CVSS v3 assessment relationship.
	cvss3 := &spdx.CvssV3VulnAssessmentRelationship{
		VulnAssessmentRelationship: spdx.VulnAssessmentRelationship{
			Relationship: spdx.Relationship{
				Element:          spdx.NewElement("https://example.org/cvss3-1", "", ci),
				From:             spdx.NewElement("https://example.org/vuln1", "", ci),
				To:               []spdx.Element{spdx.NewElement("https://example.org/pkg1", "", ci)},
				RelationshipType: spdx.RelationshipTypeDescribes,
			},
			PublishedTime: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			ModifiedTime:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		Score:        7.5,
		Severity:     spdx.CvssSeverityTypeHigh,
		VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}

	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
		Vulnerabilities:       []*spdx.Vulnerability{vuln},
		CvssV3VulnAssessments: []*spdx.CvssV3VulnAssessmentRelationship{cvss3},
	}

	var buf bytes.Buffer
	w := NewWriter()
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph := raw["@graph"].([]interface{})

	byType := make(map[string]map[string]interface{})
	for _, item := range graph {
		m := item.(map[string]interface{})
		typ, _ := m["type"].(string)
		byType[typ] = m
	}

	// Verify Vulnerability fields are prefixed.
	vulnMap := byType["security_Vulnerability"]
	if vulnMap == nil {
		t.Fatal("missing security_Vulnerability in @graph")
	}
	if _, ok := vulnMap["security_publishedTime"]; !ok {
		t.Errorf("Vulnerability: missing security_publishedTime, got %v", vulnMap["publishedTime"])
	}
	if _, ok := vulnMap["security_modifiedTime"]; !ok {
		t.Errorf("Vulnerability: missing security_modifiedTime, got %v", vulnMap["modifiedTime"])
	}
	// Core fields must stay bare.
	if vulnMap["name"] != "CVE-2024-1234" {
		t.Errorf("Vulnerability: name = %v, want bare 'name'", vulnMap["name"])
	}

	// Verify CVSS v3 fields are prefixed.
	cvssMap := byType["security_CvssV3VulnAssessmentRelationship"]
	if cvssMap == nil {
		t.Fatal("missing security_CvssV3VulnAssessmentRelationship in @graph")
	}
	if _, ok := cvssMap["security_score"]; !ok {
		t.Errorf("CVSS3: missing security_score, got %v", cvssMap["score"])
	}
	if _, ok := cvssMap["security_severity"]; !ok {
		t.Errorf("CVSS3: missing security_severity, got %v", cvssMap["severity"])
	}
	if _, ok := cvssMap["security_vectorString"]; !ok {
		t.Errorf("CVSS3: missing security_vectorString, got %v", cvssMap["vectorString"])
	}
	// Relationship Core fields must stay bare.
	if _, ok := cvssMap["relationshipType"]; !ok {
		t.Errorf("CVSS3: missing bare relationshipType")
	}
}

// TestWriter_AIProfilePrefixes verifies that AI profile fields are prefixed
// with "ai_" in the JSON-LD output.
func TestWriter_AIProfilePrefixes(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})

	aiPkg := &spdx.AIPackage{
		Package: spdx.Package{
			SoftwareArtifact: spdx.SoftwareArtifact{
				Artifact: spdx.Artifact{
					Element: spdx.NewElement("https://example.org/ai1", "Medical-AI-Model", ci),
				},
			},
			PackageVersion: "2.0.0",
		},
		AutonomyType:                spdx.PresenceTypeYes,
		Domain:                      []string{"medical"},
		InformationAboutApplication: "Diagnostic imaging",
	}

	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
		AiPackages: []*spdx.AIPackage{aiPkg},
	}

	var buf bytes.Buffer
	w := NewWriter()
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph := raw["@graph"].([]interface{})

	var aiMap map[string]interface{}
	for _, item := range graph {
		m := item.(map[string]interface{})
		if m["type"] == "ai_AIPackage" {
			aiMap = m
			break
		}
	}
	if aiMap == nil {
		t.Fatal("missing ai_AIPackage in @graph")
	}

	if _, ok := aiMap["ai_autonomyType"]; !ok {
		t.Errorf("missing ai_autonomyType, got %v", aiMap["autonomyType"])
	}
	if _, ok := aiMap["ai_domain"]; !ok {
		t.Errorf("missing ai_domain, got %v", aiMap["domain"])
	}
	if _, ok := aiMap["ai_informationAboutApplication"]; !ok {
		t.Errorf("missing ai_informationAboutApplication, got %v", aiMap["informationAboutApplication"])
	}
	// Software profile fields on the embedded Package should also be prefixed.
	if _, ok := aiMap["software_packageVersion"]; !ok {
		t.Errorf("missing software_packageVersion, got %v", aiMap["packageVersion"])
	}
	// Core fields stay bare.
	if aiMap["name"] != "Medical-AI-Model" {
		t.Errorf("name = %v, want bare 'name'", aiMap["name"])
	}
}

// TestWriter_DatasetProfilePrefixes verifies that Dataset profile fields are
// prefixed with "dataset_" in the JSON-LD output.
func TestWriter_DatasetProfilePrefixes(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})

	dsPkg := &spdx.DatasetPackage{
		Package: spdx.Package{
			SoftwareArtifact: spdx.SoftwareArtifact{
				Artifact: spdx.Artifact{
					Element: spdx.NewElement("https://example.org/ds1", "OpenImages", ci),
				},
			},
			PackageVersion: "v6",
		},
		DatasetType:            []spdx.DatasetType{spdx.DatasetTypeImage},
		DatasetSize:            9000000,
		DataCollectionProcess:  "Web scraping with consent",
		IntendedUse:            "Computer vision research",
	}

	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
		DatasetPackages: []*spdx.DatasetPackage{dsPkg},
	}

	var buf bytes.Buffer
	w := NewWriter()
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph := raw["@graph"].([]interface{})

	var dsMap map[string]interface{}
	for _, item := range graph {
		m := item.(map[string]interface{})
		if m["type"] == "dataset_Dataset" {
			dsMap = m
			break
		}
	}
	if dsMap == nil {
		t.Fatal("missing dataset_Dataset in @graph")
	}

	if _, ok := dsMap["dataset_datasetType"]; !ok {
		t.Errorf("missing dataset_datasetType, got %v", dsMap["datasetType"])
	}
	if _, ok := dsMap["dataset_datasetSize"]; !ok {
		t.Errorf("missing dataset_datasetSize, got %v", dsMap["datasetSize"])
	}
	if _, ok := dsMap["dataset_dataCollectionProcess"]; !ok {
		t.Errorf("missing dataset_dataCollectionProcess, got %v", dsMap["dataCollectionProcess"])
	}
	if _, ok := dsMap["dataset_intendedUse"]; !ok {
		t.Errorf("missing dataset_intendedUse, got %v", dsMap["intendedUse"])
	}
	// Core field stays bare.
	if dsMap["name"] != "OpenImages" {
		t.Errorf("name = %v, want bare 'name'", dsMap["name"])
	}
}

// TestWriter_BuildProfilePrefixes verifies that Build profile fields are
// prefixed with "build_" in the JSON-LD output.
func TestWriter_BuildProfilePrefixes(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})

	build := &spdx.Build{
		Element: spdx.NewElement("https://example.org/build1", "CI-Build-42", ci),
		BuildType:              "https://github.com/example/actions",
		BuildId:                "run-12345",
		ConfigSourceEntrypoint: []string{".github/workflows/build.yml"},
		BuildStartTime:         time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
	}

	doc := &parse.Document{
		SpdxDocument: &spdx.SpdxDocument{
			ElementCollection: spdx.ElementCollection{
				Element: spdx.NewElement("https://example.org/doc", "doc", ci),
			},
		},
		Builds: []*spdx.Build{build},
	}

	var buf bytes.Buffer
	w := NewWriter()
	if err := w.Write(doc, &buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	graph := raw["@graph"].([]interface{})

	var buildMap map[string]interface{}
	for _, item := range graph {
		m := item.(map[string]interface{})
		if m["type"] == "build_Build" {
			buildMap = m
			break
		}
	}
	if buildMap == nil {
		t.Fatal("missing build_Build in @graph")
	}

	if _, ok := buildMap["build_buildType"]; !ok {
		t.Errorf("missing build_buildType, got %v", buildMap["buildType"])
	}
	if _, ok := buildMap["build_buildId"]; !ok {
		t.Errorf("missing build_buildId, got %v", buildMap["buildId"])
	}
	if _, ok := buildMap["build_configSourceEntrypoint"]; !ok {
		t.Errorf("missing build_configSourceEntrypoint, got %v", buildMap["configSourceEntrypoint"])
	}
	if _, ok := buildMap["build_buildStartTime"]; !ok {
		t.Errorf("missing build_buildStartTime, got %v", buildMap["buildStartTime"])
	}
	// Core field stays bare.
	if buildMap["name"] != "CI-Build-42" {
		t.Errorf("name = %v, want bare 'name'", buildMap["name"])
	}
}

// TestWriter_RoundTrip_AllProfiles writes an SPDX document containing elements
// from every profile, reads it back with parse.Reader, and verifies that
// prefixed fields survive the round trip.
func TestWriter_RoundTrip_AllProfiles(t *testing.T) {
	ci := spdx.NewCreationInfo([]spdx.Agent{})
	ci.SpecVersion = "SPDX-3.0.1"

	// Build a document with elements from every profile.
	spdxDoc := &spdx.SpdxDocument{
		ElementCollection: spdx.ElementCollection{
			Element: spdx.NewElement("https://example.org/doc", "Test Doc", ci),
		},
	}

	pkg := &spdx.Package{
		SoftwareArtifact: spdx.SoftwareArtifact{
			Artifact: spdx.Artifact{
				Element: spdx.NewElement("https://example.org/pkg1", "MyPkg", ci),
			},
		},
		PackageVersion: "1.0.0",
	}

	vuln := &spdx.Vulnerability{
		Artifact: spdx.Artifact{
			Element: spdx.NewElement("https://example.org/vuln1", "CVE-2024-1", ci),
		},
	}
	vuln.PublishedTime = time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)

	cvss3 := &spdx.CvssV3VulnAssessmentRelationship{
		VulnAssessmentRelationship: spdx.VulnAssessmentRelationship{
			Relationship: spdx.Relationship{
				Element:          spdx.NewElement("https://example.org/cvss3-1", "", ci),
				From:             spdx.NewElement("https://example.org/vuln1", "", ci),
				To:               []spdx.Element{spdx.NewElement("https://example.org/pkg1", "", ci)},
				RelationshipType: spdx.RelationshipTypeDescribes,
			},
			PublishedTime: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		Score:        7.5,
		Severity:     spdx.CvssSeverityTypeHigh,
		VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}

	aiPkg := &spdx.AIPackage{
		Package: spdx.Package{
			SoftwareArtifact: spdx.SoftwareArtifact{
				Artifact: spdx.Artifact{
					Element: spdx.NewElement("https://example.org/ai1", "AI-Model", ci),
				},
			},
			PackageVersion: "2.0.0",
		},
		AutonomyType:                spdx.PresenceTypeYes,
		Domain:                      []string{"medical"},
		InformationAboutApplication: "Diagnostic imaging",
	}

	dsPkg := &spdx.DatasetPackage{
		Package: spdx.Package{
			SoftwareArtifact: spdx.SoftwareArtifact{
				Artifact: spdx.Artifact{
					Element: spdx.NewElement("https://example.org/ds1", "OpenImages", ci),
				},
			},
			PackageVersion: "v6",
		},
		DatasetType:            []spdx.DatasetType{spdx.DatasetTypeImage},
		DatasetSize:            9000000,
		DataCollectionProcess:  "Web scraping with consent",
		IntendedUse:            "Computer vision research",
	}

	build := &spdx.Build{
		Element:                spdx.NewElement("https://example.org/build1", "CI-Build-42", ci),
		BuildType:              "https://github.com/example/actions",
		BuildId:                "run-12345",
		ConfigSourceEntrypoint: []string{".github/workflows/build.yml"},
		BuildStartTime:         time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
	}

	doc := &parse.Document{
		SpdxDocument:              spdxDoc,
		Packages:                  []*spdx.Package{pkg},
		Vulnerabilities:           []*spdx.Vulnerability{vuln},
		CvssV3VulnAssessments:     []*spdx.CvssV3VulnAssessmentRelationship{cvss3},
		AiPackages:                []*spdx.AIPackage{aiPkg},
		DatasetPackages:           []*spdx.DatasetPackage{dsPkg},
		Builds:                    []*spdx.Build{build},
		Context:                   []string{"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"},
	}

	// Write to temp file.
	tmpFile := t.TempDir() + "/roundtrip.spdx.json"
	w := NewWriter()
	if err := w.WriteFile(doc, tmpFile); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Read back with parse.Reader.
	reader := parse.NewReader()
	parsed, err := reader.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Verify Software profile.
	if len(parsed.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(parsed.Packages))
	}
	if parsed.Packages[0].PackageVersion != "1.0.0" {
		t.Errorf("package version round-trip: got %q", parsed.Packages[0].PackageVersion)
	}

	// Verify Security profile.
	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(parsed.Vulnerabilities))
	}
	v := parsed.Vulnerabilities[0]
	if !v.PublishedTime.Equal(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("vuln publishedTime round-trip: got %v", v.PublishedTime)
	}

	if len(parsed.CvssV3VulnAssessments) != 1 {
		t.Fatalf("expected 1 CVSS3 assessment, got %d", len(parsed.CvssV3VulnAssessments))
	}
	c3 := parsed.CvssV3VulnAssessments[0]
	if c3.Score != 7.5 {
		t.Errorf("cvss3 score round-trip: got %v", c3.Score)
	}
	if c3.Severity != spdx.CvssSeverityTypeHigh {
		t.Errorf("cvss3 severity round-trip: got %v", c3.Severity)
	}
	if c3.VectorString != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("cvss3 vectorString round-trip: got %q", c3.VectorString)
	}

	// Verify AI profile.
	if len(parsed.AiPackages) != 1 {
		t.Fatalf("expected 1 AI package, got %d", len(parsed.AiPackages))
	}
	ai := parsed.AiPackages[0]
	if ai.PackageVersion != "2.0.0" {
		t.Errorf("ai packageVersion round-trip: got %q", ai.PackageVersion)
	}
	if ai.AutonomyType != spdx.PresenceTypeYes {
		t.Errorf("ai autonomyType round-trip: got %v", ai.AutonomyType)
	}
	if len(ai.Domain) != 1 || ai.Domain[0] != "medical" {
		t.Errorf("ai domain round-trip: got %v", ai.Domain)
	}
	if ai.InformationAboutApplication != "Diagnostic imaging" {
		t.Errorf("ai informationAboutApplication round-trip: got %q", ai.InformationAboutApplication)
	}

	// Verify Dataset profile.
	if len(parsed.DatasetPackages) != 1 {
		t.Fatalf("expected 1 dataset package, got %d", len(parsed.DatasetPackages))
	}
	ds := parsed.DatasetPackages[0]
	if ds.PackageVersion != "v6" {
		t.Errorf("dataset packageVersion round-trip: got %q", ds.PackageVersion)
	}
	if len(ds.DatasetType) != 1 || ds.DatasetType[0] != spdx.DatasetTypeImage {
		t.Errorf("dataset datasetType round-trip: got %v", ds.DatasetType)
	}
	if ds.DatasetSize != 9000000 {
		t.Errorf("dataset datasetSize round-trip: got %d", ds.DatasetSize)
	}
	if ds.DataCollectionProcess != "Web scraping with consent" {
		t.Errorf("dataset dataCollectionProcess round-trip: got %q", ds.DataCollectionProcess)
	}
	if ds.IntendedUse != "Computer vision research" {
		t.Errorf("dataset intendedUse round-trip: got %q", ds.IntendedUse)
	}

	// Verify Build profile.
	if len(parsed.Builds) != 1 {
		t.Fatalf("expected 1 build, got %d", len(parsed.Builds))
	}
	b := parsed.Builds[0]
	if b.BuildType != "https://github.com/example/actions" {
		t.Errorf("build buildType round-trip: got %q", b.BuildType)
	}
	if b.BuildId != "run-12345" {
		t.Errorf("build buildId round-trip: got %q", b.BuildId)
	}
	if len(b.ConfigSourceEntrypoint) != 1 || b.ConfigSourceEntrypoint[0] != ".github/workflows/build.yml" {
		t.Errorf("build configSourceEntrypoint round-trip: got %v", b.ConfigSourceEntrypoint)
	}
	if !b.BuildStartTime.Equal(time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("build buildStartTime round-trip: got %v", b.BuildStartTime)
	}
}
