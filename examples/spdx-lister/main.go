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

// spdx-lister is an example program that demonstrates the use of the parse package
// to read and display comprehensive information from SPDX 3.0.1 documents.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func main() {
	showFiles := flag.Bool("show-files", false, "Show detailed file information")
	agentType := flag.String("filter-agent", "", "Filter by agent type: organization, person, or software")
	flag.Parse()

	doc, err := loadDocument(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *agentType != "" {
		printAgentFilteredInfo(doc, *agentType)
	} else {
		printDocumentInfo(doc, *showFiles)
	}
}

func loadDocument(args []string) (*parse.Document, error) {
	reader := parse.NewReader()
	if len(args) == 0 {
		return reader.FromReader(os.Stdin)
	}
	return reader.ReadFile(args[0])
}

// =============================================================================
// Main Document Printing
// =============================================================================

func printDocumentInfo(doc *parse.Document, showFiles bool) {
	fmt.Println("=== SPDX Document Information ===")
	fmt.Println()

	printDocumentMetadata(doc)
	printCreationInfo(doc)
	printSummary(doc)
	printPackages(doc)
	if showFiles {
		printFiles(doc)
	}
	printRelationshipStats(doc)
	printAgents(doc)
	printTools(doc)
	printLicensingInfos(doc)
}

func printDocumentMetadata(doc *parse.Document) {
	if doc.SpdxDocument == nil {
		return
	}

	fmt.Println("Document:")
	fmt.Printf("  Name:        %s\n", doc.SpdxDocument.Name)
	fmt.Printf("  SPDX ID:     %s\n", doc.SpdxDocument.SpdxID)

	if doc.SpdxDocument.DataLicense != nil {
		license := resolveDataLicense(doc)
		fmt.Printf("  Data License: %s\n", license)
	}

	if len(doc.SpdxDocument.ProfileConformance) > 0 {
		fmt.Printf("  Profiles:    %v\n", doc.SpdxDocument.ProfileConformance)
	}

	if len(doc.SpdxDocument.NamespaceMap) > 0 {
		fmt.Println("  Namespace Map:")
		for _, ns := range doc.SpdxDocument.NamespaceMap {
			fmt.Printf("    %s: %s\n", ns.Prefix, ns.Namespace)
		}
	}
	fmt.Println()
}

func resolveDataLicense(doc *parse.Document) string {
	dl := doc.SpdxDocument.DataLicense
	if lic := doc.GetAnyLicenseInfoByID(dl.SpdxID); lic != nil && lic.Name != "" {
		return lic.Name
	}
	if dl.Name != "" {
		return dl.Name
	}
	return dl.SpdxID
}

func printCreationInfo(doc *parse.Document) {
	if doc.CreationInfo == nil {
		return
	}

	fmt.Println("Creation Info:")
	fmt.Printf("  Spec Version: %s\n", doc.CreationInfo.SpecVersion)

	if !doc.CreationInfo.Created.IsZero() {
		fmt.Printf("  Created:      %s\n", doc.CreationInfo.Created.Format("2006-01-02 15:04:05"))
	}

	if len(doc.CreationInfo.CreatedBy) > 0 {
		names := resolveAgentNames(doc, doc.CreationInfo.CreatedBy)
		fmt.Printf("  Created By:   %s\n", strings.Join(names, ", "))
	}

	if len(doc.CreationInfo.CreatedUsing) > 0 {
		names := resolveToolNames(doc, doc.CreationInfo.CreatedUsing)
		fmt.Printf("  Created Using: %s\n", strings.Join(names, ", "))
	}
	fmt.Println()
}

func printSummary(doc *parse.Document) {
	fmt.Println("Summary:")
	fmt.Printf("  Packages:      %d\n", len(doc.Packages))
	fmt.Printf("  Files:         %d\n", len(doc.Files))
	fmt.Printf("  Snippets:      %d\n", len(doc.Snippets))
	fmt.Printf("  Relationships: %d\n", len(doc.Relationships))
	fmt.Printf("  Annotations:   %d\n", len(doc.Annotations))
	fmt.Printf("  External Maps: %d\n", len(doc.ExternalMaps))
	fmt.Printf("  Organizations: %d\n", len(doc.Organizations))
	fmt.Printf("  Persons:       %d\n", len(doc.Persons))
	fmt.Printf("  SoftwareAgents:%d\n", len(doc.SoftwareAgents))
	fmt.Printf("  Tools:         %d\n", len(doc.Tools))
	fmt.Printf("  Licenses:      %d\n", countLicenses(doc))
	fmt.Println()
}

func countLicenses(doc *parse.Document) int {
	return len(doc.AnyLicenseInfos) +
		len(doc.ConjunctiveLicenseSets) +
		len(doc.CustomLicenses) +
		len(doc.CustomLicenseAdditions) +
		len(doc.DisjunctiveLicenseSets) +
		len(doc.IndividualLicensingInfos) +
		len(doc.ListedLicenses) +
		len(doc.ListedLicenseExceptions) +
		len(doc.LicenseExpressions) +
		len(doc.OrLaterOperators) +
		len(doc.SimpleLicensingTexts) +
		len(doc.WithAdditionOperators)
}

// =============================================================================
// Package Printing
// =============================================================================

func printPackages(doc *parse.Document) {
	if len(doc.Packages) == 0 {
		return
	}

	fmt.Println("Packages:")
	for _, pkg := range doc.Packages {
		printPackage(doc, pkg)
	}
	fmt.Println()
}

func printPackage(doc *parse.Document, pkg *spdx.Package) {
	fmt.Printf("  - %s\n", pkg.Name)
	printPackageBasicInfo(pkg)
	printPackageAgents(doc, pkg)
	printPackageDependencies(doc, pkg)
	printElementLicenses(doc, pkg.SpdxID, "      ")
	printElementSecurityInfo(doc, pkg.SpdxID, "      ")
	printElementBuildInfo(doc, pkg.SpdxID, "      ")
	printElementAnnotations(doc, pkg.SpdxID, "      ")
	printPackageContainment(doc, pkg)
}

func printPackageBasicInfo(pkg *spdx.Package) {
	if pkg.PackageVersion != "" {
		fmt.Printf("      Version: %s\n", pkg.PackageVersion)
	}
	if pkg.PackageUrl != "" {
		fmt.Printf("      PURL:    %s\n", pkg.PackageUrl)
	}
	if pkg.DownloadLocation != "" {
		fmt.Printf("      Download: %s\n", pkg.DownloadLocation)
	}
	if pkg.PrimaryPurpose != "" {
		fmt.Printf("      Purpose: %s\n", pkg.PrimaryPurpose)
	}
}

func printPackageAgents(doc *parse.Document, pkg *spdx.Package) {
	if len(pkg.CreationInfo.CreatedBy) > 0 {
		names := resolveAgentNames(doc, pkg.CreationInfo.CreatedBy)
		fmt.Printf("      Created By: %s\n", strings.Join(names, ", "))
	}

	if len(pkg.OriginatedBy) > 0 {
		names := resolveAgentNames(doc, pkg.OriginatedBy)
		fmt.Printf("      Originated By: %s\n", strings.Join(names, ", "))
	}

	if pkg.SuppliedBy != nil {
		name := resolveAgentNameWithType(doc, pkg.SuppliedBy)
		fmt.Printf("      Supplied By: %s\n", name)
	}
}

func printPackageDependencies(doc *parse.Document, pkg *spdx.Package) {
	deps := doc.GetDependenciesFor(pkg.SpdxID)
	if len(deps) == 0 {
		return
	}

	fmt.Printf("      Dependencies: %d\n", len(deps))
	for _, dep := range deps {
		if dep.PackageVersion != "" {
			fmt.Printf("        - %s@%s\n", dep.Name, dep.PackageVersion)
		} else {
			fmt.Printf("        - %s\n", dep.Name)
		}
	}
}

func printPackageContainment(doc *parse.Document, pkg *spdx.Package) {
	containment := doc.GetContainmentFor(pkg.SpdxID)
	if len(containment.Files) == 0 && len(containment.Packages) == 0 {
		return
	}

	total := len(containment.Files) + len(containment.Packages)
	fmt.Printf("      Contains: %d", total)
	if containment.Completeness != "" {
		fmt.Printf(" (%s)", containment.Completeness)
	}
	fmt.Println()

	for _, file := range containment.Files {
		purpose := ""
		if file.PrimaryPurpose != "" {
			purpose = fmt.Sprintf(" [%s]", file.PrimaryPurpose)
		}
		fmt.Printf("        - %s%s\n", file.Name, purpose)
	}

	for _, subPkg := range containment.Packages {
		version := ""
		if subPkg.PackageVersion != "" {
			version = "@" + subPkg.PackageVersion
		}
		fmt.Printf("        - %s%s\n", subPkg.Name, version)
	}
}

// =============================================================================
// File Printing
// =============================================================================

func printFiles(doc *parse.Document) {
	if len(doc.Files) == 0 {
		return
	}

	fmt.Println("Files:")
	for _, file := range doc.Files {
		printFile(doc, file)
	}
	fmt.Println()
}

func printFile(doc *parse.Document, file *spdx.File) {
	fmt.Printf("  - %s\n", file.Name)

	if file.ContentType != "" {
		fmt.Printf("      Content Type: %s\n", file.ContentType)
	}
	if file.PrimaryPurpose != "" {
		fmt.Printf("      Purpose: %s\n", file.PrimaryPurpose)
	}

	printElementLicenses(doc, file.SpdxID, "      ")

	if file.CopyrightText != "" && file.CopyrightText != "NOASSERTION" {
		fmt.Printf("      Copyright: %s\n", file.CopyrightText)
	}

	printElementBuildInfo(doc, file.SpdxID, "      ")
	printElementSecurityInfo(doc, file.SpdxID, "      ")
	printElementAnnotations(doc, file.SpdxID, "      ")
}

// =============================================================================
// Shared Element Info Printing
// =============================================================================

func printElementLicenses(doc *parse.Document, spdxID, indent string) {
	licInfo := doc.GetLicensesFor(spdxID)
	if len(licInfo.ConcludedLicenses) == 0 && len(licInfo.DeclaredLicenses) == 0 {
		return
	}

	fmt.Println(indent + "Licenses:")
	if len(licInfo.ConcludedLicenses) > 0 {
		names := getLicenseNames(licInfo.ConcludedLicenses)
		fmt.Printf("%s  Concluded: %s\n", indent, strings.Join(names, ", "))
	}
	if len(licInfo.DeclaredLicenses) > 0 {
		names := getLicenseNames(licInfo.DeclaredLicenses)
		fmt.Printf("%s  Declared: %s\n", indent, strings.Join(names, ", "))
	}
}

func printElementSecurityInfo(doc *parse.Document, spdxID, indent string) {
	secInfo := doc.GetSecurityInfoFor(spdxID)
	if len(secInfo.Relationships) == 0 {
		return
	}

	fmt.Printf("%sSecurity: %d relationship(s)\n", indent, len(secInfo.Relationships))
	for _, rel := range secInfo.Relationships {
		fmt.Printf("%s  - %s\n", indent, rel.RelationshipType)
	}
}

func printElementBuildInfo(doc *parse.Document, spdxID, indent string) {
	buildInfo := doc.GetBuildInfoFor(spdxID)
	if len(buildInfo.Relationships) == 0 {
		return
	}

	fmt.Printf("%sBuild: %d relationship(s)\n", indent, len(buildInfo.Relationships))
	for _, rel := range buildInfo.Relationships {
		fmt.Printf("%s  - %s\n", indent, rel.RelationshipType)
	}
}

func printElementAnnotations(doc *parse.Document, spdxID, indent string) {
	annotations := doc.GetAnnotationsFor(spdxID)
	if len(annotations) == 0 {
		return
	}

	fmt.Printf("%sAnnotations: %d\n", indent, len(annotations))
	for _, ann := range annotations {
		fmt.Printf("%s  - [%s] %s\n", indent, ann.AnnotationType, ann.Statement)
	}
}

// =============================================================================
// Other Sections
// =============================================================================

func printRelationshipStats(doc *parse.Document) {
	if len(doc.Relationships) == 0 {
		return
	}

	fmt.Println("Relationship Types:")
	stats := make(map[string]int)
	for _, rel := range doc.Relationships {
		stats[string(rel.RelationshipType)]++
	}
	for relType, count := range stats {
		fmt.Printf("  %s: %d\n", relType, count)
	}
	fmt.Println()
}

func printAgents(doc *parse.Document) {
	if len(doc.Organizations) == 0 && len(doc.Persons) == 0 && len(doc.SoftwareAgents) == 0 {
		return
	}

	fmt.Println("Agents:")
	for _, org := range doc.Organizations {
		fmt.Printf("  - [Organization] %s\n", org.Name)
	}
	for _, person := range doc.Persons {
		fmt.Printf("  - [Person] %s\n", person.Name)
	}
	for _, sa := range doc.SoftwareAgents {
		fmt.Printf("  - [SoftwareAgent] %s\n", sa.Name)
	}
	fmt.Println()
}

func printTools(doc *parse.Document) {
	if len(doc.Tools) == 0 {
		return
	}

	fmt.Println("Tools:")
	for _, tool := range doc.Tools {
		fmt.Printf("  - %s\n", tool.Name)
	}
	fmt.Println()
}

func printLicensingInfos(doc *parse.Document) {
	if len(doc.IndividualLicensingInfos) == 0 {
		return
	}

	fmt.Println("Individual Licensing Infos:")
	for _, ili := range doc.IndividualLicensingInfos {
		fmt.Printf("  - %s\n", ili.Name)
	}
	fmt.Println()
}

// =============================================================================
// Agent Filtered View
// =============================================================================

func printAgentFilteredInfo(doc *parse.Document, agentType string) {
	fmt.Printf("=== Agent Filter: %s ===\n", agentType)
	fmt.Println()

	agentIDs, agents := collectAgentsByType(doc, agentType)
	if agentIDs == nil {
		fmt.Fprintf(os.Stderr, "Invalid agent type: %s. Use 'organization', 'person', or 'software'\n", agentType)
		os.Exit(1)
	}

	if len(agentIDs) == 0 {
		fmt.Printf("No agents of type '%s' found in the document.\n", agentType)
		return
	}

	printAgentList(agents, agentType)
	printAgentAssociations(doc, agentIDs, agentType)
}

func collectAgentsByType(doc *parse.Document, agentType string) ([]string, []interface{}) {
	var agentIDs []string
	var agents []interface{}

	switch agentType {
	case "organization":
		for _, org := range doc.Organizations {
			agentIDs = append(agentIDs, org.SpdxID)
			agents = append(agents, org)
		}
	case "person":
		for _, person := range doc.Persons {
			agentIDs = append(agentIDs, person.SpdxID)
			agents = append(agents, person)
		}
	case "software":
		for _, sa := range doc.SoftwareAgents {
			agentIDs = append(agentIDs, sa.SpdxID)
			agents = append(agents, sa)
		}
	default:
		return nil, nil
	}

	return agentIDs, agents
}

func printAgentList(agents []interface{}, agentType string) {
	fmt.Printf("Found %d %s agent(s):\n", len(agents), agentType)
	for _, agent := range agents {
		switch a := agent.(type) {
		case *spdx.Organization:
			fmt.Printf("  - %s (ID: %s)\n", a.Name, a.SpdxID)
		case *spdx.Person:
			fmt.Printf("  - %s (ID: %s)\n", a.Name, a.SpdxID)
		case *spdx.SoftwareAgent:
			fmt.Printf("  - %s (ID: %s)\n", a.Name, a.SpdxID)
		}
	}
	fmt.Println()
}

func printAgentAssociations(doc *parse.Document, agentIDs []string, agentType string) {
	fmt.Println("Associated Elements:")
	fmt.Println()

	for _, agentID := range agentIDs {
		agentName := getAgentNameByType(doc, agentID, agentType)
		fmt.Printf("Agent: %s (ID: %s)\n", agentName, agentID)

		printAgentDocumentCreation(doc, agentID)
		printAgentCreatedElements(doc, agentID)
		printAgentRelationships(doc, agentID)
		printAgentAnnotations(doc, agentID)
		printAgentPackageAssociations(doc, agentID)

		fmt.Println()
	}
}

func printAgentDocumentCreation(doc *parse.Document, agentID string) {
	if doc.CreationInfo == nil {
		return
	}

	for _, creatorRef := range doc.CreationInfo.CreatedBy {
		if creatorRef.SpdxID == agentID {
			fmt.Printf("  - Created Document: %s\n", getElementInfo(doc, doc.SpdxDocument.SpdxID))
			break
		}
	}
}

func printAgentCreatedElements(doc *parse.Document, agentID string) {
	elements := findElementsCreatedByAgent(doc, agentID)
	if len(elements) == 0 {
		return
	}

	fmt.Println("  - Created Elements:")
	for _, elemID := range elements {
		fmt.Printf("    - %s\n", getElementInfo(doc, elemID))
	}
}

func printAgentRelationships(doc *parse.Document, agentID string) {
	relationshipTypes := make(map[string][]string)

	for _, rel := range doc.Relationships {
		if rel.From.SpdxID == agentID {
			for _, to := range rel.To {
				key := string(rel.RelationshipType)
				relationshipTypes[key] = append(relationshipTypes[key], to.SpdxID)
			}
		}
		for _, to := range rel.To {
			if to.SpdxID == agentID {
				key := "(reverse) " + string(rel.RelationshipType)
				relationshipTypes[key] = append(relationshipTypes[key], rel.From.SpdxID)
			}
		}
	}

	if len(relationshipTypes) == 0 {
		return
	}

	fmt.Println("  - Involved in Relationships:")
	for relType, elements := range relationshipTypes {
		fmt.Printf("    %s:\n", relType)
		for _, elemID := range elements {
			fmt.Printf("      - %s\n", getElementInfo(doc, elemID))
		}
	}
}

func printAgentAnnotations(doc *parse.Document, agentID string) {
	var annotatedElements []string
	for _, ann := range doc.Annotations {
		for _, creator := range ann.CreationInfo.CreatedBy {
			if creator.SpdxID == agentID {
				annotatedElements = append(annotatedElements, ann.Subject.SpdxID)
				break
			}
		}
	}

	if len(annotatedElements) == 0 {
		return
	}

	fmt.Println("  - Authored Annotations:")
	for _, elemID := range annotatedElements {
		fmt.Printf("    - Annotated: %s\n", getElementInfo(doc, elemID))
	}
}

func printAgentPackageAssociations(doc *parse.Document, agentID string) {
	pkgs := findPackagesByAgent(doc, agentID)
	if len(pkgs) == 0 {
		return
	}

	fmt.Println("  - Associated with Packages:")
	for _, pkg := range pkgs {
		fmt.Printf("    - %s\n", getElementInfo(doc, pkg.SpdxID))
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func resolveAgentNames(doc *parse.Document, agents []spdx.Agent) []string {
	names := make([]string, 0, len(agents))
	for _, agent := range agents {
		names = append(names, resolveAgentNameWithType(doc, &agent))
	}
	return names
}

func resolveAgentNameWithType(doc *parse.Document, agent *spdx.Agent) string {
	name := resolveAgentName(doc, agent)
	agentType := doc.GetAgentTypeByID(agent.SpdxID)
	if agentType != parse.AgentTypeUnknown {
		return fmt.Sprintf("%s [%s]", name, agentType)
	}
	return name
}

func resolveAgentName(doc *parse.Document, agent *spdx.Agent) string {
	if resolved := doc.GetAgentByID(agent.SpdxID); resolved != nil && resolved.Name != "" {
		return resolved.Name
	}
	if agent.Name != "" {
		return agent.Name
	}
	return agent.SpdxID
}

func resolveToolNames(doc *parse.Document, tools []spdx.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		if resolved := doc.GetToolByID(tool.SpdxID); resolved != nil && resolved.Name != "" {
			names = append(names, resolved.Name)
		} else if tool.Name != "" {
			names = append(names, tool.Name)
		} else {
			names = append(names, tool.SpdxID)
		}
	}
	return names
}

func getLicenseNames(licenses []*spdx.AnyLicenseInfo) []string {
	names := make([]string, 0, len(licenses))
	for _, lic := range licenses {
		names = append(names, lic.Name)
	}
	return names
}

func findElementsCreatedByAgent(doc *parse.Document, agentID string) []string {
	var elementIDs []string

	isCreatedBy := func(ci *spdx.CreationInfo) bool {
		if ci == nil {
			return false
		}
		for _, creator := range ci.CreatedBy {
			if creator.SpdxID == agentID {
				return true
			}
		}
		return false
	}

	for _, pkg := range doc.Packages {
		if isCreatedBy(&pkg.CreationInfo) {
			elementIDs = append(elementIDs, pkg.SpdxID)
		}
	}
	for _, file := range doc.Files {
		if isCreatedBy(&file.CreationInfo) {
			elementIDs = append(elementIDs, file.SpdxID)
		}
	}
	for _, snippet := range doc.Snippets {
		if isCreatedBy(&snippet.CreationInfo) {
			elementIDs = append(elementIDs, snippet.SpdxID)
		}
	}
	for _, rel := range doc.Relationships {
		if isCreatedBy(&rel.CreationInfo) {
			elementIDs = append(elementIDs, rel.SpdxID)
		}
	}
	for _, tool := range doc.Tools {
		if isCreatedBy(&tool.CreationInfo) {
			elementIDs = append(elementIDs, tool.SpdxID)
		}
	}
	for _, ili := range doc.IndividualLicensingInfos {
		if isCreatedBy(&ili.CreationInfo) {
			elementIDs = append(elementIDs, ili.SpdxID)
		}
	}

	return elementIDs
}

func findPackagesByAgent(doc *parse.Document, agentID string) []*spdx.Package {
	var foundPackages []*spdx.Package
	processed := make(map[string]bool)

	for _, pkg := range doc.Packages {
		for _, originator := range pkg.OriginatedBy {
			if originator.SpdxID == agentID && !processed[pkg.SpdxID] {
				foundPackages = append(foundPackages, pkg)
				processed[pkg.SpdxID] = true
				break
			}
		}

		if pkg.SuppliedBy != nil && pkg.SuppliedBy.SpdxID == agentID && !processed[pkg.SpdxID] {
			foundPackages = append(foundPackages, pkg)
			processed[pkg.SpdxID] = true
		}
	}

	return foundPackages
}

func getAgentNameByType(doc *parse.Document, agentID, agentType string) string {
	switch agentType {
	case "organization":
		for _, org := range doc.Organizations {
			if org.SpdxID == agentID {
				return org.Name
			}
		}
	case "person":
		for _, person := range doc.Persons {
			if person.SpdxID == agentID {
				return person.Name
			}
		}
	case "software":
		for _, sa := range doc.SoftwareAgents {
			if sa.SpdxID == agentID {
				return sa.Name
			}
		}
	}
	return agentID
}

func getElementInfo(doc *parse.Document, elemID string) string {
	if pkg := doc.GetPackageByID(elemID); pkg != nil {
		if pkg.PackageVersion != "" {
			return fmt.Sprintf("%s@%s (Package, ID: %s)", pkg.Name, pkg.PackageVersion, elemID)
		}
		return fmt.Sprintf("%s (Package, ID: %s)", pkg.Name, elemID)
	}

	if file := doc.GetFileByID(elemID); file != nil {
		return fmt.Sprintf("%s (File, ID: %s)", file.Name, elemID)
	}

	for _, snippet := range doc.Snippets {
		if snippet.SpdxID == elemID {
			return fmt.Sprintf("%s (Snippet, ID: %s)", snippet.Name, elemID)
		}
	}

	if tool := doc.GetToolByID(elemID); tool != nil {
		return fmt.Sprintf("%s (Tool, ID: %s)", tool.Name, elemID)
	}

	if agent := doc.GetAgentByID(elemID); agent != nil {
		return fmt.Sprintf("%s (Agent, ID: %s)", agent.Name, elemID)
	}

	if lic := doc.GetAnyLicenseInfoByID(elemID); lic != nil {
		return fmt.Sprintf("%s (License, ID: %s)", lic.Name, elemID)
	}

	if doc.SpdxDocument != nil && doc.SpdxDocument.SpdxID == elemID {
		return fmt.Sprintf("%s (Document, ID: %s)", doc.SpdxDocument.Name, elemID)
	}

	return fmt.Sprintf("ID: %s", elemID)
}
