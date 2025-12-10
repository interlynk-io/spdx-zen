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

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func main() {
	showFiles := flag.Bool("show-files", false, "Show detailed file information")
	agentType := flag.String("filter-agent", "", "Filter by agent type: organization, person, or software")
	flag.Parse()

	var doc *parse.Document
	var err error
	reader := parse.NewReader()

	args := flag.Args()
	if len(args) == 0 {
		// Read from stdin
		doc, err = reader.FromReader(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading SPDX document from stdin: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Read from file
		filePath := args[0]
		doc, err = reader.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading SPDX document from file: %v\n", err)
			os.Exit(1)
		}
	}

	if *agentType != "" {
		printAgentFilteredInfo(doc, *agentType)
	} else {
		printDocumentInfo(doc, *showFiles)
	}
}

func printDocumentInfo(doc *parse.Document, showFiles bool) {
	fmt.Println("=== SPDX Document Information ===")
	fmt.Println()

	// Document metadata
	if doc.SpdxDocument != nil {
		fmt.Println("Document:")
		fmt.Printf("  Name:        %s\n", doc.SpdxDocument.Name)
		fmt.Printf("  SPDX ID:     %s\n", doc.SpdxDocument.SpdxID)
		if doc.SpdxDocument.DataLicense != nil {
			// Resolve the license reference to get the actual name
			if lic := doc.GetAnyLicenseInfoByID(doc.SpdxDocument.DataLicense.SpdxID); lic != nil && lic.Name != "" {
				fmt.Printf("  Data License: %s\n", lic.Name)
			} else if doc.SpdxDocument.DataLicense.Name != "" {
				fmt.Printf("  Data License: %s\n", doc.SpdxDocument.DataLicense.Name)
			} else {
				fmt.Printf("  Data License: %s\n", doc.SpdxDocument.DataLicense.SpdxID)
			}
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

	// Creation info
	if doc.CreationInfo != nil {
		fmt.Println("Creation Info:")
		fmt.Printf("  Spec Version: %s\n", doc.CreationInfo.SpecVersion)
		if !doc.CreationInfo.Created.IsZero() {
			fmt.Printf("  Created:      %s\n", doc.CreationInfo.Created.Format("2006-01-02 15:04:05"))
		}
		if len(doc.CreationInfo.CreatedBy) > 0 {
			fmt.Print("  Created By:   ")
			for i, agentRef := range doc.CreationInfo.CreatedBy {
				if i > 0 {
					fmt.Print(", ")
				}
				// Resolve agent reference to get the actual name
				if agent := doc.GetAgentByID(agentRef.SpdxID); agent != nil && agent.Name != "" {
					fmt.Print(agent.Name)
				} else if agentRef.Name != "" {
					fmt.Print(agentRef.Name)
				} else {
					fmt.Print(agentRef.SpdxID)
				}
			}
			fmt.Println()
		}
		if len(doc.CreationInfo.CreatedUsing) > 0 {
			fmt.Print("  Created Using: ")
			for i, toolRef := range doc.CreationInfo.CreatedUsing {
				if i > 0 {
					fmt.Print(", ")
				}
				// Resolve tool reference to get the actual name
				if tool := doc.GetToolByID(toolRef.SpdxID); tool != nil && tool.Name != "" {
					fmt.Print(tool.Name)
				} else if toolRef.Name != "" {
					fmt.Print(toolRef.Name)
				} else {
					fmt.Print(toolRef.SpdxID)
				}
			}
			fmt.Println()
		}
		fmt.Println()
	}

	// Summary statistics
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
	fmt.Printf("  Licenses:      %d\n", len(doc.AnyLicenseInfos)+len(doc.ConjunctiveLicenseSets)+len(doc.CustomLicenses)+len(doc.CustomLicenseAdditions)+len(doc.DisjunctiveLicenseSets)+len(doc.IndividualLicensingInfos)+len(doc.ListedLicenses)+len(doc.ListedLicenseExceptions)+len(doc.LicenseExpressions)+len(doc.OrLaterOperators)+len(doc.SimpleLicensingTexts)+len(doc.WithAdditionOperators))

	fmt.Printf("  IndividualLicensingInfos: %d\n", len(doc.IndividualLicensingInfos))
	fmt.Println()

	// Packages
	if len(doc.Packages) > 0 {
		fmt.Println("Packages:")
		for _, pkg := range doc.Packages {
			fmt.Printf("  - %s\n", pkg.Name)
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
			// Display CreatedBy agents
			if len(pkg.CreationInfo.CreatedBy) > 0 {
				fmt.Print("      Created By: ")
				for i, agent := range pkg.CreationInfo.CreatedBy {
					if i > 0 {
						fmt.Print(", ")
					}
					// Resolve agent reference to get the actual name
					if agentObj := doc.GetAgentByID(agent.SpdxID); agentObj != nil && agentObj.Name != "" {
						fmt.Print(agentObj.Name)
					} else if agent.Name != "" {
						fmt.Print(agent.Name)
					} else {
						fmt.Print(agent.SpdxID)
					}
				}
				fmt.Println()
			}
			// Display OriginatedBy agents
			if len(pkg.OriginatedBy) > 0 {
				fmt.Print("      Originated By: ")
				for i, agent := range pkg.OriginatedBy {
					if i > 0 {
						fmt.Print(", ")
					}
					// Resolve agent reference to get the actual name
					if agentObj := doc.GetAgentByID(agent.SpdxID); agentObj != nil && agentObj.Name != "" {
						fmt.Print(agentObj.Name)
					} else if agent.Name != "" {
						fmt.Print(agent.Name)
					} else {
						fmt.Print(agent.SpdxID)
					}
				}
				fmt.Println()
			}
			// Display SuppliedBy agent
			if pkg.SuppliedBy != nil {
				fmt.Print("      Supplied By: ")
				// Resolve agent reference to get the actual name
				if agentObj := doc.GetAgentByID(pkg.SuppliedBy.SpdxID); agentObj != nil && agentObj.Name != "" {
					fmt.Print(agentObj.Name)
				} else if pkg.SuppliedBy.Name != "" {
					fmt.Print(pkg.SuppliedBy.Name)
				} else {
					fmt.Print(pkg.SuppliedBy.SpdxID)
				}
				fmt.Println()
			}
			// Display dependencies using parse interface
			deps := doc.GetDependenciesFor(pkg.SpdxID)
			if len(deps) > 0 {
				fmt.Printf("      Dependencies: %d\n", len(deps))
				for _, dep := range deps {
					if dep.PackageVersion != "" {
						fmt.Printf("        - %s@%s\n", dep.Name, dep.PackageVersion)
					} else {
						fmt.Printf("        - %s\n", dep.Name)
					}
				}
			}

			// Display licenses using parse interface
			licInfo := doc.GetLicensesFor(pkg.SpdxID)
			if len(licInfo.ConcludedLicenses) > 0 || len(licInfo.DeclaredLicenses) > 0 {
				fmt.Println("      Licenses:")
				if len(licInfo.ConcludedLicenses) > 0 {
					fmt.Printf("        Concluded: ")
					for i, lic := range licInfo.ConcludedLicenses {
						if i > 0 {
							fmt.Print(", ")
						}
						fmt.Print(lic.Name)
					}
					fmt.Println()
				}
				if len(licInfo.DeclaredLicenses) > 0 {
					fmt.Printf("        Declared: ")
					for i, lic := range licInfo.DeclaredLicenses {
						if i > 0 {
							fmt.Print(", ")
						}
						fmt.Print(lic.Name)
					}
					fmt.Println()
				}
			}

			// Display security info using parse interface
			secInfo := doc.GetSecurityInfoFor(pkg.SpdxID)
			if len(secInfo.Relationships) > 0 {
				fmt.Printf("      Security: %d relationship(s)\n", len(secInfo.Relationships))
				for _, rel := range secInfo.Relationships {
					fmt.Printf("        - %s\n", rel.RelationshipType)
				}
			}

			// Display build info using parse interface
			buildInfo := doc.GetBuildInfoFor(pkg.SpdxID)
			if len(buildInfo.Relationships) > 0 {
				fmt.Printf("      Build: %d relationship(s)\n", len(buildInfo.Relationships))
				for _, rel := range buildInfo.Relationships {
					fmt.Printf("        - %s\n", rel.RelationshipType)
				}
			}

			// Display annotations using parse interface
			annotations := doc.GetAnnotationsFor(pkg.SpdxID)
			if len(annotations) > 0 {
				fmt.Printf("      Annotations: %d\n", len(annotations))
				for _, ann := range annotations {
					fmt.Printf("        - [%s] %s\n", ann.AnnotationType, ann.Statement)
				}
			}

			// Display contained files/packages using parse interface
			containment := doc.GetContainmentFor(pkg.SpdxID)
			if len(containment.Files) > 0 || len(containment.Packages) > 0 {
				totalContained := len(containment.Files) + len(containment.Packages)
				fmt.Printf("      Contains: %d", totalContained)
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
		}
		fmt.Println()
	}

	// Files
	if showFiles && len(doc.Files) > 0 {
		fmt.Println("Files:")
		for _, file := range doc.Files {
			fmt.Printf("  - %s\n", file.Name)
			if file.ContentType != "" {
				fmt.Printf("      Content Type: %s\n", file.ContentType)
			}
			if file.PrimaryPurpose != "" {
				fmt.Printf("      Purpose: %s\n", file.PrimaryPurpose)
			}

			// Display licenses using parse interface
			licInfo := doc.GetLicensesFor(file.SpdxID)
			if len(licInfo.ConcludedLicenses) > 0 || len(licInfo.DeclaredLicenses) > 0 {
				fmt.Println("      Licenses:")
				if len(licInfo.ConcludedLicenses) > 0 {
					fmt.Printf("        Concluded: ")
					for i, lic := range licInfo.ConcludedLicenses {
						if i > 0 {
							fmt.Print(", ")
						}
						fmt.Print(lic.Name)
					}
					fmt.Println()
				}
				if len(licInfo.DeclaredLicenses) > 0 {
					fmt.Printf("        Declared: ")
					for i, lic := range licInfo.DeclaredLicenses {
						if i > 0 {
							fmt.Print(", ")
						}
						fmt.Print(lic.Name)
					}
					fmt.Println()
				}
			}

			// Display copyright text if available
			if file.CopyrightText != "" && file.CopyrightText != "NOASSERTION" {
				fmt.Printf("      Copyright: %s\n", file.CopyrightText)
			}

			// Display build info using parse interface
			buildInfo := doc.GetBuildInfoFor(file.SpdxID)
			if len(buildInfo.Relationships) > 0 {
				fmt.Printf("      Build: %d relationship(s)\n", len(buildInfo.Relationships))
				// for _, rel := range buildInfo.Relationships {
				// 	fmt.Printf("        - %s", rel.RelationshipType)
				// 	if len(rel.To) > 0 {
				// 		fmt.Printf(" ->")
				// 		for i, toElem := range rel.To {
				// 			if i > 0 {
				// 				fmt.Printf(",")
				// 			}
				// 			targetName := toElem.SpdxID
				// 			// Try to resolve the target element name
				// 			if rel.RelationshipType == "hasInput" || rel.RelationshipType == "hasOutput" {
				// 				// Find the target element
				// 				for _, f := range doc.Files {
				// 					if f.SpdxID == toElem.SpdxID {
				// 						targetName = f.Name
				// 						break
				// 					}
				// 				}
				// 			}
				// 			fmt.Printf(" %s", targetName)
				// 		}
				// 	}
				// 	fmt.Println()
				// }
			}

			// Display security info using parse interface
			secInfo := doc.GetSecurityInfoFor(file.SpdxID)
			if len(secInfo.Relationships) > 0 {
				fmt.Printf("      Security: %d relationship(s)\n", len(secInfo.Relationships))
				for _, rel := range secInfo.Relationships {
					fmt.Printf("        - %s\n", rel.RelationshipType)
				}
			}

			// Display annotations using parse interface
			annotations := doc.GetAnnotationsFor(file.SpdxID)
			if len(annotations) > 0 {
				fmt.Printf("      Annotations: %d\n", len(annotations))
				for _, ann := range annotations {
					fmt.Printf("        - [%s] %s\n", ann.AnnotationType, ann.Statement)
				}
			}
		}
		fmt.Println()
	}

	// Relationships
	if len(doc.Relationships) > 0 {
		fmt.Println("Relationship Types:")
		relStats := make(map[string]int)
		for _, rel := range doc.Relationships {
			relStats[string(rel.RelationshipType)]++
		}
		for relType, count := range relStats {
			fmt.Printf("  %s: %d\n", relType, count)
		}
		fmt.Println()
	}

	// Agents
	if len(doc.Organizations) > 0 || len(doc.Persons) > 0 || len(doc.SoftwareAgents) > 0 {
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

	// Tools
	if len(doc.Tools) > 0 {
		fmt.Println("Tools:")
		for _, tool := range doc.Tools {
			fmt.Printf("  - %s\n", tool.Name)
		}
		fmt.Println()
	}



	// Individual Licensing Infos
	if len(doc.IndividualLicensingInfos) > 0 {
		fmt.Println("Individual Licensing Infos:")
		for _, ili := range doc.IndividualLicensingInfos {
			fmt.Printf("  - %s\n", ili.Name)
		}
		fmt.Println()
	}
}

func printAgentFilteredInfo(doc *parse.Document, agentType string) {
	fmt.Printf("=== Agent Filter: %s ===\n", agentType)
	fmt.Println()

	// Collect agent IDs based on type
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
		fmt.Fprintf(os.Stderr, "Invalid agent type: %s. Use 'organization', 'person', or 'software'\n", agentType)
		os.Exit(1)
	}

	if len(agentIDs) == 0 {
		fmt.Printf("No agents of type '%s' found in the document.\n", agentType)
		return
	}

	// Display the agents
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

	// Find elements associated with these agents
	fmt.Println("Associated Elements:")
	fmt.Println()

	for _, agentID := range agentIDs {
		agentName := getAgentName(doc, agentID, agentType)
		fmt.Printf("Agent: %s (ID: %s)\n", agentName, agentID)

		// Check document creation
		if doc.CreationInfo != nil {
			for _, creatorRef := range doc.CreationInfo.CreatedBy {
				if creatorRef.SpdxID == agentID {
					fmt.Printf("  - Created Document: %s\n", getElementInfo(doc, doc.SpdxDocument.SpdxID))
					break
				}
			}
		}

		// Find all elements created by this agent
		createdElements := findElementsCreatedByAgent(doc, agentID)
		if len(createdElements) > 0 {
			fmt.Println("  - Created Elements:")
			for _, elemID := range createdElements {
				fmt.Printf("    - %s\n", getElementInfo(doc, elemID))
			}
		}

		// Check relationships where agent is involved
		var relatedElements []string
		relationshipTypes := make(map[string][]string)

		for _, rel := range doc.Relationships {
			if rel.From.SpdxID == agentID {
				for _, to := range rel.To {
					relatedElements = append(relatedElements, to.SpdxID)
					relationshipTypes[string(rel.RelationshipType)] = append(relationshipTypes[string(rel.RelationshipType)], to.SpdxID)
				}
			}
			for _, to := range rel.To {
				if to.SpdxID == agentID {
					relatedElements = append(relatedElements, rel.From.SpdxID)
					relType := "(reverse) " + string(rel.RelationshipType)
					relationshipTypes[relType] = append(relationshipTypes[relType], rel.From.SpdxID)
				}
			}
		}

		if len(relatedElements) > 0 {
			fmt.Println("  - Involved in Relationships:")
			for relType, elements := range relationshipTypes {
				fmt.Printf("    %s:\n", relType)
				for _, elemID := range elements {
					elemInfo := getElementInfo(doc, elemID)
					fmt.Printf("      - %s\n", elemInfo)
				}
			}
		}

		// Check annotations made by these agents
		var annotatedElements []string
		for _, ann := range doc.Annotations {
			for _, creator := range ann.CreationInfo.CreatedBy {
				if creator.SpdxID == agentID {
					annotatedElements = append(annotatedElements, ann.Subject.SpdxID)
					break
				}
			}
		}

		if len(annotatedElements) > 0 {
			fmt.Println("  - Authored Annotations:")
			for _, elemID := range annotatedElements {
				elemInfo := getElementInfo(doc, elemID)
				fmt.Printf("    - Annotated: %s\n", elemInfo)
			}
		}

		// Check packages associated with these agents (OriginatedBy, SuppliedBy)
		pkgs := findPackagesByAgent(doc, agentID)
		if len(pkgs) > 0 {
			fmt.Println("  - Associated with Packages:")
			for _, pkg := range pkgs {
				pkgInfo := getElementInfo(doc, pkg.SpdxID)
				fmt.Printf("    - %s\n", pkgInfo)
			}
		}
		fmt.Println()
	}
}

func findElementsCreatedByAgent(doc *parse.Document, agentID string) []string {
	var elementIDs []string

	// Helper function to check creation info
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
	// Annotations are checked separately in printAgentFilteredInfo to show what they annotated
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
		// Check OriginatedBy
		for _, originator := range pkg.OriginatedBy {
			if originator.SpdxID == agentID {
				if !processed[pkg.SpdxID] {
					foundPackages = append(foundPackages, pkg)
					processed[pkg.SpdxID] = true
				}
				break
			}
		}

		// Check SuppliedBy
		if pkg.SuppliedBy != nil && pkg.SuppliedBy.SpdxID == agentID {
			if !processed[pkg.SpdxID] {
				foundPackages = append(foundPackages, pkg)
				processed[pkg.SpdxID] = true
			}
		}
	}

	return foundPackages
}


func getAgentName(doc *parse.Document, agentID string, agentType string) string {
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
	// Check packages
	for _, pkg := range doc.Packages {
		if pkg.SpdxID == elemID {
			if pkg.PackageVersion != "" {
				return fmt.Sprintf("%s@%s (Package, ID: %s)", pkg.Name, pkg.PackageVersion, elemID)
			}
			return fmt.Sprintf("%s (Package, ID: %s)", pkg.Name, elemID)
		}
	}

	// Check files
	for _, file := range doc.Files {
		if file.SpdxID == elemID {
			return fmt.Sprintf("%s (File, ID: %s)", file.Name, elemID)
		}
	}

	// Check snippets
	for _, snippet := range doc.Snippets {
		if snippet.SpdxID == elemID {
			return fmt.Sprintf("%s (Snippet, ID: %s)", snippet.Name, elemID)
		}
	}

	// Check tools
	for _, tool := range doc.Tools {
		if tool.SpdxID == elemID {
			return fmt.Sprintf("%s (Tool, ID: %s)", tool.Name, elemID)
		}
	}

	// Check agents
	for _, org := range doc.Organizations {
		if org.SpdxID == elemID {
			return fmt.Sprintf("%s (Organization, ID: %s)", org.Name, elemID)
		}
	}
	for _, person := range doc.Persons {
		if person.SpdxID == elemID {
			return fmt.Sprintf("%s (Person, ID: %s)", person.Name, elemID)
		}
	}
	for _, sa := range doc.SoftwareAgents {
		if sa.SpdxID == elemID {
			return fmt.Sprintf("%s (SoftwareAgent, ID: %s)", sa.Name, elemID)
		}
	}

	// Check licenses
	if lic := doc.GetAnyLicenseInfoByID(elemID); lic != nil {
		return fmt.Sprintf("%s (License, ID: %s)", lic.Name, elemID)
	}



	// Check document itself
	if doc.SpdxDocument != nil && doc.SpdxDocument.SpdxID == elemID {
		return fmt.Sprintf("%s (Document, ID: %s)", doc.SpdxDocument.Name, elemID)
	}

	return fmt.Sprintf("ID: %s", elemID)
}
