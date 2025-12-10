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

	"github.com/interlynk-io/spdx-zen/parse"
)

func main() {
	showFiles := flag.Bool("show-files", false, "Show detailed file information")
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

	printDocumentInfo(doc, *showFiles)
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
			if lic := doc.GetLicenseByID(doc.SpdxDocument.DataLicense.SpdxID); lic != nil && lic.Name != "" {
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
	fmt.Printf("  Licenses:      %d\n", len(doc.Licenses))
	fmt.Printf("  IndividualElements: %d\n", len(doc.IndividualElements))
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

	// Individual Elements
	if len(doc.IndividualElements) > 0 {
		fmt.Println("Individual Elements:")
		for _, ie := range doc.IndividualElements {
			fmt.Printf("  - %s\n", ie.Name)
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
