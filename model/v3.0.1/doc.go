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

/*
Package spdx provides Go types for working with SPDX 3.0.1 documents.

This package contains types generated from the SPDX 3.0.1 model specification,
organized by SPDX profile domains. The types support JSON-LD serialization
and include validation tags.

# Type Hierarchy

The SPDX 3.0.1 model follows a hierarchical structure:

	Element (base for all SPDX elements)
	├── Artifact (things that can be created)
	│   ├── SoftwareArtifact
	│   │   ├── Package
	│   │   ├── File
	│   │   └── Snippet
	│   └── Vulnerability
	├── Agent (actors in the system)
	│   ├── Person
	│   ├── Organization
	│   └── SoftwareAgent
	├── Relationship
	├── Annotation
	├── ElementCollection
	│   ├── SpdxDocument
	│   ├── Bundle
	│   └── Bom
	└── AnyLicenseInfo (licensing types)

# Profiles

The types are organized by SPDX profiles:

  - Core: Element, Relationship, Annotation, Agent, CreationInfo
  - Software: Package, File, Snippet, Sbom
  - Security: Vulnerability, VexVulnAssessmentRelationship, CvssVulnAssessment
  - Licensing: AnyLicenseInfo, License, LicenseExpression
  - AI: AIPackage
  - Dataset: DatasetPackage
  - Build: Build

# Basic Usage

Creating a simple SPDX document:

	import (
		"time"
		spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	)

	// Create creation info
	creationInfo := spdx.CreationInfo{
		SpecVersion: spdx.SpecVersion,
		Created:     time.Now(),
		CreatedBy: []spdx.Agent{
			{Element: spdx.Element{SpdxID: "urn:spdx:agent-1", Name: "ACME Tools"}},
		},
	}

	// Create a package
	pkg := &spdx.Package{
		SoftwareArtifact: spdx.SoftwareArtifact{
			Artifact: spdx.Artifact{
				Element: spdx.Element{
					SpdxID:       "urn:spdx:pkg-1",
					Name:         "my-package",
					CreationInfo: creationInfo,
				},
			},
		},
		PackageVersion: "1.0.0",
	}

	// Create a document
	doc := &spdx.SpdxDocument{
		ElementCollection: spdx.ElementCollection{
			Element: spdx.Element{
				SpdxID:       "urn:spdx:doc-1",
				Name:         "My SBOM",
				CreationInfo: creationInfo,
			},
		},
	}

# Interfaces

The package provides interfaces for version-agnostic code:

  - ElementInterface: Common interface for all SPDX elements
  - ArtifactInterface: Interface for artifact elements

# Validation

Enum types provide IsValid() methods for validation:

	relType := spdx.RelationshipType("dependsOn")
	if !relType.IsValid() {
		// Handle invalid relationship type
	}

# Generated Code

The types_gen.go and enums_gen.go files are generated from the SPDX model
specification. Do not edit these files directly. Use the spdx-gen tool to
regenerate them:

	go generate ./...
*/
package spdx
