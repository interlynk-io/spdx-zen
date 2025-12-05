# SPDX Zen

[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/spdx-zen)](https://goreportcard.com/report/github.com/interlynk-io/spdx-zen)
[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/spdx-zen.svg)](https://pkg.go.dev/github.com/interlynk-io/spdx-zen)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A high-performance Go library for parsing and manipulating SPDX 3.0.1 JSON-LD documents. SPDX Zen provides a clean, type-safe API for working with Software Bill of Materials (SBOM) data in the SPDX format.

## Features

- **Full SPDX 3.0.1 Support**: Complete implementation of the SPDX 3.0.1 specification
- **Type-Safe Models**: Strongly typed Go structures for all SPDX elements
- **JSON-LD Native**: First-class support for SPDX JSON-LD format
- **High Performance**: Optimized parsing with O(1) element lookups via indexing
- **Rich Query API**: Intuitive methods for traversing relationships, dependencies, and licenses
- **Profile Support**: Supports all SPDX profiles (Core, Software, Security, Licensing, AI, Dataset, Build)
- **Validation**: Built-in enum validation for SPDX-defined types

## Installation

```bash
go get github.com/interlynk-io/spdx-zen
```

## Quick Start

### Reading an SPDX Document

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/interlynk-io/spdx-zen/parse"
)

func main() {
    // Create a new reader
    reader := parse.NewReader()
    
    // Read an SPDX file
    doc, err := reader.ReadFile("sbom.spdx.json")
    if err != nil {
        log.Fatal(err)
    }
    
    // Access document information
    fmt.Printf("Document: %s\n", doc.GetName())
    fmt.Printf("SPDX Version: %s\n", doc.CreationInfo.SpecVersion)
    fmt.Printf("Packages: %d\n", len(doc.Packages))
    fmt.Printf("Files: %d\n", len(doc.Files))
}
```

### Working with Packages

```go
// Find packages by name
packages := doc.GetPackageByName("my-package")

// Get package by SPDX ID
pkg := doc.GetPackageByID("urn:spdx:pkg-1")

if pkg != nil {
    fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.PackageVersion)
    fmt.Printf("PURL: %s\n", pkg.PackageUrl)
    fmt.Printf("Download: %s\n", pkg.DownloadLocation)
    
    // Get dependencies
    deps := doc.GetDependenciesFor(pkg.SpdxID)
    for _, dep := range deps {
        fmt.Printf("  Depends on: %s\n", dep.Name)
    }
    
    // Get license information
    licInfo := doc.GetLicensesFor(pkg.SpdxID)
    for _, lic := range licInfo.ConcludedLicenses {
        fmt.Printf("  License: %s\n", lic.Name)
    }
}
```

### Exploring Relationships

```go
// Get all relationships from a package
relationships := doc.GetRelationshipsFrom(pkg.SpdxID)

// Get specific relationship types
dependencies := doc.GetRelationshipsByType(spdx.RelationshipTypeDependsOn)

// Get containment information (files and sub-packages)
containment := doc.GetContainmentFor(pkg.SpdxID)
fmt.Printf("Contains %d files and %d packages\n", 
    len(containment.Files), len(containment.Packages))

// Check completeness
if containment.Completeness != nil {
    fmt.Printf("Completeness: %s\n", *containment.Completeness)
}
```

### Security and Vulnerability Information

```go
// Get security information for a package
secInfo := doc.GetSecurityInfoFor(pkg.SpdxID)
for _, rel := range secInfo.Relationships {
    if rel.RelationshipType == spdx.RelationshipTypeAffects {
        fmt.Printf("Affected by vulnerability\n")
    }
}

// Get annotations (comments, reviews, etc.)
annotations := doc.GetAnnotationsFor(pkg.SpdxID)
for _, ann := range annotations {
    fmt.Printf("Annotation [%s]: %s\n", ann.AnnotationType, ann.Statement)
}
```


## Advanced Usage

### Reading from stdin

```go
reader := parse.NewReader()
doc, err := reader.FromReader(os.Stdin)
if err != nil {
    log.Fatal(err)
}
```

### Custom File Reading

```go
// Use a custom file reader (e.g., for testing)
reader := parse.NewReader(
    parse.WithFileReader(func(path string) ([]byte, error) {
        // Custom file reading logic
        return customFileSystem.ReadFile(path)
    }),
)
```

### Query Build Information

```go
// Get build-related information
buildInfo := doc.GetBuildInfoFor(pkg.SpdxID)
for _, rel := range buildInfo.Relationships {
    switch rel.RelationshipType {
    case spdx.RelationshipTypeHasInput:
        fmt.Println("Build input found")
    case spdx.RelationshipTypeHasOutput:
        fmt.Println("Build output found")
    case spdx.RelationshipTypeInvokedBy:
        fmt.Println("Build tool found")
    }
}
```

## Code Generation Tool

The library includes `spdx-gen`, a code generation tool that creates Go types from SPDX RDF/JSON-LD schemas. This tool is used to generate the model types from the official SPDX specification.

### Using spdx-gen

```bash
# Build the generator
make build

# Generate types from an SPDX schema
./bin/spdx-gen -spec docs/spdx-model.json-ld -out ./model/v3.0.1 -pkg spdx -version 3.0.1

# Or use go generate (configured in model/v3.0.1/spdx.go)
go generate ./...
```

### Generator Options

- `-spec`: Path to the SPDX model JSON-LD file (required)
- `-out`: Output directory for generated code (required)  
- `-pkg`: Package name for generated code (default: "spdx")
- `-version`: SPDX version for the generated code

The generator creates:
- `types_gen.go`: All SPDX element types with proper inheritance
- `enums_gen.go`: Enumeration types with validation methods

This ensures the library always stays in sync with the official SPDX specification.

## Example Application

The repository includes a complete example application `spdx-lister` that demonstrates comprehensive document parsing:

```bash
# Build the example
make examples

# Run with a file
./bin/spdx-lister samples/sbomasm.spdx.json

# Run with stdin
cat samples/sbomasm.spdx.json | ./spdx-lister

# Show detailed file information
./spdx-lister --show-files samples/sbomasm.spdx.json
```

## Supported SPDX Specifications

- **SPDX 3.0.1**: Full support for the latest specification
- **JSON-LD Format**: Native support for SPDX JSON-LD serialization
- **All Profiles**: Core, Software, Security, Licensing, AI, Dataset, Build

## Package Structure

```
spdx-zen/
├── model/v3.0.1/       # SPDX 3.0.1 model types
│   ├── spdx.go         # Core types and interfaces
│   ├── types_gen.go    # Generated type definitions
│   └── enums_gen.go    # Generated enum types
├── parse/              # Document parsing functionality
│   ├── reader.go       # Main reader implementation
│   ├── document.go     # Document type with query methods
│   └── internal/       # Internal parsing logic
└── examples/           # Example applications
    └── spdx-lister/    # Complete example showing usage
```

## Performance

The library is designed for high performance:

- **Indexed Lookups**: O(1) element retrieval by SPDX ID
- **Efficient Traversal**: Pre-built relationship indexes for fast queries
- **Minimal Allocations**: Optimized memory usage during parsing
- **Large File Support**: Handles SPDX documents with thousands of elements

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

For questions, issues, or feature requests, please open an issue on [GitHub](https://github.com/interlynk-io/spdx-zen/issues).

## About Interlynk

SPDX Zen is maintained by [Interlynk](https://interlynk.io), a company dedicated to improving software supply chain security through better SBOM tooling and practices.