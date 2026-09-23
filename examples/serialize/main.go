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

// serialize-demo is an example program that demonstrates the complete
// SPDX 3.0 JSON-LD round-trip workflow: parse an existing document and
// serialize it back out.
//
// Usage:
//
//	go run main.go -input minimal.spdx3.json -output out.spdx3.json
//	go run main.go -input minimal.spdx3.json -pretty
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/interlynk-io/spdx-zen/parse"
	"github.com/interlynk-io/spdx-zen/serialize"
)

func main() {
	inputFile := flag.String("input", "minimal.spdx3.json", "Input SPDX 3.0 JSON-LD file")
	outputFile := flag.String("output", "", "Output file (default: stdout)")
	pretty := flag.Bool("pretty", false, "Pretty-print the output with indentation")
	flag.Parse()

	// ── Step 1: Parse ─────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "Parsing: %s\n", *inputFile)

	reader := parse.NewReader()
	doc, err := reader.ReadFile(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing document: %v\n", err)
		os.Exit(1)
	}

	printParsedSummary(doc)

	// ── Step 2: Serialize ─────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "Serializing...\n")

	var opts []serialize.Option
	if *pretty {
		opts = append(opts, serialize.WithIndent("\t"))
	}
	writer := serialize.NewWriter(opts...)

	var out *os.File
	if *outputFile != "" {
		out, err = os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
		fmt.Fprintf(os.Stderr, "Writing to: %s\n", *outputFile)
	} else {
		out = os.Stdout
		fmt.Fprintln(os.Stderr, "Writing to stdout")
	}

	if err := writer.Write(doc, out); err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing document: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Done!")
}

func printParsedSummary(doc *parse.Document) {
	fmt.Fprintf(os.Stderr, "\n=== Parsed Document Summary ===\n")

	if doc.SpdxDocument != nil {
		fmt.Fprintf(os.Stderr, "  Document:     %s\n", doc.SpdxDocument.Name)
		fmt.Fprintf(os.Stderr, "  SPDX ID:      %s\n", doc.SpdxDocument.SpdxID)
	}
	if doc.CreationInfo != nil {
		fmt.Fprintf(os.Stderr, "  Spec Version: %s\n", doc.CreationInfo.SpecVersion)
		fmt.Fprintf(os.Stderr, "  Created:      %s\n", doc.CreationInfo.Created.Format("2006-01-02 15:04:05"))
	}

	fmt.Fprintf(os.Stderr, "  Packages:     %d\n", len(doc.Packages))
	fmt.Fprintf(os.Stderr, "  Files:        %d\n", len(doc.Files))
	fmt.Fprintf(os.Stderr, "  Snippets:     %d\n", len(doc.Snippets))
	fmt.Fprintf(os.Stderr, "  Relationships:%d\n", len(doc.Relationships))
	fmt.Fprintf(os.Stderr, "  Organizations:%d\n", len(doc.Organizations))
	fmt.Fprintf(os.Stderr, "  Persons:      %d\n", len(doc.Persons))
	fmt.Fprintf(os.Stderr, "  Tools:        %d\n", len(doc.Tools))
	fmt.Fprintf(os.Stderr, "  Licenses:     %d\n", len(doc.AnyLicenseInfos))
	fmt.Fprintf(os.Stderr, "================================\n\n")
}
