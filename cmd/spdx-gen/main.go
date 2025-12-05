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

// Package main provides the spdx-gen command for generating Go code from SPDX RDF schemas.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/interlynk-io/spdx-zen/internal/gen"
)

func main() {
	var (
		specFile string
		outDir   string
		pkgName  string
		version  string
	)

	flag.StringVar(&specFile, "spec", "", "Path to SPDX model JSON-LD file")
	flag.StringVar(&outDir, "out", "", "Output directory for generated code")
	flag.StringVar(&pkgName, "pkg", "spdx", "Package name for generated code")
	flag.StringVar(&version, "version", "", "SPDX version (e.g., 3.1.0)")
	flag.Parse()

	if specFile == "" || outDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Parse the model
	parser := gen.NewParser()
	model, err := parser.ParseFile(specFile)
	if err != nil {
		log.Fatalf("Failed to parse model: %v", err)
	}

	// Set version if provided
	if version != "" {
		model.SpecVersion = version
	}

	// Generate code
	generator := gen.NewGenerator(model, pkgName, outDir)
	if err := generator.Generate(); err != nil {
		log.Fatalf("Failed to generate code: %v", err)
	}

	fmt.Printf("Successfully generated code in %s\n", outDir)
}
