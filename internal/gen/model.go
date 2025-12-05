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

// Package gen provides types and functions for parsing SPDX model specifications.
package gen

// Model represents the parsed SPDX specification model.
type Model struct {
	SpecVersion string // e.g., "3.0.1"
	Classes     map[string]*Class
	Properties  map[string]*Property
	Enums       map[string]*Enum
}

// Class represents an SPDX class definition.
type Class struct {
	ID         string
	Name       string
	Comment    string
	Parent     string
	Properties []*PropertyRef
	IsAbstract bool
	NodeKind   string
	Namespace  string // Core, Software, Security, etc.
}

// Property represents an SPDX property definition.
type Property struct {
	ID        string
	Name      string
	Comment   string
	Range     string // The type of the property
	IsObject  bool   // true if ObjectProperty, false if DatatypeProperty
	Namespace string
}

// PropertyRef represents a property reference within a class (from SHACL shapes).
type PropertyRef struct {
	Path     string // Property IRI
	Name     string // Property name
	DataType string // XSD datatype or class reference
	MinCount int
	MaxCount int // -1 means unbounded
	NodeKind string
	ClassRef string   // If referencing another class
	InValues []string // For enums with sh:in
}

// Enum represents an enumeration type.
type Enum struct {
	ID        string
	Name      string
	Comment   string
	Values    []*EnumValue
	Namespace string
}

// EnumValue represents a single enum value.
type EnumValue struct {
	ID      string
	Name    string
	Label   string
	Comment string
}

// NewModel creates a new empty Model.
func NewModel() *Model {
	return &Model{
		Classes:    make(map[string]*Class),
		Properties: make(map[string]*Property),
		Enums:      make(map[string]*Enum),
	}
}
