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

package gen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	owlClass            = "http://www.w3.org/2002/07/owl#Class"
	owlNamedIndividual  = "http://www.w3.org/2002/07/owl#NamedIndividual"
	owlObjectProperty   = "http://www.w3.org/2002/07/owl#ObjectProperty"
	owlDatatypeProperty = "http://www.w3.org/2002/07/owl#DatatypeProperty"
	rdfsSubClassOf      = "http://www.w3.org/2000/01/rdf-schema#subClassOf"
	rdfsComment         = "http://www.w3.org/2000/01/rdf-schema#comment"
	rdfsLabel           = "http://www.w3.org/2000/01/rdf-schema#label"
	rdfsRange           = "http://www.w3.org/2000/01/rdf-schema#range"
	shaclNodeShape      = "http://www.w3.org/ns/shacl#NodeShape"
	shaclProperty       = "http://www.w3.org/ns/shacl#property"
	shaclPath           = "http://www.w3.org/ns/shacl#path"
	shaclDatatype       = "http://www.w3.org/ns/shacl#datatype"
	shaclClass          = "http://www.w3.org/ns/shacl#class"
	shaclMinCount       = "http://www.w3.org/ns/shacl#minCount"
	shaclMaxCount       = "http://www.w3.org/ns/shacl#maxCount"
	shaclNodeKind       = "http://www.w3.org/ns/shacl#nodeKind"
	shaclIn             = "http://www.w3.org/ns/shacl#in"
	shaclMessage        = "http://www.w3.org/ns/shacl#message"
	spdxBaseURI         = "https://spdx.org/rdf/3.0.1/terms/"
)

// RDFNode represents a node in the JSON-LD graph.
type RDFNode map[string]json.RawMessage

// Parser parses SPDX model JSON-LD files.
type Parser struct {
	nodes      map[string]RDFNode
	blankNodes map[string]RDFNode
}

// NewParser creates a new Parser.
func NewParser() *Parser {
	return &Parser{
		nodes:      make(map[string]RDFNode),
		blankNodes: make(map[string]RDFNode),
	}
}

// ParseFile parses an SPDX model JSON-LD file.
//
//nolint:gocognit // Code generator with multiple parsing passes; complexity is acceptable for tooling.
func (p *Parser) ParseFile(path string) (*Model, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var nodes []RDFNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("unmarshal JSON-LD: %w", err)
	}

	// Index all nodes by their @id
	for _, node := range nodes {
		id := p.getString(node, "@id")
		if id == "" {
			continue
		}
		if strings.HasPrefix(id, "_:") {
			p.blankNodes[id] = node
		} else {
			p.nodes[id] = node
		}
	}

	model := NewModel()

	// First pass: collect all classes, properties, and enum types
	for id, node := range p.nodes {
		types := p.getTypes(node)

		if p.containsType(types, owlClass) {
			class := p.parseClass(id, node)
			if class != nil {
				model.Classes[id] = class
			}
		}

		if p.containsType(types, owlObjectProperty) {
			prop := p.parseProperty(id, node, true)
			if prop != nil {
				model.Properties[id] = prop
			}
		}

		if p.containsType(types, owlDatatypeProperty) {
			prop := p.parseProperty(id, node, false)
			if prop != nil {
				model.Properties[id] = prop
			}
		}
	}

	// Second pass: collect enum values
	for id, node := range p.nodes {
		types := p.getTypes(node)

		if p.containsType(types, owlNamedIndividual) {
			// Find which enum type this belongs to
			for _, t := range types {
				if strings.HasPrefix(t, spdxBaseURI) && t != owlNamedIndividual {
					enumID := t
					enum, exists := model.Enums[enumID]
					if !exists {
						// Don't treat a class with a parent as an enum.
						if class, isClass := model.Classes[enumID]; isClass {
							if class.Parent != "" {
								continue
							}
						}
						// Create the enum if it doesn't exist
						enum = &Enum{
							ID:        enumID,
							Name:      extractName(enumID),
							Namespace: extractNamespace(enumID),
							Values:    make([]*EnumValue, 0),
						}
						// Get comment from the class if available
						if classNode, ok := p.nodes[enumID]; ok {
							enum.Comment = p.getComment(classNode)
						}
						model.Enums[enumID] = enum
					}

					value := &EnumValue{
						ID:      id,
						Name:    extractEnumValueName(id),
						Label:   p.getLabel(node),
						Comment: p.getComment(node),
					}
					enum.Values = append(enum.Values, value)
					break
				}
			}
		}
	}

	// Third pass: parse SHACL property shapes for classes
	for id, node := range p.nodes {
		types := p.getTypes(node)

		if p.containsType(types, shaclNodeShape) {
			class, exists := model.Classes[id]
			if !exists {
				continue
			}

			propRefs := p.getArray(node, shaclProperty)
			for _, propRefRaw := range propRefs {
				var propRef struct {
					ID string `json:"@id"`
				}
				if err := json.Unmarshal(propRefRaw, &propRef); err != nil {
					continue
				}

				blankNode, exists := p.blankNodes[propRef.ID]
				if !exists {
					continue
				}

				pr := p.parsePropertyRef(blankNode)
				if pr != nil {
					// Check if this is an abstract class marker
					if p.isAbstractMarker(blankNode, id) {
						class.IsAbstract = true
						continue
					}
					class.Properties = append(class.Properties, pr)
				}
			}
		}
	}

	return model, nil
}

func (p *Parser) parseClass(id string, node RDFNode) *Class {
	class := &Class{
		ID:         id,
		Name:       extractName(id),
		Comment:    p.getComment(node),
		Namespace:  extractNamespace(id),
		Properties: make([]*PropertyRef, 0),
	}

	// Get parent class
	subClassOf := p.getArray(node, rdfsSubClassOf)
	if len(subClassOf) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(subClassOf[0], &ref); err == nil {
			class.Parent = ref.ID
		}
	}

	// Get node kind
	nodeKindArr := p.getArray(node, shaclNodeKind)
	if len(nodeKindArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(nodeKindArr[0], &ref); err == nil {
			class.NodeKind = ref.ID
		}
	}

	return class
}

func (p *Parser) parseProperty(id string, node RDFNode, isObject bool) *Property {
	prop := &Property{
		ID:        id,
		Name:      extractName(id),
		Comment:   p.getComment(node),
		IsObject:  isObject,
		Namespace: extractNamespace(id),
	}

	// Get range
	rangeArr := p.getArray(node, rdfsRange)
	if len(rangeArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(rangeArr[0], &ref); err == nil {
			prop.Range = ref.ID
		}
	}

	return prop
}

func (p *Parser) parsePropertyRef(node RDFNode) *PropertyRef {
	pr := &PropertyRef{
		MinCount: 0,
		MaxCount: -1, // unbounded by default
	}

	// Get path
	pathArr := p.getArray(node, shaclPath)
	if len(pathArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(pathArr[0], &ref); err == nil {
			pr.Path = ref.ID
			pr.Name = extractName(ref.ID)
		}
	}

	// Get datatype
	datatypeArr := p.getArray(node, shaclDatatype)
	if len(datatypeArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(datatypeArr[0], &ref); err == nil {
			pr.DataType = ref.ID
		}
	}

	// Get class reference
	classArr := p.getArray(node, shaclClass)
	if len(classArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(classArr[0], &ref); err == nil {
			pr.ClassRef = ref.ID
		}
	}

	// Get minCount
	minCountArr := p.getArray(node, shaclMinCount)
	if len(minCountArr) > 0 {
		var val struct {
			Value int `json:"@value"`
		}
		if err := json.Unmarshal(minCountArr[0], &val); err == nil {
			pr.MinCount = val.Value
		}
	}

	// Get maxCount
	maxCountArr := p.getArray(node, shaclMaxCount)
	if len(maxCountArr) > 0 {
		var val struct {
			Value int `json:"@value"`
		}
		if err := json.Unmarshal(maxCountArr[0], &val); err == nil {
			pr.MaxCount = val.Value
		}
	}

	// Get nodeKind
	nodeKindArr := p.getArray(node, shaclNodeKind)
	if len(nodeKindArr) > 0 {
		var ref struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(nodeKindArr[0], &ref); err == nil {
			pr.NodeKind = ref.ID
		}
	}

	// Get sh:in values for enums
	inArr := p.getArray(node, shaclIn)
	if len(inArr) > 0 {
		var list struct {
			List []struct {
				ID string `json:"@id"`
			} `json:"@list"`
		}
		if err := json.Unmarshal(inArr[0], &list); err == nil {
			for _, item := range list.List {
				pr.InValues = append(pr.InValues, item.ID)
			}
		}
	}

	return pr
}

func (p *Parser) isAbstractMarker(node RDFNode, _ string) bool {
	// Check if this is an abstract class marker (sh:message containing "abstract")
	msgArr := p.getArray(node, shaclMessage)
	if len(msgArr) > 0 {
		var msg struct {
			Value string `json:"@value"`
		}
		if err := json.Unmarshal(msgArr[0], &msg); err == nil {
			return strings.Contains(strings.ToLower(msg.Value), "abstract")
		}
	}
	return false
}

func (p *Parser) getString(node RDFNode, key string) string {
	raw, ok := node[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func (p *Parser) getTypes(node RDFNode) []string {
	raw, ok := node["@type"]
	if !ok {
		return nil
	}

	var types []string
	if err := json.Unmarshal(raw, &types); err != nil {
		// Try single value
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			return []string{single}
		}
		return nil
	}
	return types
}

func (p *Parser) getArray(node RDFNode, key string) []json.RawMessage {
	raw, ok := node[key]
	if !ok {
		return nil
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	return arr
}

func (p *Parser) getComment(node RDFNode) string {
	comments := p.getArray(node, rdfsComment)
	if len(comments) == 0 {
		return ""
	}

	var comment struct {
		Value    string `json:"@value"`
		Language string `json:"@language"`
	}
	if err := json.Unmarshal(comments[0], &comment); err != nil {
		return ""
	}
	return comment.Value
}

func (p *Parser) getLabel(node RDFNode) string {
	labels := p.getArray(node, rdfsLabel)
	if len(labels) == 0 {
		return ""
	}

	var label struct {
		Value string `json:"@value"`
	}
	if err := json.Unmarshal(labels[0], &label); err != nil {
		return ""
	}
	return label.Value
}

func (p *Parser) containsType(types []string, target string) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

// extractName extracts the local name from an IRI.
func extractName(iri string) string {
	// Handle SPDX URIs like https://spdx.org/rdf/3.0.1/terms/Core/Element
	if idx := strings.LastIndex(iri, "/"); idx >= 0 {
		return iri[idx+1:]
	}
	if idx := strings.LastIndex(iri, "#"); idx >= 0 {
		return iri[idx+1:]
	}
	return iri
}

// extractNamespace extracts the namespace from an SPDX IRI.
func extractNamespace(iri string) string {
	if !strings.HasPrefix(iri, spdxBaseURI) {
		return ""
	}
	rest := strings.TrimPrefix(iri, spdxBaseURI)
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// extractEnumValueName extracts the enum value name from an IRI.
// e.g., "https://spdx.org/rdf/3.0.1/terms/Core/HashAlgorithm/sha256" -> "sha256"
func extractEnumValueName(iri string) string {
	if idx := strings.LastIndex(iri, "/"); idx >= 0 {
		return iri[idx+1:]
	}
	return iri
}
