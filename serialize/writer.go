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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

// Writer provides JSON-LD serialization capabilities for SPDX 3.0 documents.
type Writer struct {
	// indent controls whether output is pretty-printed.
	// When empty, output is compact (single line).
	indent string
}

// Option configures a Writer.
type Option interface {
	apply(*Writer)
}

type optionFunc func(*Writer)

func (f optionFunc) apply(w *Writer) { f(w) }

// WithIndent enables pretty-printed output with the given indent string
// (e.g., "\t" or "  ").
func WithIndent(indent string) Option {
	return optionFunc(func(w *Writer) {
		w.indent = indent
	})
}

// NewWriter creates a new SPDX JSON-LD writer with the given options.
func NewWriter(opts ...Option) *Writer {
	w := &Writer{}
	for _, opt := range opts {
		opt.apply(w)
	}
	return w
}

// WriteFile serializes an SPDX document to the given file path.
func (w *Writer) WriteFile(doc *parse.Document, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}

	if err := w.Write(doc, f); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("closing file: %w", err)
	}
	return nil
}

// Write serializes an SPDX document to an io.Writer.
func (w *Writer) Write(doc *parse.Document, out io.Writer) error {
	// Step 1: Collect all elements, deduplicating by SpdxID.
	elements := flattenAndDeduplicateDocumentElements(doc)

	// Step 2: Deduplicate CreationInfo values into shared blank nodes.
	ciMap, ciElements, err := deduplicateCreationInfo(elements)
	if err != nil {
		return fmt.Errorf("deduplicating creationInfo: %w", err)
	}

	// Step 3: Convert each element to map + inject type + emit references.
	graph := make([]map[string]interface{}, 0, len(elements)+len(ciElements))

	for _, elem := range elements {
		jsonLDMap, err := marshalSPDXElementToJSONLDMap(elem, ciMap)
		if err != nil {
			return fmt.Errorf("serializing %T: %w", elem, err)
		}
		graph = append(graph, jsonLDMap)
	}

	for _, ciElem := range ciElements {
		graph = append(graph, ciElem)
	}

	// Step 4 & 5: Build output document and marshal JSON.
	output := map[string]interface{}{
		"@context": getContext(doc),
		"@graph":   graph,
	}

	if w.indent != "" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", w.indent)
		return enc.Encode(output)
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	_, err = out.Write(data)
	return err
}

// getContext returns the @context value for the document.
func getContext(doc *parse.Document) interface{} {
	if len(doc.Context) > 0 {
		if len(doc.Context) == 1 {
			return doc.Context[0]
		}
		return doc.Context
	}
	return spdx.ContextURL
}

// flattenAndDeduplicateDocumentElements gathers all elements from a Document's
// typed slices (Packages, Files, Relationships, etc.) into a single flat slice,
// deduplicating by SpdxID.
//
// Why flatten? SPDX 3.0 JSON-LD uses a flat @graph — all elements are peers,
// regardless of their logical relationship. A Package referenced by a
// Relationship appears once in @graph, not nested inside the Relationship.
//
// Why deduplicate? An element may appear in multiple Document slices (e.g., a
// Package in both doc.Packages and doc.SoftwareArtifacts). Deduplication by
// SpdxID ensures each element appears exactly once.
//
// Elements without a SpdxID (Hash, DictionaryEntry) are skipped — these are
// value objects, not independent elements.
func flattenAndDeduplicateDocumentElements(doc *parse.Document) []interface{} {
	seen := make(map[string]bool)
	var elements []interface{}

	add := func(elem interface{}) {
		if elem == nil {
			return
		}
		id := getSpdxID(elem)
		if id == "" {
			return
		}
		if seen[id] {
			return
		}
		seen[id] = true
		elements = append(elements, elem)
	}

	add(doc.SpdxDocument)
	for _, e := range doc.Sboms {
		add(e)
	}
	for _, e := range doc.Boms {
		add(e)
	}
	for _, e := range doc.Bundles {
		add(e)
	}
	for _, e := range doc.Packages {
		add(e)
	}
	for _, e := range doc.SoftwareArtifacts {
		add(e)
	}
	for _, e := range doc.Files {
		add(e)
	}
	for _, e := range doc.Snippets {
		add(e)
	}
	for _, e := range doc.Relationships {
		add(e)
	}
	for _, e := range doc.LifecycleScopedRelationships {
		add(e)
	}
	for _, e := range doc.Annotations {
		add(e)
	}
	for _, e := range doc.ExternalMaps {
		add(e)
	}
	for _, e := range doc.Organizations {
		add(e)
	}
	for _, e := range doc.Persons {
		add(e)
	}
	for _, e := range doc.SoftwareAgents {
		add(e)
	}
	for _, e := range doc.Tools {
		add(e)
	}
	for _, e := range doc.AnyLicenseInfos {
		add(e)
	}
	for _, e := range doc.ConjunctiveLicenseSets {
		add(e)
	}
	for _, e := range doc.CustomLicenses {
		add(e)
	}
	for _, e := range doc.CustomLicenseAdditions {
		add(e)
	}
	for _, e := range doc.DisjunctiveLicenseSets {
		add(e)
	}
	for _, e := range doc.IndividualLicensingInfos {
		add(e)
	}
	for _, e := range doc.ListedLicenses {
		add(e)
	}
	for _, e := range doc.ListedLicenseExceptions {
		add(e)
	}
	for _, e := range doc.LicenseExpressions {
		add(e)
	}
	for _, e := range doc.OrLaterOperators {
		add(e)
	}
	for _, e := range doc.SimpleLicensingTexts {
		add(e)
	}
	for _, e := range doc.WithAdditionOperators {
		add(e)
	}
	for _, e := range doc.Vulnerabilities {
		add(e)
	}
	for _, e := range doc.CvssV2VulnAssessments {
		add(e)
	}
	for _, e := range doc.CvssV3VulnAssessments {
		add(e)
	}
	for _, e := range doc.CvssV4VulnAssessments {
		add(e)
	}
	for _, e := range doc.EpssVulnAssessments {
		add(e)
	}
	for _, e := range doc.SsvcVulnAssessments {
		add(e)
	}
	for _, e := range doc.ExploitCatalogVulnAssessments {
		add(e)
	}
	for _, e := range doc.VexAffectedVulnAssessments {
		add(e)
	}
	for _, e := range doc.VexFixedVulnAssessments {
		add(e)
	}
	for _, e := range doc.VexNotAffectedVulnAssessments {
		add(e)
	}
	for _, e := range doc.VexUnderInvestigationVulnAssessments {
		add(e)
	}
	for _, e := range doc.AiPackages {
		add(e)
	}
	for _, e := range doc.DatasetPackages {
		add(e)
	}
	for _, e := range doc.Builds {
		add(e)
	}

	return elements
}

// getSpdxID extracts the SpdxID field from a struct value, recursively
// searching embedded anonymous structs.
func getSpdxID(v interface{}) string {
	if v == nil {
		return ""
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return ""
	}
	return findFieldRecursive(val, "SpdxID")
}

// findFieldRecursive searches for a named field in a struct and its
// embedded anonymous fields.
func findFieldRecursive(v reflect.Value, name string) string {
	if v.Kind() != reflect.Struct {
		return ""
	}
	if f := v.FieldByName(name); f.IsValid() && f.CanInterface() {
		if s, ok := f.Interface().(string); ok {
			return s
		}
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			if s := findFieldRecursive(v.Field(i), name); s != "" {
				return s
			}
		}
	}
	return ""
}

// creationInfoKey is a comparable key used to deduplicate CreationInfo values.
type creationInfoKey struct {
	SpecVersion  string
	Comment      string
	Created      string // RFC3339Nano
	CreatedBy    string // comma-separated sorted SpdxIDs
	CreatedUsing string // comma-separated sorted SpdxIDs
}

// makeCreationInfoKey builds a deterministic key from a CreationInfo.
func makeCreationInfoKey(ci *spdx.CreationInfo) creationInfoKey {
	var createdBy []string
	for _, a := range ci.CreatedBy {
		createdBy = append(createdBy, a.SpdxID)
	}
	sort.Strings(createdBy)

	var createdUsing []string
	for _, t := range ci.CreatedUsing {
		createdUsing = append(createdUsing, t.SpdxID)
	}
	sort.Strings(createdUsing)

	return creationInfoKey{
		SpecVersion:  ci.SpecVersion,
		Comment:      ci.Comment,
		Created:      ci.Created.Format(time.RFC3339Nano),
		CreatedBy:    strings.Join(createdBy, ","),
		CreatedUsing: strings.Join(createdUsing, ","),
	}
}

// deduplicateCreationInfo walks all elements and extracts their CreationInfo.
// Identical CreationInfo values are grouped and assigned a shared blank node ID.
// The returned map maps each key to its blank node ID, and the slice contains
// the CreationInfo elements ready for the @graph.
func deduplicateCreationInfo(elements []interface{}) (map[creationInfoKey]string, []map[string]interface{}, error) {
	// Group elements by their CreationInfo key.
	groups := make(map[creationInfoKey][]interface{})
	for _, elem := range elements {
		ci := extractCreationInfo(elem)
		if ci == nil {
			continue
		}
		key := makeCreationInfoKey(ci)
		groups[key] = append(groups[key], elem)
	}

	if len(groups) == 0 {
		return nil, nil, nil
	}

	// Sort keys for deterministic blank node IDs.
	var keys []creationInfoKey
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Created < keys[j].Created ||
			(keys[i].Created == keys[j].Created && keys[i].SpecVersion < keys[j].SpecVersion)
	})

	ciMap := make(map[creationInfoKey]string)
	var ciElements []map[string]interface{}

	for i, key := range keys {
		var id string
		if i == 0 {
			id = "_:creationinfo"
		} else {
			id = fmt.Sprintf("_:creationinfo%d", i)
		}
		ciMap[key] = id

		// Build the CreationInfo @graph element.
		// Use the first element's CreationInfo as the representative.
		repElem := groups[key][0]
		ci := extractCreationInfo(repElem)
		if ci == nil {
			continue
		}
		ciElem, err := marshalCreationInfoToBlankNodeMap(ci, id)
		if err != nil {
			return nil, nil, fmt.Errorf("serializing creationInfo: %w", err)
		}
		ciElements = append(ciElements, ciElem)
	}

	return ciMap, ciElements, nil
}

// extractCreationInfo returns the CreationInfo field from an element struct
// via recursive reflection over embedded anonymous fields.
func extractCreationInfo(v interface{}) *spdx.CreationInfo {
	if v == nil {
		return nil
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil
	}
	return findCreationInfoRecursive(val)
}

func findCreationInfoRecursive(v reflect.Value) *spdx.CreationInfo {
	if v.Kind() != reflect.Struct {
		return nil
	}
	if f := v.FieldByName("CreationInfo"); f.IsValid() && f.CanInterface() {
		if ci, ok := f.Interface().(spdx.CreationInfo); ok {
			// Return a copy so modifications don't affect the original.
			return &ci
		}
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			if ci := findCreationInfoRecursive(v.Field(i)); ci != nil {
				return ci
			}
		}
	}
	return nil
}

// marshalCreationInfoToBlankNodeMap converts a CreationInfo struct into a
// map[string]interface{} suitable for the JSON-LD @graph, assigns it the
// given blank node ID (e.g. "_:creationinfo"), and applies reference emission
// so that nested elements (createdBy Agents) become string IDs instead of
// inline objects.
//
// Blank nodes are used because CreationInfo has no SpdxID of its own — it is
// a shared metadata block referenced by multiple elements in the @graph.
func marshalCreationInfoToBlankNodeMap(ci *spdx.CreationInfo, blankNodeID string) (map[string]interface{}, error) {
	m, err := marshalStructToBareFieldMap(ci)
	if err != nil {
		return nil, err
	}
	m["@id"] = blankNodeID
	m["type"] = "CreationInfo"
	replaceNestedElementMapsWithStringReferences(m)
	return m, nil
}

// applyJSONLDFieldPrefixesUsingRegistry renames bare ontology field names to
// their JSON-LD prefixed equivalents using the official SPDX URI registry.
//
// SPDX 3.0 JSON-LD requires profile-specific fields to carry a namespace prefix:
//
//	downloadLocation → software_downloadLocation
//	packageVersion   → software_packageVersion
//	publishedTime    → security_publishedTime
//
// Core fields (name, spdxId, creationInfo) are NOT in the registry and stay bare.
// The registry entries are backed by official SPDX ontology URIs:
//
//	https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation → Prefix="software_"
func applyJSONLDFieldPrefixesUsingRegistry(m map[string]interface{}, elemType spdx.ElementType) {
	for bareField, info := range spdx.JSONLDFieldRegistry[elemType] {
		if v, exists := m[bareField]; exists {
			delete(m, bareField)
			m[info.Prefix+bareField] = v
		}
	}
}

// marshalSPDXElementToJSONLDMap transforms a single SPDX Go struct (e.g. Package,
// Relationship, Vulnerability) into a map[string]interface{} ready for the
// JSON-LD @graph array.
//
// This is the core serialization pipeline for a single element. It performs
// multiple JSON-LD-specific transformations that cannot be expressed in
// the Go model itself:
//  1. marshalStructToBareFieldMap — produces bare ontology field names
//  2. Injects "type" field (e.g. "software_Package") from goTypeToJSONLDTypeString
//  3. applyJSONLDFieldPrefixesUsingRegistry — renames profile fields (software_, security_)
//  4. Replaces CreationInfo with shared blank node reference (e.g. "_:creationinfo")
//  5. replaceNestedElementMapsWithStringReferences — spdxId maps become string IDs
//
// The result is one entry in the JSON-LD @graph array.
func marshalSPDXElementToJSONLDMap(elem interface{}, ciMap map[creationInfoKey]string) (map[string]interface{}, error) {
	bareFieldLists, err := marshalStructToBareFieldMap(elem)
	if err != nil {
		return nil, err
	}

	jsonLDElementType, ok := GetJSONLDTypeString(elem)
	if !ok {
		return nil, fmt.Errorf("unknown element type: %T", elem)
	}
	bareFieldLists["type"] = jsonLDElementType

	// Rename fields to match SPDX JSON-LD prefixed names.
	applyJSONLDFieldPrefixesUsingRegistry(bareFieldLists, spdx.ElementType(jsonLDElementType))

	// Replace CreationInfo with blank node reference.
	if ciMap != nil {
		ci := extractCreationInfo(elem)
		if ci != nil {
			key := makeCreationInfoKey(ci)
			if ref, ok := ciMap[key]; ok {
				bareFieldLists["creationInfo"] = ref
			}
		}
	}

	replaceNestedElementMapsWithStringReferences(bareFieldLists)
	return bareFieldLists, nil
}

// marshalStructToBareFieldMap converts a Go struct into a map[string]interface{}
// whose keys are the SPDX ontology bare property names.
//
// How it works:
//  1. json.Marshal(v) produces JSON bytes using the struct's json tags.
//     Our Go model tags are the bare names from the SPDX ontology
//     (e.g. json:"downloadLocation"), so the JSON keys are already
//     ontology-compliant.
//  2. json.Unmarshal into map[string]interface{} gives us a manipulable map.
//
// Why round-trip instead of manual reflection? Because json.Marshal already
// handles omitempty, nested structs, slices, time.Time, and all json tags.
// Reimplementing that would be error-prone and redundant.
//
// Example: a spdx.Package with DownloadLocation:"https://..." becomes
// map[string]interface{}{"downloadLocation": "https://...", ...}.
func marshalStructToBareFieldMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshaling struct: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling to map: %w", err)
	}
	return m, nil
}

// replaceNestedElementMapsWithStringReferences recursively walks a map and
// replaces any nested map[string]interface{} that represents an SPDX element
// reference (i.e. contains a "spdxId" key) with just its string ID value.
//
// In SPDX 3.0 JSON-LD, relationships between elements are expressed as
// string references, not inline objects. For example:
//
//	Before: "originatedBy": [{"spdxId": "http://...", "name": "Tool", ...}]
//	After:  "originatedBy": ["http://..."]
//
// This generic rule handles ALL reference fields without hardcoding field names:
// Relationship.from/to, Artifact.originatedBy, CreationInfo.createdBy, etc.
// If SPDX adds a new element type with a reference field, this code already
// handles it.
//
// Maps that do NOT contain "spdxId" (value objects like Hash) are left inline
// but get their "type" field injected via injectJSONLDTypeIntoValueObjects.
func replaceNestedElementMapsWithStringReferences(m map[string]interface{}) {
	for k, v := range m {
		switch val := v.(type) {
		case map[string]interface{}:
			if isElementReferenceMap(val) {
				m[k] = val["spdxId"]
			} else {
				replaceNestedElementMapsWithStringReferences(val)
				injectJSONLDTypeIntoValueObjects(val)
			}
		case []interface{}:
			for i, item := range val {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if isElementReferenceMap(itemMap) {
						val[i] = itemMap["spdxId"]
					} else {
						replaceNestedElementMapsWithStringReferences(itemMap)
						injectJSONLDTypeIntoValueObjects(itemMap)
					}
				}
			}
		}
	}
}

// isElementReferenceMap returns true if the map represents an SPDX element
// reference, i.e. it contains a non-empty "spdxId" key.
//
// In SPDX 3.0 JSON-LD, any object with "spdxId" is an element that can be
// referenced by ID. Value objects (Hash, PackageVerificationCode) do NOT have
// spdxId and remain inline with their fields intact.
func isElementReferenceMap(m map[string]interface{}) bool {
	v, ok := m["spdxId"]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s != ""
}

// injectJSONLDTypeIntoValueObjects adds a "type" field to inline value objects
// that don't have one yet. These are SPDX sub-types that are not independent
// elements (no spdxId) but still need a JSON-LD "type" for consumers to
// identify them.
//
// Currently handles:
//   - Hash → "type": "Hash"
//   - PackageVerificationCode → "type": "PackageVerificationCode"
//
// This is called during reference emission for maps that are NOT element
// references (no spdxId).
func injectJSONLDTypeIntoValueObjects(m map[string]interface{}) {
	if _, hasType := m["type"]; hasType {
		return
	}
	if _, ok := m["hashValue"]; ok {
		m["type"] = "Hash"
	} else if _, ok := m["packageVerificationCodeValue"]; ok {
		m["type"] = "PackageVerificationCode"
	}
}
