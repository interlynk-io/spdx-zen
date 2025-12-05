// Package jsonld provides JSON-LD processing capabilities for SPDX documents.
package jsonld

import (
	"github.com/piprate/json-gold/ld"
)

// DocumentLoader defines the interface for loading JSON-LD documents.
// This enables mocking and testing without network dependencies.
type DocumentLoader interface {
	LoadDocument(url string) (*ld.RemoteDocument, error)
}

// FallbackLoader provides a document loader that falls back to empty contexts
// when remote URLs are unavailable.
type FallbackLoader struct {
	defaultLoader ld.DocumentLoader
}

// NewFallbackLoader creates a new FallbackLoader with the default document loader.
func NewFallbackLoader() *FallbackLoader {
	return &FallbackLoader{
		defaultLoader: ld.NewDefaultDocumentLoader(nil),
	}
}

// LoadDocument loads a JSON-LD document from the given URL.
// If the default loader fails, it returns an empty context document.
func (l *FallbackLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	doc, err := l.defaultLoader.LoadDocument(url)
	if err == nil {
		return doc, nil
	}

	// Return empty context for unavailable URLs
	return &ld.RemoteDocument{
		DocumentURL: url,
		Document:    map[string]interface{}{},
	}, nil
}

// Processor wraps the JSON-LD processor with configurable options.
type Processor struct {
	proc    *ld.JsonLdProcessor
	options *ld.JsonLdOptions
}

// NewProcessor creates a new JSON-LD processor with the given document loader.
func NewProcessor(loader DocumentLoader) *Processor {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = loader

	return &Processor{
		proc:    proc,
		options: options,
	}
}

// Expand performs JSON-LD expansion on the document.
func (p *Processor) Expand(doc interface{}) ([]interface{}, error) {
	return p.proc.Expand(doc, p.options)
}

// Flatten performs JSON-LD flattening on the document.
func (p *Processor) Flatten(doc interface{}) (interface{}, error) {
	return p.proc.Flatten(doc, nil, p.options)
}

// Compact performs JSON-LD compaction on the document with the given context.
func (p *Processor) Compact(doc interface{}, context interface{}) (interface{}, error) {
	return p.proc.Compact(doc, context, p.options)
}
