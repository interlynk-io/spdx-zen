package parser

import (
	"time"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

// ElementParser provides parsing methods for SPDX elements.
// It converts raw JSON maps into typed SPDX model structs.
type ElementParser struct {
	h *Helpers
}

// NewElementParser creates a new ElementParser.
func NewElementParser() *ElementParser {
	return &ElementParser{
		h: NewHelpers(),
	}
}

// ParseElement parses common element fields from a JSON map.
func (p *ElementParser) ParseElement(elemMap map[string]interface{}) spdx.Element {
	elem := spdx.Element{
		SpdxID:      p.h.GetString(elemMap, "spdxId"),
		Name:        p.h.GetString(elemMap, "name"),
		Summary:     p.h.GetString(elemMap, "summary"),
		Description: p.h.GetString(elemMap, "description"),
		Comment:     p.h.GetString(elemMap, "comment"),
	}

	// Parse creationInfo if it's an embedded object
	if ciMap := p.h.GetMap(elemMap, "creationInfo"); ciMap != nil {
		if ci := p.ParseCreationInfo(ciMap); ci != nil {
			elem.CreationInfo = *ci
		}
	}

	// Parse externalIdentifier
	if ei := p.h.GetSlice(elemMap, "externalIdentifier"); ei != nil {
		for _, e := range ei {
			if eMap, ok := e.(map[string]interface{}); ok {
				elem.ExternalIdentifier = append(elem.ExternalIdentifier, *p.ParseExternalIdentifier(eMap))
			}
		}
	}

	return elem
}

// ParseCreationInfo parses creation information from a JSON map.
func (p *ElementParser) ParseCreationInfo(elemMap map[string]interface{}) *spdx.CreationInfo {
	if elemMap == nil {
		return nil
	}

	ci := &spdx.CreationInfo{
		SpecVersion: p.h.GetString(elemMap, "specVersion"),
		Comment:     p.h.GetString(elemMap, "comment"),
		Created:     p.h.GetTime(elemMap, "created"),
	}

	// CreatedBy is a list of Agent references
	if cb := p.h.GetSlice(elemMap, "createdBy"); cb != nil {
		for _, a := range cb {
			if as, ok := a.(string); ok {
				ci.CreatedBy = append(ci.CreatedBy, spdx.Agent{Element: spdx.Element{SpdxID: as}})
			}
		}
	}

	// CreatedUsing is a list of Tool references
	if cu := p.h.GetSlice(elemMap, "createdUsing"); cu != nil {
		for _, t := range cu {
			if ts, ok := t.(string); ok {
				ci.CreatedUsing = append(ci.CreatedUsing, spdx.Tool{Element: spdx.Element{SpdxID: ts}})
			}
		}
	}

	return ci
}

// ParseExternalIdentifier parses an external identifier from a JSON map.
func (p *ElementParser) ParseExternalIdentifier(elemMap map[string]interface{}) *spdx.ExternalIdentifier {
	ei := &spdx.ExternalIdentifier{
		Identifier:        p.h.GetString(elemMap, "identifier"),
		Comment:           p.h.GetString(elemMap, "comment"),
		IdentifierLocator: p.h.GetStringSlice(elemMap, "identifierLocator"),
		IssuingAuthority:  p.h.GetString(elemMap, "issuingAuthority"),
	}

	if eit, ok := elemMap["externalIdentifierType"].(string); ok {
		ei.ExternalIdentifierType = spdx.ExternalIdentifierType(eit)
	}

	return ei
}

// ParseArtifact parses artifact fields from a JSON map.
func (p *ElementParser) ParseArtifact(elemMap map[string]interface{}) *spdx.Artifact {
	artifact := spdx.Artifact{
		StandardName: p.h.GetStringSlice(elemMap, "standardName"),
	}

	// Parse suppliedBy if present
	if sb := p.h.GetMap(elemMap, "suppliedBy"); sb != nil {
		artifact.SuppliedBy = p.ParseAgent(sb)
	}

	// Parse supportLevel if present
	if sl := p.h.GetSlice(elemMap, "supportLevel"); sl != nil {
		artifact.SupportLevel = p.parseSupportLevel(sl)
	}

	artifact.BuiltTime = p.h.GetTime(elemMap, "builtTime")
	artifact.ReleaseTime = p.h.GetTime(elemMap, "releaseTime")
	artifact.ValidUntilTime = p.h.GetTime(elemMap, "validUntilTime")

	if vu := p.h.GetSlice(elemMap, "originatedBy"); vu != nil {
		for _, v := range vu {
			if vMap, ok := v.(map[string]interface{}); ok {
				artifact.OriginatedBy = append(artifact.OriginatedBy, *p.ParseAgent(vMap))
			}
		}
	}

	return &artifact
}

func (p *ElementParser) parseSupportLevel(elemList []interface{}) []spdx.SupportType {
	var supportTypes []spdx.SupportType
	for _, item := range elemList {
		if ps, ok := item.(string); ok {
			supportTypes = append(supportTypes, spdx.SupportType(ps))
		}
	}
	return supportTypes
}

// ParseAgent parses an agent from a JSON map.
func (p *ElementParser) ParseAgent(elemMap map[string]interface{}) *spdx.Agent {
	return &spdx.Agent{
		Element: p.ParseElement(elemMap),
	}
}

// ParseOrganization parses an organization from a JSON map.
func (p *ElementParser) ParseOrganization(elemMap map[string]interface{}) *spdx.Organization {
	return &spdx.Organization{
		Agent: spdx.Agent{
			Element: p.ParseElement(elemMap),
		},
	}
}

// ParsePerson parses a person from a JSON map.
func (p *ElementParser) ParsePerson(elemMap map[string]interface{}) *spdx.Person {
	return &spdx.Person{
		Agent: spdx.Agent{
			Element: p.ParseElement(elemMap),
		},
	}
}

// ParseSoftwareAgent parses a software agent from a JSON map.
func (p *ElementParser) ParseSoftwareAgent(elemMap map[string]interface{}) *spdx.SoftwareAgent {
	return &spdx.SoftwareAgent{
		Agent: spdx.Agent{
			Element: p.ParseElement(elemMap),
		},
	}
}

// ParseTool parses a tool from a JSON map.
func (p *ElementParser) ParseTool(elemMap map[string]interface{}) *spdx.Tool {
	return &spdx.Tool{
		Element: p.ParseElement(elemMap),
	}
}

// ParseLicenseInfo parses license information from a JSON map.
func (p *ElementParser) ParseLicenseInfo(elemMap map[string]interface{}) *spdx.AnyLicenseInfo {
	if elemMap == nil {
		return nil
	}
	
	// Check for license expression field (simplelicensing_licenseExpression)
	licenseExpression := p.h.GetString(elemMap, "simplelicensing_licenseExpression")
	if licenseExpression == "" {
		// Also check for the standard field name
		licenseExpression = p.h.GetString(elemMap, "licenseExpression")
	}
	
	// If we have a license expression, use it as the name
	name := p.h.GetString(elemMap, "name")
	if name == "" && licenseExpression != "" {
		name = licenseExpression
	}
	
	return &spdx.AnyLicenseInfo{
		Element: spdx.Element{
			SpdxID:  p.h.GetString(elemMap, "spdxId"),
			Name:    name,
			Comment: p.h.GetString(elemMap, "comment"),
		},
	}
}

// ParseIntegrityMethod parses an integrity method from a JSON map.
func (p *ElementParser) ParseIntegrityMethod(elemMap map[string]interface{}) spdx.IntegrityMethod {
	return spdx.IntegrityMethod{
		Comment: p.h.GetString(elemMap, "comment"),
	}
}

// ParseRange parses a positive integer range from a JSON map.
func (p *ElementParser) ParseRange(rangeMap map[string]interface{}) *spdx.PositiveIntegerRange {
	return &spdx.PositiveIntegerRange{
		BeginIntegerRange: p.h.GetInt(rangeMap, "beginIntegerRange"),
		EndIntegerRange:   p.h.GetInt(rangeMap, "endIntegerRange"),
	}
}

// ParseSpdxDocument parses an SPDX document element from a JSON map.
func (p *ElementParser) ParseSpdxDocument(elemMap map[string]interface{}) *spdx.SpdxDocument {
	doc := &spdx.SpdxDocument{}

	doc.Element = p.ParseElement(elemMap)

	// DataLicense is a reference (string) to a license element
	if dl, ok := elemMap["dataLicense"].(string); ok {
		doc.DataLicense = &spdx.AnyLicenseInfo{
			Element: spdx.Element{SpdxID: dl},
		}
	}

	// Parse namespaceMap
	doc.NamespaceMap = []spdx.NamespaceMap{}
	if nsMap := p.h.GetMap(elemMap, "namespaceMap"); nsMap != nil {
		for k, v := range nsMap {
			if vs, ok := v.(string); ok {
				doc.NamespaceMap = append(doc.NamespaceMap, spdx.NamespaceMap{Prefix: k, Namespace: vs})
			}
		}
	}

	// Parse profileConformance
	if pc := p.h.GetSlice(elemMap, "profileConformance"); pc != nil {
		for _, profile := range pc {
			if ps, ok := profile.(string); ok {
				doc.ProfileConformance = append(doc.ProfileConformance, spdx.ProfileIdentifierType(ps))
			}
		}
	}

	// Parse imports
	doc.Import = []spdx.ExternalMap{}
	if imps := p.h.GetSlice(elemMap, "import"); imps != nil {
		for _, imp := range imps {
			if impMap, ok := imp.(map[string]interface{}); ok {
				doc.Import = append(doc.Import, *p.ParseExternalMap(impMap))
			}
		}
	}

	return doc
}

// ParsePackage parses a software package from a JSON map.
func (p *ElementParser) ParsePackage(elemMap map[string]interface{}) *spdx.Package {
	pkg := &spdx.Package{}

	pkg.DownloadLocation = p.h.GetString(elemMap, "software_downloadLocation")
	pkg.HomePage = p.h.GetString(elemMap, "software_homePage")
	pkg.PackageUrl = p.h.GetString(elemMap, "software_packageUrl")
	pkg.PackageVersion = p.h.GetString(elemMap, "software_packageVersion")
	pkg.SourceInfo = p.h.GetString(elemMap, "software_sourceInfo")

	// Software Artifact fields
	if pp, ok := elemMap["software_primaryPurpose"].(string); ok {
		pkg.PrimaryPurpose = spdx.SoftwarePurpose(pp)
	}

	if ap := p.h.GetSlice(elemMap, "software_additionalPurpose"); ap != nil {
		for _, purpose := range ap {
			if ps, ok := purpose.(string); ok {
				pkg.AdditionalPurpose = append(pkg.AdditionalPurpose, spdx.SoftwarePurpose(ps))
			}
		}
	}

	pkg.CopyrightText = p.h.GetString(elemMap, "software_copyrightText")
	pkg.AttributionText = p.h.GetStringSlice(elemMap, "software_attributionText")

	// Artifact
	pkg.Artifact = *p.ParseArtifact(elemMap)

	// Element
	pkg.Element = p.ParseElement(elemMap)

	return pkg
}

// ParseFile parses a software file from a JSON map.
func (p *ElementParser) ParseFile(elemMap map[string]interface{}) *spdx.File {
	file := &spdx.File{
		ContentType: p.h.GetString(elemMap, "software_contentType"),
	}

	// Set SoftwareArtifact fields
	file.Element = p.ParseElement(elemMap)
	file.CopyrightText = p.h.GetString(elemMap, "software_copyrightText")
	file.AttributionText = p.h.GetStringSlice(elemMap, "software_attributionText")

	if pp, ok := elemMap["software_primaryPurpose"].(string); ok {
		file.PrimaryPurpose = spdx.SoftwarePurpose(pp)
	}

	if fk, ok := elemMap["software_fileKind"].(string); ok {
		file.FileKind = spdx.FileKindType(fk)
	}

	return file
}

// ParseSnippet parses a software snippet from a JSON map.
func (p *ElementParser) ParseSnippet(elemMap map[string]interface{}) *spdx.Snippet {
	snippet := &spdx.Snippet{}

	// Set SoftwareArtifact fields
	snippet.Element = p.ParseElement(elemMap)
	snippet.CopyrightText = p.h.GetString(elemMap, "software_copyrightText")
	snippet.AttributionText = p.h.GetStringSlice(elemMap, "software_attributionText")

	if br := p.h.GetMap(elemMap, "software_byteRange"); br != nil {
		snippet.ByteRange = p.ParseRange(br)
	}

	if lr := p.h.GetMap(elemMap, "software_lineRange"); lr != nil {
		snippet.LineRange = p.ParseRange(lr)
	}

	return snippet
}

// ParseRelationship parses a relationship from a JSON map.
func (p *ElementParser) ParseRelationship(elemMap map[string]interface{}) *spdx.Relationship {
	rel := &spdx.Relationship{
		Element: p.ParseElement(elemMap),
	}

	// Store From as an Element with just the SpdxID set
	if from, ok := elemMap["from"].(string); ok {
		rel.From = spdx.Element{SpdxID: from}
	}

	// Store To as Elements with just the SpdxIDs set
	if to := p.h.GetSlice(elemMap, "to"); to != nil {
		for _, t := range to {
			if ts, ok := t.(string); ok {
				rel.To = append(rel.To, spdx.Element{SpdxID: ts})
			}
		}
	}

	if rt, ok := elemMap["relationshipType"].(string); ok {
		rel.RelationshipType = spdx.NormalizeRelationshipType(rt)
	}

	if comp, ok := elemMap["completeness"].(string); ok {
		rel.Completeness = spdx.RelationshipCompleteness(comp)
	}

	rel.StartTime = p.h.GetTime(elemMap, "startTime")
	rel.EndTime = p.h.GetTime(elemMap, "endTime")

	return rel
}

// ParseAnnotation parses an annotation from a JSON map.
func (p *ElementParser) ParseAnnotation(elemMap map[string]interface{}) *spdx.Annotation {
	ann := &spdx.Annotation{
		Element:     p.ParseElement(elemMap),
		ContentType: p.h.GetString(elemMap, "contentType"),
		Statement:   p.h.GetString(elemMap, "statement"),
	}

	// Subject is an Element reference
	if subject, ok := elemMap["subject"].(string); ok {
		ann.Subject = spdx.Element{SpdxID: subject}
	}

	if at, ok := elemMap["annotationType"].(string); ok {
		ann.AnnotationType = spdx.AnnotationType(at)
	}

	return ann
}

// ParseExternalMap parses an external map from a JSON map.
func (p *ElementParser) ParseExternalMap(elemMap map[string]interface{}) *spdx.ExternalMap {
	em := &spdx.ExternalMap{
		ExternalSpdxId: p.h.GetString(elemMap, "externalSpdxId"),
		LocationHint:   p.h.GetString(elemMap, "locationHint"),
	}

	if vu := p.h.GetSlice(elemMap, "verifiedUsing"); vu != nil {
		for _, v := range vu {
			if vMap, ok := v.(map[string]interface{}); ok {
				em.VerifiedUsing = append(em.VerifiedUsing, p.ParseIntegrityMethod(vMap))
			}
		}
	}

	return em
}

// GetTime is a helper for parsing time strings.
func (p *ElementParser) GetTime(elemMap map[string]interface{}, key string) time.Time {
	return p.h.GetTime(elemMap, key)
}
