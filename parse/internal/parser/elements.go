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
	if sb, ok := elemMap["suppliedBy"]; ok {
		if sbMap, ok := sb.(map[string]interface{}); ok {
			artifact.SuppliedBy = p.ParseAgent(sbMap)
		} else if sbStr, ok := sb.(string); ok {
			artifact.SuppliedBy = &spdx.Agent{Element: spdx.Element{SpdxID: sbStr}}
		}
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
			} else if vStr, ok := v.(string); ok {
				agent := spdx.Agent{Element: spdx.Element{SpdxID: vStr}}
				artifact.OriginatedBy = append(artifact.OriginatedBy, agent)
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

// ParseSbom parses an Sbom from a JSON map.
func (p *ElementParser) ParseSbom(elemMap map[string]interface{}) *spdx.Sbom {
	sbom := &spdx.Sbom{}
	// Sbom embeds Bom, so parse embedded Bom fields
	sbom.Bom = *p.ParseBom(elemMap)

	if sbt := p.h.GetSlice(elemMap, "sbomType"); sbt != nil {
		for _, typ := range sbt {
			if ts, ok := typ.(string); ok {
				sbom.SbomType = append(sbom.SbomType, spdx.SbomType(ts))
			}
		}
	}
	return sbom
}

// ParseContentIdentifier parses a ContentIdentifier from a JSON map.
func (p *ElementParser) ParseContentIdentifier(elemMap map[string]interface{}) *spdx.ContentIdentifier {
	ci := &spdx.ContentIdentifier{}
	// ContentIdentifier embeds IntegrityMethod, so parse embedded IntegrityMethod fields
	ci.IntegrityMethod = p.ParseIntegrityMethod(elemMap)

	if cit, ok := elemMap["contentIdentifierType"].(string); ok {
		ci.ContentIdentifierType = spdx.ContentIdentifierType(cit)
	}
	ci.ContentIdentifierValue = p.h.GetString(elemMap, "contentIdentifierValue")

	return ci
}

// ParseVulnerability parses a vulnerability from a JSON map.
func (p *ElementParser) ParseVulnerability(elemMap map[string]interface{}) *spdx.Vulnerability {
	vuln := &spdx.Vulnerability{}
	vuln.Artifact = *p.ParseArtifact(elemMap) // Vulnerability embeds Artifact
	vuln.PublishedTime = p.h.GetTime(elemMap, "publishedTime")
	vuln.ModifiedTime = p.h.GetTime(elemMap, "modifiedTime")
	vuln.WithdrawnTime = p.h.GetTime(elemMap, "withdrawnTime")
	return vuln
}

// ParseVulnAssessmentRelationship parses a generic vulnerability assessment relationship from a JSON map.
// This serves as a helper for specific VulnAssessmentRelationship types.
func (p *ElementParser) ParseVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VulnAssessmentRelationship {
	var vulnRel spdx.VulnAssessmentRelationship
	vulnRel.Relationship = *p.ParseRelationship(elemMap) // VulnAssessmentRelationship embeds Relationship

	if ae, ok := elemMap["assessedElement"].(string); ok {
		vulnRel.AssessedElement = &spdx.SoftwareArtifact{
			Artifact: spdx.Artifact{
				Element: spdx.Element{SpdxID: ae},
			},
		}
	}

	vulnRel.PublishedTime = p.h.GetTime(elemMap, "publishedTime")

	// Parse suppliedBy if present
	if sb, ok := elemMap["suppliedBy"]; ok {
		if sbMap, ok := sb.(map[string]interface{}); ok {
			vulnRel.SuppliedBy = p.ParseAgent(sbMap)
		} else if sbStr, ok := sb.(string); ok {
			vulnRel.SuppliedBy = &spdx.Agent{Element: spdx.Element{SpdxID: sbStr}}
		}
	}

	vulnRel.ModifiedTime = p.h.GetTime(elemMap, "modifiedTime")
	vulnRel.WithdrawnTime = p.h.GetTime(elemMap, "withdrawnTime")
	return &vulnRel
}

// ParseVexVulnAssessmentRelationship parses a generic VEX vulnerability assessment relationship from a JSON map.
// This serves as a helper for specific VEX VulnAssessmentRelationship types.
func (p *ElementParser) ParseVexVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VexVulnAssessmentRelationship {
	var vexVulnRel spdx.VexVulnAssessmentRelationship
	vexVulnRel.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // VexVulnAssessmentRelationship embeds VulnAssessmentRelationship

	vexVulnRel.VexVersion = p.h.GetString(elemMap, "vexVersion")
	vexVulnRel.StatusNotes = p.h.GetString(elemMap, "statusNotes")
	return &vexVulnRel
}

// ParseCvssV2VulnAssessmentRelationship parses a CVSSv2 vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseCvssV2VulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.CvssV2VulnAssessmentRelationship {
	cvss2 := &spdx.CvssV2VulnAssessmentRelationship{}
	cvss2.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	cvss2.Score = p.h.GetFloat(elemMap, "score")
	cvss2.VectorString = p.h.GetString(elemMap, "vectorString")
	return cvss2
}

// ParseCvssV3VulnAssessmentRelationship parses a CVSSv3 vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseCvssV3VulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.CvssV3VulnAssessmentRelationship {
	cvss3 := &spdx.CvssV3VulnAssessmentRelationship{}
	cvss3.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	cvss3.Score = p.h.GetFloat(elemMap, "score")
	if sev, ok := elemMap["severity"].(string); ok {
		cvss3.Severity = spdx.CvssSeverityType(sev)
	}
	cvss3.VectorString = p.h.GetString(elemMap, "vectorString")
	return cvss3
}

// ParseCvssV4VulnAssessmentRelationship parses a CVSSv4 vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseCvssV4VulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.CvssV4VulnAssessmentRelationship {
	cvss4 := &spdx.CvssV4VulnAssessmentRelationship{}
	cvss4.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	cvss4.Score = p.h.GetFloat(elemMap, "score")
	if sev, ok := elemMap["severity"].(string); ok {
		cvss4.Severity = spdx.CvssSeverityType(sev)
	}
	cvss4.VectorString = p.h.GetString(elemMap, "vectorString")
	return cvss4
}

// ParseEpssVulnAssessmentRelationship parses an EPSS vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseEpssVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.EpssVulnAssessmentRelationship {
	epss := &spdx.EpssVulnAssessmentRelationship{}
	epss.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	epss.Probability = p.h.GetFloat(elemMap, "probability")
	epss.Percentile = p.h.GetFloat(elemMap, "percentile")
	return epss
}

// ParseSsvcVulnAssessmentRelationship parses an SSVC vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseSsvcVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.SsvcVulnAssessmentRelationship {
	ssvc := &spdx.SsvcVulnAssessmentRelationship{}
	ssvc.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	if dt, ok := elemMap["decisionType"].(string); ok {
		ssvc.DecisionType = spdx.SsvcDecisionType(dt)
	}
	return ssvc
}

// ParseExploitCatalogVulnAssessmentRelationship parses an ExploitCatalog vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseExploitCatalogVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.ExploitCatalogVulnAssessmentRelationship {
	ec := &spdx.ExploitCatalogVulnAssessmentRelationship{}
	ec.VulnAssessmentRelationship = *p.ParseVulnAssessmentRelationship(elemMap) // embeds VulnAssessmentRelationship

	if ct, ok := elemMap["catalogType"].(string); ok {
		ec.CatalogType = spdx.ExploitCatalogType(ct)
	}
	ec.Exploited = p.h.GetBool(elemMap, "exploited")
	ec.Locator = p.h.GetString(elemMap, "locator")
	return ec
}

// ParseVexAffectedVulnAssessmentRelationship parses a VexAffected vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseVexAffectedVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VexAffectedVulnAssessmentRelationship {
	vexAffected := &spdx.VexAffectedVulnAssessmentRelationship{}
	vexAffected.VexVulnAssessmentRelationship = *p.ParseVexVulnAssessmentRelationship(elemMap) // embeds VexVulnAssessmentRelationship

	vexAffected.ActionStatement = p.h.GetString(elemMap, "actionStatement")
	vexAffected.ActionStatementTime = p.h.GetTime(elemMap, "actionStatementTime")
	return vexAffected
}

// ParseVexFixedVulnAssessmentRelationship parses a VexFixed vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseVexFixedVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VexFixedVulnAssessmentRelationship {
	vexFixed := &spdx.VexFixedVulnAssessmentRelationship{}
	vexFixed.VexVulnAssessmentRelationship = *p.ParseVexVulnAssessmentRelationship(elemMap) // embeds VexVulnAssessmentRelationship
	return vexFixed
}

// ParseVexNotAffectedVulnAssessmentRelationship parses a VexNotAffected vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseVexNotAffectedVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VexNotAffectedVulnAssessmentRelationship {
	vexNotAffected := &spdx.VexNotAffectedVulnAssessmentRelationship{}
	vexNotAffected.VexVulnAssessmentRelationship = *p.ParseVexVulnAssessmentRelationship(elemMap) // embeds VexVulnAssessmentRelationship

	if jt, ok := elemMap["justificationType"].(string); ok {
		vexNotAffected.JustificationType = spdx.VexJustificationType(jt)
	}
	vexNotAffected.ImpactStatement = p.h.GetString(elemMap, "impactStatement")
	vexNotAffected.ImpactStatementTime = p.h.GetTime(elemMap, "impactStatementTime")
	return vexNotAffected
}

// ParseVexUnderInvestigationVulnAssessmentRelationship parses a VexUnderInvestigation vulnerability assessment relationship from a JSON map.
func (p *ElementParser) ParseVexUnderInvestigationVulnAssessmentRelationship(elemMap map[string]interface{}) *spdx.VexUnderInvestigationVulnAssessmentRelationship {
	vexUnderInvestigation := &spdx.VexUnderInvestigationVulnAssessmentRelationship{}
	vexUnderInvestigation.VexVulnAssessmentRelationship = *p.ParseVexVulnAssessmentRelationship(elemMap) // embeds VexVulnAssessmentRelationship
	return vexUnderInvestigation
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

// ParseDictionaryEntry parses a dictionary entry from a JSON map.
func (p *ElementParser) ParseDictionaryEntry(elemMap map[string]interface{}) *spdx.DictionaryEntry {
	return &spdx.DictionaryEntry{
		Key:   p.h.GetString(elemMap, "key"),
		Value: p.h.GetString(elemMap, "value"),
	}
}

// ParseIndividualElement parses an individual element from a JSON map.
func (p *ElementParser) ParseIndividualElement(elemMap map[string]interface{}) *spdx.IndividualElement {
	return &spdx.IndividualElement{
		Element: p.ParseElement(elemMap),
	}
}

// ParseIndividualLicensingInfo parses individual licensing info from a JSON map.
func (p *ElementParser) ParseIndividualLicensingInfo(elemMap map[string]interface{}) *spdx.IndividualLicensingInfo {
	return &spdx.IndividualLicensingInfo{
		AnyLicenseInfo: spdx.AnyLicenseInfo{
			Element: p.ParseElement(elemMap),
		},
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

// ParseElementCollection parses an element collection from a JSON map.
func (p *ElementParser) ParseElementCollection(elemMap map[string]interface{}) spdx.ElementCollection {
	ec := spdx.ElementCollection{
		Element: p.ParseElement(elemMap),
	}

	if elems := p.h.GetSlice(elemMap, "element"); elems != nil {
		for _, e := range elems {
			if es, ok := e.(string); ok {
				ec.Elements = append(ec.Elements, spdx.Element{SpdxID: es})
			}
		}
	}

	if rootElems := p.h.GetSlice(elemMap, "rootElement"); rootElems != nil {
		for _, r := range rootElems {
			if rs, ok := r.(string); ok {
				ec.RootElement = append(ec.RootElement, spdx.Element{SpdxID: rs})
			}
		}
	}

	if pc := p.h.GetSlice(elemMap, "profileConformance"); pc != nil {
		for _, profile := range pc {
			if ps, ok := profile.(string); ok {
				ec.ProfileConformance = append(ec.ProfileConformance, spdx.ProfileIdentifierType(ps))
			}
		}
	}

	return ec
}

// ParseBundle parses a bundle from a JSON map.
func (p *ElementParser) ParseBundle(elemMap map[string]interface{}) *spdx.Bundle {
	bundle := &spdx.Bundle{
		ElementCollection: p.ParseElementCollection(elemMap),
		Context:           p.h.GetString(elemMap, "context"),
	}
	return bundle
}

// ParseBom parses a bom from a JSON map.
func (p *ElementParser) ParseBom(elemMap map[string]interface{}) *spdx.Bom {
	bom := &spdx.Bom{
		Bundle: *p.ParseBundle(elemMap),
	}
	return bom
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

	// Parse ContentIdentifier (from embedded SoftwareArtifact)
	if cids := p.h.GetSlice(elemMap, "contentIdentifier"); cids != nil {
		for _, ci := range cids {
			if ciMap, ok := ci.(map[string]interface{}); ok {
				pkg.ContentIdentifier = append(pkg.ContentIdentifier, *p.ParseContentIdentifier(ciMap))
			}
		}
	}

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

	// Parse ContentIdentifier (from embedded SoftwareArtifact)
	if cids := p.h.GetSlice(elemMap, "contentIdentifier"); cids != nil {
		for _, ci := range cids {
			if ciMap, ok := ci.(map[string]interface{}); ok {
				file.ContentIdentifier = append(file.ContentIdentifier, *p.ParseContentIdentifier(ciMap))
			}
		}
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

	// Parse ContentIdentifier (from embedded SoftwareArtifact)
	if cids := p.h.GetSlice(elemMap, "contentIdentifier"); cids != nil {
		for _, ci := range cids {
			if ciMap, ok := ci.(map[string]interface{}); ok {
				snippet.ContentIdentifier = append(snippet.ContentIdentifier, *p.ParseContentIdentifier(ciMap))
			}
		}
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

// ParseLifecycleScopedRelationship parses a lifecycle-scoped relationship from a JSON map.
func (p *ElementParser) ParseLifecycleScopedRelationship(elemMap map[string]interface{}) *spdx.LifecycleScopedRelationship {
	rel := &spdx.LifecycleScopedRelationship{
		Relationship: *p.ParseRelationship(elemMap),
	}

	if scope, ok := elemMap["scope"].(string); ok {
		rel.Scope = spdx.LifecycleScopeType(scope)
	}

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

// ParseHash parses a hash from a JSON map.
func (p *ElementParser) ParseHash(elemMap map[string]interface{}) *spdx.Hash {
	hash := &spdx.Hash{
		IntegrityMethod: p.ParseIntegrityMethod(elemMap),
		HashValue:       p.h.GetString(elemMap, "hashValue"),
	}
	if alg, ok := elemMap["algorithm"].(string); ok {
		hash.Algorithm = spdx.HashAlgorithm(alg)
	}
	return hash
}

// ParsePackageVerificationCode parses a package verification code from a JSON map.
func (p *ElementParser) ParsePackageVerificationCode(elemMap map[string]interface{}) *spdx.PackageVerificationCode {
	pvc := &spdx.PackageVerificationCode{
		IntegrityMethod:                     p.ParseIntegrityMethod(elemMap),
		HashValue:                           p.h.GetString(elemMap, "hashValue"),
		PackageVerificationCodeExcludedFile: p.h.GetStringSlice(elemMap, "packageVerificationCodeExcludedFile"),
	}
	if alg, ok := elemMap["algorithm"].(string); ok {
		pvc.Algorithm = spdx.HashAlgorithm(alg)
	}
	return pvc
}

// GetTime is a helper for parsing time strings.
func (p *ElementParser) GetTime(elemMap map[string]interface{}, key string) time.Time {
	return p.h.GetTime(elemMap, key)
}
