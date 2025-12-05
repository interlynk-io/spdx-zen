package parse

import spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"

// Document represents an SPDX 3.0 JSON-LD document
type Document struct {
	Context []string       `json:"@context,omitempty"`
	Graph   []spdx.Element `json:"-"` // Parsed elements from @graph

	// Parsed and categorized elements
	SpdxDocument  *spdx.SpdxDocument
	Packages      []*spdx.Package
	Files         []*spdx.File
	Snippets      []*spdx.Snippet
	Relationships []*spdx.Relationship
	Annotations   []*spdx.Annotation
	ExternalMaps  []*spdx.ExternalMap
	CreationInfo  *spdx.CreationInfo
	Agents        []*spdx.Agent
	Tools         []*spdx.Tool
	Licenses      []*spdx.AnyLicenseInfo

	// All elements indexed by SPDX ID
	ElementsByID map[string]interface{}

	// Relationship indexes for O(1) lookups
	RelationshipsFromIndex map[string][]*spdx.Relationship
	RelationshipsToIndex   map[string][]*spdx.Relationship

	// Element type indexes for O(1) lookups
	PackagesByID map[string]*spdx.Package
	FilesByID    map[string]*spdx.File
	AgentsByID   map[string]*spdx.Agent
	ToolsByID    map[string]*spdx.Tool
	LicensesByID map[string]*spdx.AnyLicenseInfo
}

// GetName returns the document name
func (d *Document) GetName() string {
	if d.SpdxDocument != nil {
		return d.SpdxDocument.Name
	}
	return ""
}

// GetSpdxID returns the document SPDX ID
func (d *Document) GetSpdxID() string {
	if d.SpdxDocument != nil {
		return d.SpdxDocument.SpdxID
	}
	return ""
}

// GetProfiles returns the profile conformance list
func (d *Document) GetProfiles() []spdx.ProfileIdentifierType {
	if d.SpdxDocument != nil {
		return d.SpdxDocument.ProfileConformance
	}
	return nil
}

// GetDataLicense returns the data license
func (d *Document) GetDataLicense() *spdx.AnyLicenseInfo {
	if d.SpdxDocument != nil {
		return d.SpdxDocument.DataLicense
	}
	return nil
}

// GetPackageByID returns a package by its SPDX ID
func (d *Document) GetPackageByID(spdxID string) *spdx.Package {
	if d.PackagesByID != nil {
		return d.PackagesByID[spdxID]
	}
	for _, pkg := range d.Packages {
		if pkg.SpdxID == spdxID {
			return pkg
		}
	}
	return nil
}

// GetPackageByName returns packages matching the given name
func (d *Document) GetPackageByName(name string) []*spdx.Package {
	var result []*spdx.Package
	for _, pkg := range d.Packages {
		if pkg.Name == name {
			result = append(result, pkg)
		}
	}
	return result
}

// GetFileByID returns a file by its SPDX ID
func (d *Document) GetFileByID(spdxID string) *spdx.File {
	if d.FilesByID != nil {
		return d.FilesByID[spdxID]
	}
	for _, file := range d.Files {
		if file.SpdxID == spdxID {
			return file
		}
	}
	return nil
}

// GetFileByName returns files matching the given name
func (d *Document) GetFileByName(name string) []*spdx.File {
	var result []*spdx.File
	for _, file := range d.Files {
		if file.Name == name {
			result = append(result, file)
		}
	}
	return result
}

// GetRelationshipsByType returns relationships of a specific type
func (d *Document) GetRelationshipsByType(relType spdx.RelationshipType) []*spdx.Relationship {
	var result []*spdx.Relationship
	for _, rel := range d.Relationships {
		if rel.RelationshipType == relType {
			result = append(result, rel)
		}
	}
	return result
}

// GetRelationshipsFrom returns relationships from a specific element
func (d *Document) GetRelationshipsFrom(spdxID string) []*spdx.Relationship {
	if d.RelationshipsFromIndex != nil {
		return d.RelationshipsFromIndex[spdxID]
	}
	var result []*spdx.Relationship
	for _, rel := range d.Relationships {
		if rel.From.GetSpdxID() == spdxID {
			result = append(result, rel)
		}
	}
	return result
}

// GetRelationshipsTo returns relationships to a specific element
func (d *Document) GetRelationshipsTo(spdxID string) []*spdx.Relationship {
	if d.RelationshipsToIndex != nil {
		return d.RelationshipsToIndex[spdxID]
	}
	var result []*spdx.Relationship
	for _, rel := range d.Relationships {
		for _, to := range rel.To {
			if to.GetSpdxID() == spdxID {
				result = append(result, rel)
				break
			}
		}
	}
	return result
}

// GetDependencies returns all DEPENDS_ON relationships
func (d *Document) GetDependencies() []*spdx.Relationship {
	return d.GetRelationshipsByType(spdx.RelationshipTypeDependsOn)
}

// GetDescribes returns all DESCRIBES relationships
func (d *Document) GetDescribes() []*spdx.Relationship {
	return d.GetRelationshipsByType(spdx.RelationshipTypeDescribes)
}

// GetElementByID returns any element by its SPDX ID
func (d *Document) GetElementByID(spdxID string) interface{} {
	return d.ElementsByID[spdxID]
}

// GetRelationshipTypeStats returns a map of relationship types to their counts
func (d *Document) GetRelationshipTypeStats() map[spdx.RelationshipType]int {
	stats := make(map[spdx.RelationshipType]int)
	for _, rel := range d.Relationships {
		stats[rel.RelationshipType]++
	}
	return stats
}

// GetPackagesWithPURL returns packages that have a PURL external identifier
func (d *Document) GetPackagesWithPURL() []*spdx.Package {
	var result []*spdx.Package
	for _, pkg := range d.Packages {
		for _, ei := range pkg.ExternalIdentifier {
			if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypePackageUrl {
				result = append(result, pkg)
				break
			}
		}
	}
	return result
}

// GetDependenciesFor returns the packages that the given element depends on.
// It uses the model's IsDependency() method to identify dependency relationships
// (DEPENDS_ON, HAS_OPTIONAL_DEPENDENCY, HAS_PROVIDED_DEPENDENCY, HAS_PREREQUISITE).
func (d *Document) GetDependenciesFor(spdxID string) []*spdx.Package {
	var result []*spdx.Package
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsDependency() {
			for _, to := range rel.To {
				if pkg := d.GetPackageByID(to.GetSpdxID()); pkg != nil {
					result = append(result, pkg)
				}
			}
		}
	}
	return result
}

// LicenseInfo holds license information for an element.
type LicenseInfo struct {
	ConcludedLicenses []*spdx.AnyLicenseInfo
	DeclaredLicenses  []*spdx.AnyLicenseInfo
}

// GetLicensesFor returns the license information for the given element.
// It looks up HAS_CONCLUDED_LICENSE and HAS_DECLARED_LICENSE relationships.
func (d *Document) GetLicensesFor(spdxID string) *LicenseInfo {
	info := &LicenseInfo{}
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsConcludedLicense() {
			for _, to := range rel.To {
				if lic := d.GetLicenseByID(to.GetSpdxID()); lic != nil {
					info.ConcludedLicenses = append(info.ConcludedLicenses, lic)
				}
			}
		} else if rel.IsDeclaredLicense() {
			for _, to := range rel.To {
				if lic := d.GetLicenseByID(to.GetSpdxID()); lic != nil {
					info.DeclaredLicenses = append(info.DeclaredLicenses, lic)
				}
			}
		}
	}
	return info
}

// GetLicenseByID returns a license by its SPDX ID.
func (d *Document) GetLicenseByID(spdxID string) *spdx.AnyLicenseInfo {
	if d.LicensesByID != nil {
		if lic := d.LicensesByID[spdxID]; lic != nil {
			return lic
		}
	} else {
		for _, lic := range d.Licenses {
			if lic.SpdxID == spdxID {
				return lic
			}
		}
	}
	// Also check ElementsByID for licenses that might be stored as generic elements
	if elem := d.ElementsByID[spdxID]; elem != nil {
		if elemMap, ok := elem.(map[string]interface{}); ok {
			if name, ok := elemMap["name"].(string); ok {
				return &spdx.AnyLicenseInfo{
					Element: spdx.Element{
						SpdxID: spdxID,
						Name:   name,
					},
				}
			}
		}
	}
	return nil
}

// SecurityInfo holds security/vulnerability information for an element.
type SecurityInfo struct {
	Relationships []*spdx.Relationship
}

// GetSecurityInfoFor returns security-related relationships for the given element.
// This includes vulnerability assessments, affects/doesNotAffect, fixedIn, etc.
func (d *Document) GetSecurityInfoFor(spdxID string) *SecurityInfo {
	info := &SecurityInfo{}
	// Check relationships FROM this element
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsSecurityRelationship() {
			info.Relationships = append(info.Relationships, rel)
		}
	}
	// Also check relationships TO this element (e.g., vulnerability affects package)
	for _, rel := range d.GetRelationshipsTo(spdxID) {
		if rel.IsSecurityRelationship() {
			info.Relationships = append(info.Relationships, rel)
		}
	}
	return info
}

// BuildInfo holds build information for an element.
type BuildInfo struct {
	Relationships []*spdx.Relationship
}

// GetBuildInfoFor returns build-related relationships for the given element.
// This includes hasInput, hasOutput, hasHost, invokedBy, generates.
func (d *Document) GetBuildInfoFor(spdxID string) *BuildInfo {
	info := &BuildInfo{}
	// Check relationships FROM this element
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsBuildRelationship() {
			info.Relationships = append(info.Relationships, rel)
		}
	}
	// Also check relationships TO this element
	for _, rel := range d.GetRelationshipsTo(spdxID) {
		if rel.IsBuildRelationship() {
			info.Relationships = append(info.Relationships, rel)
		}
	}
	return info
}

// GetAnnotationsFor returns annotations that reference the given element as their subject.
func (d *Document) GetAnnotationsFor(spdxID string) []*spdx.Annotation {
	var result []*spdx.Annotation
	for _, ann := range d.Annotations {
		if ann.Subject.GetSpdxID() == spdxID {
			result = append(result, ann)
		}
	}
	return result
}

// GetAgentByID returns an agent by its SPDX ID.
// This is useful for resolving agent references in CreationInfo.
func (d *Document) GetAgentByID(spdxID string) *spdx.Agent {
	if d.AgentsByID != nil {
		return d.AgentsByID[spdxID]
	}
	for _, agent := range d.Agents {
		if agent.SpdxID == spdxID {
			return agent
		}
	}
	return nil
}

// GetToolByID returns a tool by its SPDX ID.
// This is useful for resolving tool references in CreationInfo.
func (d *Document) GetToolByID(spdxID string) *spdx.Tool {
	if d.ToolsByID != nil {
		return d.ToolsByID[spdxID]
	}
	for _, tool := range d.Tools {
		if tool.SpdxID == spdxID {
			return tool
		}
	}
	return nil
}

// GetContainedFilesFor returns the files contained by the given element.
// It looks up CONTAINS relationships where the element is the 'from' side.
func (d *Document) GetContainedFilesFor(spdxID string) []*spdx.File {
	var result []*spdx.File
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsContainment() {
			for _, to := range rel.To {
				if file := d.GetFileByID(to.GetSpdxID()); file != nil {
					result = append(result, file)
				}
			}
		}
	}
	return result
}

// GetContainedPackagesFor returns the packages contained by the given element.
// It looks up CONTAINS relationships where the element is the 'from' side.
func (d *Document) GetContainedPackagesFor(spdxID string) []*spdx.Package {
	var result []*spdx.Package
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsContainment() {
			for _, to := range rel.To {
				if pkg := d.GetPackageByID(to.GetSpdxID()); pkg != nil {
					result = append(result, pkg)
				}
			}
		}
	}
	return result
}

// ContainmentInfo holds containment information for an element including completeness.
type ContainmentInfo struct {
	Files        []*spdx.File
	Packages     []*spdx.Package
	Completeness *spdx.RelationshipCompleteness
}

// GetContainmentFor returns containment info including files, packages, and completeness.
func (d *Document) GetContainmentFor(spdxID string) *ContainmentInfo {
	info := &ContainmentInfo{}
	for _, rel := range d.GetRelationshipsFrom(spdxID) {
		if rel.IsContainment() {
			// Capture completeness from the first containment relationship
			if info.Completeness == nil && rel.Completeness != nil {
				info.Completeness = rel.Completeness
			}
			for _, to := range rel.To {
				if file := d.GetFileByID(to.GetSpdxID()); file != nil {
					info.Files = append(info.Files, file)
				} else if pkg := d.GetPackageByID(to.GetSpdxID()); pkg != nil {
					info.Packages = append(info.Packages, pkg)
				}
			}
		}
	}
	return info
}
