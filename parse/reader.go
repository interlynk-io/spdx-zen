// Package parse provides parsing capabilities for SPDX 3.0 JSON-LD documents.
//
// The package supports reading SPDX documents from files or byte slices,
// parsing them into typed Go structures based on the SPDX 3.0.1 model.
//
// Example usage:
//
//	reader := parse.NewReader()
//	doc, err := reader.ReadFile("document.spdx.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Document: %s\n", doc.GetName())
package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse/internal/jsonld"
	"github.com/interlynk-io/spdx-zen/parse/internal/parser"
)

// Reader provides JSON-LD parsing capabilities for SPDX 3.0 documents.
type Reader struct {
	processor *jsonld.Processor
	parser    *parser.ElementParser
	fileRead  func(string) ([]byte, error)
}

// Option configures a Reader.
type Option interface {
	apply(*Reader)
}

type optionFunc func(*Reader)

func (f optionFunc) apply(r *Reader) { f(r) }

// WithDocumentLoader sets a custom JSON-LD document loader.
// This is useful for testing or for providing custom context resolution.
func WithDocumentLoader(loader jsonld.DocumentLoader) Option {
	return optionFunc(func(r *Reader) {
		r.processor = jsonld.NewProcessor(loader)
	})
}

// WithFileReader sets a custom file reader function.
// This is useful for testing or for reading from custom sources.
func WithFileReader(readFn func(string) ([]byte, error)) Option {
	return optionFunc(func(r *Reader) {
		r.fileRead = readFn
	})
}

// NewReader creates a new SPDX JSON-LD reader with the given options.
func NewReader(opts ...Option) *Reader {
	r := &Reader{
		processor: jsonld.NewProcessor(jsonld.NewFallbackLoader()),
		parser:    parser.NewElementParser(),
		fileRead:  os.ReadFile,
	}

	for _, opt := range opts {
		opt.apply(r)
	}

	return r
}

// ReadFile reads and parses an SPDX JSON-LD file from the given path.
func (r *Reader) ReadFile(filePath string) (*Document, error) {
	data, err := r.fileRead(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	return r.Read(data)
}

// FromReader reads and parses an SPDX JSON-LD document from an io.Reader.
func (r *Reader) FromReader(reader io.Reader) (*Document, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	return r.Read(data)
}

// Read parses SPDX JSON-LD data from bytes.
func (r *Reader) Read(data []byte) (*Document, error) {
	var rawDoc interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	return r.parse(rawDoc)
}

// parse processes the raw JSON-LD document.
func (r *Reader) parse(rawDoc interface{}) (*Document, error) {
	docMap, ok := rawDoc.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("document is not a JSON object")
	}

	doc := &Document{
		ElementsByID:                             make(map[string]interface{}),
		RelationshipsFromIndex:                   make(map[string][]*spdx.Relationship),
		RelationshipsToIndex:                     make(map[string][]*spdx.Relationship),
		PackagesByID:                             make(map[string]*spdx.Package),
		FilesByID:                                make(map[string]*spdx.File),
		OrganizationsByID:                        make(map[string]*spdx.Organization),
		PersonsByID:                              make(map[string]*spdx.Person),
		SoftwareAgentsByID:                       make(map[string]*spdx.SoftwareAgent),
		ToolsByID:                                make(map[string]*spdx.Tool),
		AnyLicenseInfosByID:                      make(map[string]*spdx.AnyLicenseInfo),
		ConjunctiveLicenseSetsByID:               make(map[string]*spdx.ConjunctiveLicenseSet),
		CustomLicensesByID:                       make(map[string]*spdx.CustomLicense),
		CustomLicenseAdditionsByID:               make(map[string]*spdx.CustomLicenseAddition),
		DisjunctiveLicenseSetsByID:               make(map[string]*spdx.DisjunctiveLicenseSet),
		IndividualLicensingInfosByID:             make(map[string]*spdx.IndividualLicensingInfo),
		ListedLicensesByID:                       make(map[string]*spdx.ListedLicense),
		ListedLicenseExceptionsByID:              make(map[string]*spdx.ListedLicenseException),
		LicenseExpressionsByID:                   make(map[string]*spdx.LicenseExpression),
		OrLaterOperatorsByID:                     make(map[string]*spdx.OrLaterOperator),
		SimpleLicensingTextsByID:                 make(map[string]*spdx.SimpleLicensingText),
		WithAdditionOperatorsByID:                make(map[string]*spdx.WithAdditionOperator),
		VulnerabilitiesByID:                      make(map[string]*spdx.Vulnerability),
		CvssV2VulnAssessmentsByID:                make(map[string]*spdx.CvssV2VulnAssessmentRelationship),
		CvssV3VulnAssessmentsByID:                make(map[string]*spdx.CvssV3VulnAssessmentRelationship),
		CvssV4VulnAssessmentsByID:                make(map[string]*spdx.CvssV4VulnAssessmentRelationship),
		EpssVulnAssessmentsByID:                  make(map[string]*spdx.EpssVulnAssessmentRelationship),
		SsvcVulnAssessmentsByID:                  make(map[string]*spdx.SsvcVulnAssessmentRelationship),
		ExploitCatalogVulnAssessmentsByID:        make(map[string]*spdx.ExploitCatalogVulnAssessmentRelationship),
		VexAffectedVulnAssessmentsByID:           make(map[string]*spdx.VexAffectedVulnAssessmentRelationship),
		VexFixedVulnAssessmentsByID:              make(map[string]*spdx.VexFixedVulnAssessmentRelationship),
		VexNotAffectedVulnAssessmentsByID:        make(map[string]*spdx.VexNotAffectedVulnAssessmentRelationship),
		VexUnderInvestigationVulnAssessmentsByID: make(map[string]*spdx.VexUnderInvestigationVulnAssessmentRelationship),
		AiPackagesByID:                           make(map[string]*spdx.AIPackage),
		EnergyConsumptionsByID:                   make(map[string]*spdx.EnergyConsumption),
		EnergyConsumptionDescriptionsByID:        make(map[string]*spdx.EnergyConsumptionDescription),
		DatasetPackagesByID:                      make(map[string]*spdx.DatasetPackage),
		BuildsByID:                               make(map[string]*spdx.Build),
	}

	// Extract @context
	if ctx, ok := docMap["@context"]; ok {
		doc.Context = r.parseContext(ctx)
	}

	// Extract and parse @graph
	graph, ok := docMap["@graph"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("document does not contain @graph array")
	}

	// First pass: categorize and count elements
	for _, elem := range graph {
		elemMap, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}

		elemType := r.getElementType(elemMap)

		// Get SPDX ID if available
		if spdxID, ok := elemMap["spdxId"].(string); ok {
			doc.ElementsByID[spdxID] = elemMap
		}

		// Parse and categorize by type
		r.categorizeElement(doc, elemMap, elemType)
	}

	// Build relationship indexes for O(1) lookups
	for _, rel := range doc.Relationships {
		fromID := rel.From.GetSpdxID()
		doc.RelationshipsFromIndex[fromID] = append(doc.RelationshipsFromIndex[fromID], rel)
		for _, to := range rel.To {
			toID := to.GetSpdxID()
			doc.RelationshipsToIndex[toID] = append(doc.RelationshipsToIndex[toID], rel)
		}
	}

	return doc, nil
}

// parseContext extracts context URLs from the @context field.
func (r *Reader) parseContext(ctx interface{}) []string {
	var contexts []string

	switch c := ctx.(type) {
	case string:
		contexts = append(contexts, c)
	case []interface{}:
		for _, item := range c {
			if s, ok := item.(string); ok {
				contexts = append(contexts, s)
			}
		}
	}

	return contexts
}

// getElementType extracts the element type from a map.
func (r *Reader) getElementType(elemMap map[string]interface{}) ElementType {
	if typeVal, ok := elemMap["type"].(string); ok {
		return ElementType(typeVal)
	}
	return ""
}

// categorizeElement parses and categorizes an element based on its type.
func (r *Reader) categorizeElement(doc *Document, elemMap map[string]interface{}, elemType ElementType) {
	if r.handleCoreElements(doc, elemMap, elemType) {
		return
	}
	if r.handleSoftwareElements(doc, elemMap, elemType) {
		return
	}
	if r.handleLicensingElements(doc, elemMap, elemType) {
		return
	}
	if r.handleSecurityElements(doc, elemMap, elemType) {
		return
	}
	// Add new handlers here
	if r.handleAiElements(doc, elemMap, elemType) {
		return
	}
	if r.handleDatasetElements(doc, elemMap, elemType) {
		return
	}
	if r.handleBuildElements(doc, elemMap, elemType) {
		return
	}
}

func (r *Reader) handleCoreElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	switch elemType {
	case TypeSpdxDocument:
		doc.SpdxDocument = r.parser.ParseSpdxDocument(elemMap)
	case TypeRelationship:
		doc.Relationships = append(doc.Relationships, r.parser.ParseRelationship(elemMap))
	case TypeLifecycleScopedRelationship:
		doc.LifecycleScopedRelationships = append(doc.LifecycleScopedRelationships, r.parser.ParseLifecycleScopedRelationship(elemMap))
	case TypeAnnotation:
		doc.Annotations = append(doc.Annotations, r.parser.ParseAnnotation(elemMap))
	case TypeExternalMap:
		doc.ExternalMaps = append(doc.ExternalMaps, r.parser.ParseExternalMap(elemMap))
	case TypeCreationInfo:
		doc.CreationInfo = r.parser.ParseCreationInfo(elemMap)
	case TypeOrganization:
		org := r.parser.ParseOrganization(elemMap)
		doc.Organizations = append(doc.Organizations, org)
		if org.SpdxID != "" {
			doc.OrganizationsByID[org.SpdxID] = org
		}
	case TypePerson:
		person := r.parser.ParsePerson(elemMap)
		doc.Persons = append(doc.Persons, person)
		if person.SpdxID != "" {
			doc.PersonsByID[person.SpdxID] = person
		}
	case TypeSoftwareAgent:
		sa := r.parser.ParseSoftwareAgent(elemMap)
		doc.SoftwareAgents = append(doc.SoftwareAgents, sa)
		if sa.SpdxID != "" {
			doc.SoftwareAgentsByID[sa.SpdxID] = sa
		}
	case TypeTool:
		tool := r.parser.ParseTool(elemMap)
		doc.Tools = append(doc.Tools, tool)
		if tool.SpdxID != "" {
			doc.ToolsByID[tool.SpdxID] = tool
		}
	case TypeBom:
		bom := r.parser.ParseBom(elemMap)
		doc.Boms = append(doc.Boms, bom)
	case TypeBundle:
		bundle := r.parser.ParseBundle(elemMap)
		doc.Bundles = append(doc.Bundles, bundle)
	case TypeDictionaryEntry:
		de := r.parser.ParseDictionaryEntry(elemMap)
		doc.DictionaryEntries = append(doc.DictionaryEntries, de)
	case TypeHash:
		hash := r.parser.ParseHash(elemMap)
		doc.Hashes = append(doc.Hashes, hash)
	case TypePackageVerificationCode:
		pvc := r.parser.ParsePackageVerificationCode(elemMap)
		doc.PackageVerificationCodes = append(doc.PackageVerificationCodes, pvc)
	default:
		return false
	}
	return true
}

func (r *Reader) handleSoftwareElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	switch elemType {
	case TypeSoftwarePackage:
		pkg := r.parser.ParsePackage(elemMap)
		doc.Packages = append(doc.Packages, pkg)
		if pkg.SpdxID != "" {
			doc.PackagesByID[pkg.SpdxID] = pkg
		}
	case TypeSoftwareFile:
		file := r.parser.ParseFile(elemMap)
		doc.Files = append(doc.Files, file)
		if file.SpdxID != "" {
			doc.FilesByID[file.SpdxID] = file
		}
	case TypeSoftwareSnippet:
		doc.Snippets = append(doc.Snippets, r.parser.ParseSnippet(elemMap))
	case TypeSoftwareSbom:
		sbom := r.parser.ParseSbom(elemMap)
		doc.Boms = append(doc.Boms, &sbom.Bom)
	default:
		return false
	}
	return true
}

func (r *Reader) handleLicensingElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	spdxID := r.parser.H.GetString(elemMap, "spdxId")

	switch elemType {
	case TypeAnyLicenseInfo:
		lic := r.parser.ParseAnyLicenseInfo(elemMap)
		doc.AnyLicenseInfos = append(doc.AnyLicenseInfos, lic)
		if spdxID != "" {
			doc.AnyLicenseInfosByID[spdxID] = lic
		}
	case TypeConjunctiveLicenseSet:
		cls := r.parser.ParseConjunctiveLicenseSet(elemMap)
		doc.ConjunctiveLicenseSets = append(doc.ConjunctiveLicenseSets, cls)
		if spdxID != "" {
			doc.ConjunctiveLicenseSetsByID[spdxID] = cls
		}
	case TypeCustomLicense:
		cl := r.parser.ParseCustomLicense(elemMap)
		doc.CustomLicenses = append(doc.CustomLicenses, cl)
		if spdxID != "" {
			doc.CustomLicensesByID[spdxID] = cl
		}
	case TypeLicenseAddition:
		cla := r.parser.ParseCustomLicenseAddition(elemMap)
		doc.CustomLicenseAdditions = append(doc.CustomLicenseAdditions, cla)
		if spdxID != "" {
			doc.CustomLicenseAdditionsByID[spdxID] = cla
		}
	case TypeDisjunctiveLicenseSet:
		dls := r.parser.ParseDisjunctiveLicenseSet(elemMap)
		doc.DisjunctiveLicenseSets = append(doc.DisjunctiveLicenseSets, dls)
		if spdxID != "" {
			doc.DisjunctiveLicenseSetsByID[spdxID] = dls
		}
	case TypeIndividualLicensingInfo: // Moved from handleCoreElements
		ili := r.parser.ParseIndividualLicensingInfo(elemMap)
		doc.IndividualLicensingInfos = append(doc.IndividualLicensingInfos, ili)
		if spdxID != "" {
			doc.IndividualLicensingInfosByID[spdxID] = ili
		}
	case TypeListedLicense:
		ll := r.parser.ParseListedLicense(elemMap)
		doc.ListedLicenses = append(doc.ListedLicenses, ll)
		if spdxID != "" {
			doc.ListedLicensesByID[spdxID] = ll
		}
	case TypeListedLicenseException:
		lle := r.parser.ParseListedLicenseException(elemMap)
		doc.ListedLicenseExceptions = append(doc.ListedLicenseExceptions, lle)
		if spdxID != "" {
			doc.ListedLicenseExceptionsByID[spdxID] = lle
		}
	case TypeLicenseExpression:
		le := r.parser.ParseLicenseExpression(elemMap)
		doc.LicenseExpressions = append(doc.LicenseExpressions, le)
		if spdxID != "" {
			doc.LicenseExpressionsByID[spdxID] = le
		}
	case TypeOrLaterOperator:
		olo := r.parser.ParseOrLaterOperator(elemMap)
		doc.OrLaterOperators = append(doc.OrLaterOperators, olo)
		if spdxID != "" {
			doc.OrLaterOperatorsByID[spdxID] = olo
		}
	case TypeSimpleLicensingText:
		slt := r.parser.ParseSimpleLicensingText(elemMap)
		doc.SimpleLicensingTexts = append(doc.SimpleLicensingTexts, slt)
		if spdxID != "" {
			doc.SimpleLicensingTextsByID[spdxID] = slt
		}
	case TypeWithAdditionOperator:
		wao := r.parser.ParseWithAdditionOperator(elemMap)
		doc.WithAdditionOperators = append(doc.WithAdditionOperators, wao)
		if spdxID != "" {
			doc.WithAdditionOperatorsByID[spdxID] = wao
		}
	default:
		return false
	}
	return true
}

func (r *Reader) handleSecurityElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	switch elemType {
	case TypeVulnerability:
		vuln := r.parser.ParseVulnerability(elemMap)
		doc.Vulnerabilities = append(doc.Vulnerabilities, vuln)
		if vuln.SpdxID != "" {
			doc.VulnerabilitiesByID[vuln.SpdxID] = vuln
		}
	case TypeCvssV2VulnAssessment:
		cvss2 := r.parser.ParseCvssV2VulnAssessmentRelationship(elemMap)
		doc.CvssV2VulnAssessments = append(doc.CvssV2VulnAssessments, cvss2)
		if cvss2.SpdxID != "" {
			doc.CvssV2VulnAssessmentsByID[cvss2.SpdxID] = cvss2
		}
	case TypeCvssV3VulnAssessment:
		cvss3 := r.parser.ParseCvssV3VulnAssessmentRelationship(elemMap)
		doc.CvssV3VulnAssessments = append(doc.CvssV3VulnAssessments, cvss3)
		if cvss3.SpdxID != "" {
			doc.CvssV3VulnAssessmentsByID[cvss3.SpdxID] = cvss3
		}
	case TypeCvssV4VulnAssessment:
		cvss4 := r.parser.ParseCvssV4VulnAssessmentRelationship(elemMap)
		doc.CvssV4VulnAssessments = append(doc.CvssV4VulnAssessments, cvss4)
		if cvss4.SpdxID != "" {
			doc.CvssV4VulnAssessmentsByID[cvss4.SpdxID] = cvss4
		}
	case TypeEpssVulnAssessment:
		epss := r.parser.ParseEpssVulnAssessmentRelationship(elemMap)
		doc.EpssVulnAssessments = append(doc.EpssVulnAssessments, epss)
		if epss.SpdxID != "" {
			doc.EpssVulnAssessmentsByID[epss.SpdxID] = epss
		}
	case TypeSsvcVulnAssessment:
		ssvc := r.parser.ParseSsvcVulnAssessmentRelationship(elemMap)
		doc.SsvcVulnAssessments = append(doc.SsvcVulnAssessments, ssvc)
		if ssvc.SpdxID != "" {
			doc.SsvcVulnAssessmentsByID[ssvc.SpdxID] = ssvc
		}
	case TypeExploitCatalogVulnAssessment:
		ec := r.parser.ParseExploitCatalogVulnAssessmentRelationship(elemMap)
		doc.ExploitCatalogVulnAssessments = append(doc.ExploitCatalogVulnAssessments, ec)
		if ec.SpdxID != "" {
			doc.ExploitCatalogVulnAssessmentsByID[ec.SpdxID] = ec
		}
	case TypeVexAffectedVulnAssessment:
		vexAffected := r.parser.ParseVexAffectedVulnAssessmentRelationship(elemMap)
		doc.VexAffectedVulnAssessments = append(doc.VexAffectedVulnAssessments, vexAffected)
		if vexAffected.SpdxID != "" {
			doc.VexAffectedVulnAssessmentsByID[vexAffected.SpdxID] = vexAffected
		}
	case TypeVexFixedVulnAssessment:
		vexFixed := r.parser.ParseVexFixedVulnAssessmentRelationship(elemMap)
		doc.VexFixedVulnAssessments = append(doc.VexFixedVulnAssessments, vexFixed)
		if vexFixed.SpdxID != "" {
			doc.VexFixedVulnAssessmentsByID[vexFixed.SpdxID] = vexFixed
		}
	case TypeVexNotAffectedVulnAssessment:
		vexNotAffected := r.parser.ParseVexNotAffectedVulnAssessmentRelationship(elemMap)
		doc.VexNotAffectedVulnAssessments = append(doc.VexNotAffectedVulnAssessments, vexNotAffected)
		if vexNotAffected.SpdxID != "" {
			doc.VexNotAffectedVulnAssessmentsByID[vexNotAffected.SpdxID] = vexNotAffected
		}
	case TypeVexUnderInvestigationVulnAssessment:
		vexUnderInvestigation := r.parser.ParseVexUnderInvestigationVulnAssessmentRelationship(elemMap)
		doc.VexUnderInvestigationVulnAssessments = append(doc.VexUnderInvestigationVulnAssessments, vexUnderInvestigation)
		if vexUnderInvestigation.SpdxID != "" {
			doc.VexUnderInvestigationVulnAssessmentsByID[vexUnderInvestigation.SpdxID] = vexUnderInvestigation
		}
	default:
		return false
	}
	return true
}

func (r *Reader) handleAiElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	spdxID := r.parser.H.GetString(elemMap, "spdxId")

	switch elemType {
	case TypeAIPackage:
		aiPkg := r.parser.ParseAIPackage(elemMap)
		doc.AiPackages = append(doc.AiPackages, aiPkg)
		if spdxID != "" {
			doc.AiPackagesByID[spdxID] = aiPkg
		}
	case TypeEnergyConsumption:
		ec := r.parser.ParseEnergyConsumption(elemMap)
		doc.EnergyConsumptions = append(doc.EnergyConsumptions, ec)
		if spdxID != "" {
			doc.EnergyConsumptionsByID[spdxID] = ec
		}
	case TypeEnergyConsumptionDescription:
		ecd := r.parser.ParseEnergyConsumptionDescription(elemMap)
		doc.EnergyConsumptionDescriptions = append(doc.EnergyConsumptionDescriptions, ecd)
		if spdxID != "" {
			doc.EnergyConsumptionDescriptionsByID[spdxID] = ecd
		}
	default:
		return false
	}
	return true
}

func (r *Reader) handleDatasetElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	spdxID := r.parser.H.GetString(elemMap, "spdxId")

	switch elemType {
	case TypeDataset: // Note: uses TypeDataset but parses into DatasetPackage
		datasetPkg := r.parser.ParseDatasetPackage(elemMap)
		doc.DatasetPackages = append(doc.DatasetPackages, datasetPkg)
		if spdxID != "" {
			doc.DatasetPackagesByID[spdxID] = datasetPkg
		}
	default:
		return false
	}
	return true
}

func (r *Reader) handleBuildElements(doc *Document, elemMap map[string]interface{}, elemType ElementType) bool {
	spdxID := r.parser.H.GetString(elemMap, "spdxId")

	switch elemType {
	case TypeBuild:
		build := r.parser.ParseBuild(elemMap)
		doc.Builds = append(doc.Builds, build)
		if spdxID != "" {
			doc.BuildsByID[spdxID] = build
		}
	default:
		return false
	}
	return true
}

// Expand uses JSON-LD expansion on the document.
func (r *Reader) Expand(data []byte) ([]interface{}, error) {
	var rawDoc interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	expanded, err := r.processor.Expand(rawDoc)
	if err != nil {
		return nil, fmt.Errorf("expanding JSON-LD: %w", err)
	}

	return expanded, nil
}

// Flatten uses JSON-LD flattening on the document.
func (r *Reader) Flatten(data []byte) (interface{}, error) {
	var rawDoc interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	flattened, err := r.processor.Flatten(rawDoc)
	if err != nil {
		return nil, fmt.Errorf("flattening JSON-LD: %w", err)
	}

	return flattened, nil
}

// Compact uses JSON-LD compaction on the document.
func (r *Reader) Compact(data []byte, context interface{}) (interface{}, error) {
	var rawDoc interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	compacted, err := r.processor.Compact(rawDoc, context)
	if err != nil {
		return nil, fmt.Errorf("compacting JSON-LD: %w", err)
	}

	return compacted, nil
}
