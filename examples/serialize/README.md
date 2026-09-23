# SPDX 3.0 JSON-LD Serialization Example

This directory demonstrates the complete SPDX 3.0 JSON-LD round-trip workflow:

```text
SPDX JSON-LD file → parse.Reader → *parse.Document → serialize.Writer → SPDX JSON-LD file
```

## Files

| File | Description |
|------|-------------|
| `main.go` | Example program: parses an SPDX file and serializes it back out |
| `minimal.spdx3.json` | Minimal but valid SPDX 3.0 JSON-LD document (8 elements) |
| `Makefile` | Convenience targets for running the demo |

## The Minimal Example Document

`minimal.spdx3.json` contains:

- **1 SpdxDocument** — the root document
- **1 Organization** — the supplier
- **1 Tool** — the generator
- **1 Package** — `example-package` v1.0.0 (with a Hash in `verifiedUsing`)
- **1 File** — `main.go` (with a Hash in `verifiedUsing`)
- **2 Relationships** — `describes` and `contains`
- **1 shared CreationInfo** — referenced as `_:creationinfo` by all elements

This covers all the key serialization concepts:

- Element reference emission (`from`, `to`, `suppliedBy`)
- Value objects staying inline (`Hash` in `verifiedUsing`)
- CreationInfo blank node deduplication
- Profile field prefixing (`software_packageVersion`, `software_downloadLocation`)

## Edge Case Test Documents

The following files test specific serializer behaviors:

| File | What It Tests |
|------|--------------|
| `edgecase-empty.spdx3.json` | Minimal document with just SpdxDocument + Tool (no packages/files) |
| `edgecase-multi-creationinfo.spdx3.json` | Multiple CreationInfo blank nodes (`_:creationinfo` + `_:creationinfo2`) |
| `edgecase-references.spdx3.json` | All reference types: `from`, `to`, `originatedBy`, `suppliedBy`, `subject` (Annotation), `scope` (LifecycleScopedRelationship) |
| `edgecase-security-profile.spdx3.json` | Security profile elements: `security_Vulnerability`, `security_CvssV3VulnAssessmentRelationship`, `security_VexAffectedVulnAssessmentRelationship` |
| `edgecase-licenses.spdx3.json` | Licensing profile: `ListedLicense`, `simplelicensing_LicenseExpression`, `ConjunctiveLicenseSet`, license relationships |
| `edgecase-all-profiles.spdx3.json` | AI (`ai_AIPackage`), Dataset (`dataset_Dataset`), and Build (`build_Build`) profile elements |

### Running Edge Cases

```bash
cd examples/serialize

# Test each edge case
for f in edgecase-*.spdx3.json; do
    echo "=== $f ==="
    go run main.go -input "$f" -output /tmp/"$f" -pretty
done
```

## Running the Example

### Parse and serialize to a file

```bash
cd examples/serialize
go run main.go -input minimal.spdx3.json -output output.spdx3.json
```

o/p:

```bash
Parsing: minimal.spdx3.json

=== Parsed Document Summary ===
  Document:     Minimal Example SBOM
  Spec Version: 3.0.1
  Packages:     1
  Files:        1
  Relationships:2
  ...
================================

Serializing...
Writing to: output.spdx3.json
Done!
```

### Pretty-print to stdout

```bash
go run main.go -input minimal.spdx3.json -pretty
```

### Use with the real-world example

```bash
# From the repo root
go run examples/serialize/main.go \
    -input examplemaven-0.0.1.spdx3.json \
    -output /tmp/examplemaven-out.spdx3.json \
    -pretty
```

### Makefile targets

```bash
make run         # Parse + serialize to output.spdx3.json
make run-pretty  # Parse + pretty-print to stdout
make roundtrip   # Parse → serialize → parse again (validates round-trip)
make clean       # Remove output.spdx3.json
```

## What the Example Demonstrates

### 1. Parse → Go structs

The `parse.Reader` reads the JSON-LD `@graph` and populates typed Go slices:

```go
reader := parse.NewReader()
doc, err := reader.ReadFile("minimal.spdx3.json")
// doc.Packages, doc.Files, doc.Relationships, etc.
```

### 2. Serialize → JSON-LD

The `serialize.Writer` converts Go structs back to JSON-LD:

```go
writer := serialize.NewWriter(serialize.WithIndent("\t"))
err := writer.Write(doc, os.Stdout)
```