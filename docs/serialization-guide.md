# Serialization Guide

> **Use case:** You have an SPDX document in memory and want to write it back out as valid JSON-LD.
>
> **Not what you're looking for?** See [Serialization Deep Dive](serialization-deep-dive.md) for how the serializer works internally, or [Serialization Design](serialization-design.md) for contributor-facing architecture.

## Table of Contents

- [Quick Start](#quick-start)
- [Cookbook](#cookbook)
- [What You Don't Need to Worry About](#what-you-dont-need-to-worry-about)
- [Current Limitations](#current-limitations)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## Quick Start

```go
package main

import (
    "log"

    "github.com/interlynk-io/spdx-zen/parse"
    "github.com/interlynk-io/spdx-zen/serialize"
)

func main() {
    // Read
    doc, err := parse.NewReader().ReadFile("input.spdx.json")
    if err != nil {
        log.Fatal(err)
    }

    // Modify (optional)
    doc.SpdxDocument[0].Name = "Updated SBOM"

    // Write — compact output
    if err := serialize.NewWriter().WriteFile(doc, "output.spdx.json"); err != nil {
        log.Fatal(err)
    }

    // Or pretty-printed
    writer := serialize.NewWriter(serialize.WithIndent("  "))
    if err := writer.WriteFile(doc, "pretty.spdx.json"); err != nil {
        log.Fatal(err)
    }
}
```

**Round-trip in one expression:**

```go
serialize.NewWriter().WriteFile(
    must(parse.NewReader().ReadFile("in.spdx.json")),
    "out.spdx.json",
)
```

## Cookbook

### Filter Packages Before Writing

Only serialize packages that have a download location:

```go
var kept []spdx.Package
for _, pkg := range doc.Packages {
    if pkg.DownloadLocation != "" {
        kept = append(kept, pkg)
    }
}
doc.Packages = kept
serialize.NewWriter().WriteFile(doc, "filtered.spdx.json")
```

### Add a Relationship

```go
newRel := spdx.Relationship{
    Element: spdx.Element{
        SpdxID:   "https://example.org/rel-new",
        Name:     "doc-to-new-pkg",
    },
    RelationshipType: spdx.RelationshipTypeDescribes,
    From:             spdx.Element{SpdxID: doc.SpdxDocument[0].SpdxID},
    To:               []spdx.Element{{SpdxID: newPkg.SpdxID}},
}
doc.Relationships = append(doc.Relationships, newRel)
serialize.NewWriter().WriteFile(doc, "with-rel.spdx.json")
```

### Update All Package Versions

```go
for i := range doc.Packages {
    doc.Packages[i].PackageVersion = "2.0.0"
}
serialize.NewWriter().WriteFile(doc, "bumped.spdx.json")
```

### Write to `io.Writer` Instead of File

```go
writer := serialize.NewWriter(serialize.WithIndent("\t"))
if err := writer.Write(doc, os.Stdout); err != nil {
    log.Fatal(err)
}
```

### Verify Round-Trip Correctness

```go
reader := parse.NewReader()

// Parse original
original, _ := reader.ReadFile("original.spdx.json")

// Serialize
serialize.NewWriter().WriteFile(original, "roundtrip.spdx.json")

// Parse again
roundtrip, _ := reader.ReadFile("roundtrip.spdx.json")
```

## What You Don't Need to Worry About

The serializer handles these automatically. You build plain Go structs; the serializer takes care of the JSON-LD details.

| Concern | What the Serializer Does For You |
|---|---|
| **Field prefixes** | Core fields stay bare (`name`, `spdxId`); profile fields get their namespace prefix (`software_downloadLocation`, `security_publishedTime`) |
| **`"type"` fields** | Injected automatically for every element based on its Go type |
| **CreationInfo deduplication** | Identical `CreationInfo` blocks are extracted into shared blank nodes (`_:creationinfo`) so they don't repeat 500 times |
| **References** | Nested `Element` structs become string IDs in JSON-LD — no manual `.SpdxID` extraction needed |
| **Value objects** | `Hash` and `PackageVerificationCode` get their `"type"` injected even though they have no `spdxId` |
| **Zero-value times** | Unset `time.Time` fields are stripped — no `"0001-01-01T00:00:00Z"` in your output |
| **All profiles** | Software, Security, Licensing, AI, Dataset, Build — all serialize correctly with correct prefixes |

If you want to understand **how** any of this works, read the [Serialization Deep Dive](serialization-deep-dive.md).

## Current Limitations

| Limitation | Impact | Workaround |
|---|---|---|
| **No semantic field ordering** | Fields appear in Go struct order, not logical order (`spdxId` → `type` → `name`). Only affects human readability. | Post-process with `jq` if display order matters |
| **No pre-write validation** | A relationship can reference a non-existent `SpdxID` and the serializer will emit it. | Validate references yourself with `doc.GetElementByID()` before writing |
| **Standard `@context` only** | Only `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` is emitted. | Manually patch the output if you need custom context extensions |

## API Reference

### `serialize.Writer`

```go
// Compact output (default)
writer := serialize.NewWriter()

// Pretty-printed output
writer := serialize.NewWriter(serialize.WithIndent("  "))

// Write to file
err := writer.WriteFile(doc, "output.spdx.json")

// Write to any io.Writer
err := writer.Write(doc, os.Stdout)
```

### Options

| Option | Description |
|---|---|
| `WithIndent(indent string)` | Pretty-print with the given indent string. Omit for compact (single-line) output. |

### Type Registry Helpers (for custom tooling)

```go
// Get the JSON-LD type string for a Go struct
typ, ok := serialize.GetJSONLDTypeString(spdx.Package{})
// typ == "software_Package", ok == true

// Check if a type is registered
if serialize.IsRegistered(spdx.File{}) {
    // ...
}
```

## Troubleshooting

### "I expected `downloadLocation` but the output has `software_downloadLocation`"

**This is correct.** The serializer applies the official SPDX JSON-LD prefixes. Core fields (`name`, `spdxId`, `type`) stay bare; profile fields carry their namespace prefix. The parser will read it back correctly.

### "CreationInfo appears as an inline object, not `_:creationinfo`"

Deduplication only fires when elements share the **same** `*spdx.CreationInfo` pointer or **identical** field values. If you construct elements with `&spdx.CreationInfo{...}` separately for each one, they're different pointers and won't deduplicate.

**Fix:** Share one pointer:

```go
ci := &spdx.CreationInfo{SpecVersion: "3.0.1", Created: now}
pkg1.CreationInfo = ci
pkg2.CreationInfo = ci // same pointer — will deduplicate
```

### "Output still has nested objects where I expected string references"

Only maps containing a `"spdxId"` key become string references. Value objects like `Hash` don't have `spdxId`, so they stay inline — which is correct JSON-LD.

### "My custom struct type isn't serializing with a `"type"` field"

Add it to the type registry in `serialize/types.go`:

```go
var goTypeToJSONLDTypeString = map[reflect.Type]string{
    reflect.TypeOf(spdx.MyCustomType{}): "myprofile_MyCustomType",
}
```

## Running the Examples

The `examples/serialize/` directory contains a complete round-trip demo plus 7 edge-case SPDX files:

```bash
cd examples/serialize
make run-pretty   # Pretty-print the minimal example
make roundtrip     # Parse → serialize → parse again
make clean         # Remove generated files
```

| File | What It Tests |
|---|---|
| `minimal.spdx3.json` | Package, File, Relationship, Organization, Tool |
| `edgecase-empty.spdx3.json` | Empty `@graph` — handles gracefully |
| `edgecase-multi-creationinfo.spdx3.json` | Multiple distinct CreationInfo blocks |
| `edgecase-references.spdx3.json` | Nested vs string references |
| `edgecase-security-profile.spdx3.json` | Security profile elements |
| `edgecase-licenses.spdx3.json` | License expressions, conjunctive sets |
| `edgecase-all-profiles.spdx3.json` | Software + Security + Licensing + AI |

## Further Reading

| Document | Audience | Content |
|---|---|---|
| **[Serialization Concepts](serialization-concepts.md)** | Anyone curious about internals | Bottom-up journey from JSON-LD output patterns to serializer design |
| **[README Quick Start](../README.md)** | New users | Installation, basic parse/write examples |
