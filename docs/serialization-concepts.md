# How SPDX 3.0 JSON-LD Serialization Works

> A bottom-up journey: from what you see in the final JSON-LD output, to what lives in Go memory, to how the serializer bridges the two.

## Part 1: Observing the Final Output

Before we talk about code, let's look at what a serialized SPDX 3.0 document actually looks like. Here is a single element from a valid JSON-LD `@graph`:

```json
{
  "type": "software_Package",
  "spdxId": "https://example.org/pkg1",
  "name": "my-package",
  "creationInfo": "_:creationinfo",
  "software_downloadLocation": "https://example.org/pkg1.tgz",
  "software_packageVersion": "1.0.0",
  "software_primaryPurpose": "library",
  "suppliedBy": "https://example.org/org1",
  "verifiedUsing": [{
    "type": "Hash",
    "algorithm": "sha256",
    "hashValue": "e3b0c44298fc..."
  }]
}
```

## 2. Output Structure

```json
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "name": "My SBOM",
      "creationInfo": "_:creationinfo",
      ...
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "my-package",
      "creationInfo": "_:creationinfo",
      "software_downloadLocation": "https://example.org/pkg1.tgz",
      "software_packageVersion": "1.0.0",
      "software_primaryPurpose": "library",
      "suppliedBy": "https://example.org/org1",
      "verifiedUsing": [{
        "type": "Hash",
        "algorithm": "sha256",
        "hashValue": "e3b0c44298fc..."
      }]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "SPDX-3.0.1",
      "created": "2024-01-15T10:00:00Z",
      "createdBy": ["https://example.org/org1"]
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel1",
      "from": "https://example.org/doc1",
      "to": ["https://example.org/pkg1"],
      "relationshipType": "describes",
      "creationInfo": "_:creationinfo"
    }
  ]
}
```

And here is a `Relationship` element from the same document:

```json
{
  "type": "Relationship",
  "spdxId": "https://example.org/rel1",
  "relationshipType": "describes",
  "from": "https://example.org/doc1",
  "to": ["https://example.org/pkg1"],
  "creationInfo": "_:creationinfo"
}
```

If we study these outputs carefully, we notice a consistent set of patterns:

### 1. Every element has a `"type"` field

`software_Package`, `Relationship`, `CreationInfo`, `Hash` — every object declares what it is.

### 2. Most top-level elements have `"spdxId"`

The Package has `spdxId`. The Relationship has `spdxId`. But `Hash` (inside `verifiedUsing`) does not — it is a **value object**, not an independently addressable element.

### 3. Core properties are bare; profile properties are prefixed

`name`, `spdxId`, `creationInfo`, `type` appear as-is. But Software-specific properties carry the `software_` prefix: `software_downloadLocation`, `software_packageVersion`, `software_primaryPurpose`.

### 4. References between elements are string IDs, not nested objects

`from` is `"https://example.org/doc1"` — a string. `to` is `["https://example.org/pkg1"]` — an array of strings. `suppliedBy` is `"https://example.org/org1"`. There are no inline objects with `spdxId` inside them.

### 5. `CreationInfo` is a blank node reference, not an inline object

`"creationInfo": "_:creationinfo"` — a string pointing to a shared blank node elsewhere in the `@graph`. It is not the full `CreationInfo` struct inlined here.

### 6. Value objects have `"type"` but no `spdxId`

The `Hash` inside `verifiedUsing` has `"type": "Hash"`, but it is not a top-level `@graph` entry. It is nested inline because it has no independent identity.

### 7. No bogus timestamps

You will never see `"0001-01-01T00:00:00Z"` in valid SPDX output. Unset timestamps simply do not appear.

## Part 2: What We Have in Go Memory

Now let's look at what the parser gives us. After calling `parse.NewReader().ReadFile(...)`, we have a `*parse.Document` — a collection of typed slices holding plain Go structs.

```go
type Document struct {
    SpdxDocument   []SpdxDocument
    Packages       []Package
    Files          []File
    Relationships  []Relationship
    Organizations  []Organization
    // ... 40+ more slices
}
```

Each struct looks like this:

```go
type Package struct {
    Element                         // embedded: SpdxID, Name, CreationInfo
    DownloadLocation  string        `json:"downloadLocation,omitempty"`
    PackageVersion    string        `json:"packageVersion,omitempty"`
    PrimaryPurpose    string        `json:"primaryPurpose,omitempty"`
}
```

If we compare this to the JSON-LD output above, we see **seven fundamental mismatches**:

| What JSON-LD Expects | What Go Gives Us |
|---|---|
| Flat `@graph` array | Typed slices (`Packages`, `Files`, etc.) |
| Prefixed profile fields (`software_downloadLocation`) | Bare field names (`DownloadLocation`) |
| `"type": "software_Package"` | No `Type` field on the struct |
| String references (`from: "..."`) | Nested struct references (`From Element`) |
| `CreationInfo` as blank node (`_:creationinfo`) | Inline `*CreationInfo` on every element |
| Value objects with `"type"` | Plain structs with no type annotation |
| No zero-value timestamps | `time.Time` zero values exist in memory |

These are not bugs. They are the natural consequence of two design decisions:

1. **The Go model is format-agnostic.** It represents the SPDX ontology, not JSON-LD. Bare names, no type fields, nested structs — these are clean Go idioms.
2. **JSON-LD is a serialization format.** It imposes conventions — prefixes, type fields, string references, blank nodes — that exist only at the serialization layer.

The serializer's job is to bridge these seven mismatches.

## Part 3: The Seven Challenges and How We Solve Them

### Challenge 1: Typed Slices → Flat `@graph`

**The problem.** The parser stores Packages in `doc.Packages`, Files in `doc.Files`, Relationships in `doc.Relationships`. JSON-LD requires one flat `@graph` array where every element is a peer.

**The solution: Flatten + Deduplicate by SpdxID.**

We walk every typed slice in a deterministic order and collect elements into a single `[]interface{}`. If an element appears in multiple slices (e.g., a Package in both `Packages` and `SoftwareArtifacts`), we deduplicate it using its `SpdxID` as the key. Elements without a `SpdxID` — value objects like `Hash` — are skipped. They are not independent `@graph` entries.

**Why SpdxID?** It is the only mandatory, globally unique identifier in SPDX 3.0.

### Challenge 2: Bare Names → Prefixed Names

**The problem.** The Go model uses bare ontology names: `DownloadLocation`, `PackageVersion`, `PrimaryPurpose`. JSON-LD consumers expect namespaced keys: `software_downloadLocation`, `software_packageVersion`, `software_primaryPurpose`.

**But here is the crucial insight: this is not an ontology requirement. It is a JSON-LD convention.**

In the SPDX ontology, the property is `downloadLocation`. Full stop. Its URI is `https://spdx.org/rdf/3.0.1/terms/Software/downloadLocation`. The namespace (`Software/`) and the local name (`downloadLocation`) together form the URI. The prefix `software_` does not exist in the ontology. It is a convenience invented by the JSON-LD serialization format so that humans can read the document and parsers can disambiguate which profile a field belongs to.

**The solution: A URI-based field prefix registry.**

The official SPDX JSON-LD field registry maps each bare field name to its full ontology URI. From the URI, we derive:

- The **namespace** (e.g., `Software`)
- The **prefix** (e.g., `software_`)
- The **bare field name** (e.g., `downloadLocation`)

During serialization, we look up each field in the registry. If it is found, we rename it with its prefix. If it is not found, it is a Core field (`name`, `spdxId`, `creationInfo`) and stays bare.

| Bare Field | Registry URI | Prefix | Serialized Key |
|---|---|---|---|
| `downloadLocation` | `.../terms/Software/downloadLocation` | `software_` | `software_downloadLocation` |
| `publishedTime` | `.../terms/Security/publishedTime` | `security_` | `security_publishedTime` |
| `name` | `.../terms/Core/name` | (none — Core) | `name` |

**Why derive from URI instead of hardcoding prefixes?** Because the registry is the single source of truth. If SPDX adds a new field in a future version, updating the registry automatically updates both parser and serializer. The ontology is the anchor; the prefix is derived.

### Challenge 3: No `Type` Field → `"type"` Injection

**The problem.** Go structs don't know their JSON-LD type name. A `spdx.Package` has no `Type` field. We need `"type": "software_Package"` in the output.

**The solution: A type registry.**

We maintain a map from Go `reflect.Type` to JSON-LD type string:

| Go Type | Injected `"type"` |
|---|---|
| `spdx.Package` | `"software_Package"` |
| `spdx.File` | `"software_File"` |
| `spdx.LicenseExpression` | `"simplelicensing_LicenseExpression"` |
| `spdx.Vulnerability` | `"security_Vulnerability"` |
| `spdx.Hash` | `"Hash"` |

**Why a registry?** Because Go type names and SPDX JSON-LD type names do not always align. `DatasetPackage` serializes as `"dataset_Dataset"`. `AIPackage` serializes as `"ai_AIPackage"`. A hardcoded convention (`lowercase + "_"`) would break on edge cases.

### Challenge 4: Nested Structs → String References

**The problem.** In memory, a `Relationship` holds actual `Element` structs:

```go
type Relationship struct {
    Element
    From Element
    To   []Element
}
```

If we naively marshal this, `From` becomes a nested object with `spdxId`, `name`, `type`, and everything else. But JSON-LD requires string IDs:

```json
"from": "https://example.org/doc1",
"to": ["https://example.org/pkg1"]
```

**The solution: A generic runtime reference emission rule.**

After marshaling a struct to a map, we recursively walk the map. Whenever we find a nested `map[string]interface{}` that contains a `"spdxId"` key, we replace the entire map with just that key's string value.

This handles **every** reference field automatically — `from`, `to`, `createdBy`, `originatedBy`, `rootElement`, `subject` — without hardcoding field names. If SPDX adds a new element type with a new reference field tomorrow, this code already handles it.

**The rule is simple:** *Any nested map with a `spdxId` becomes a string reference.*

**Edge case:** Value objects like `Hash` don't have `spdxId`, so the rule does not fire. They stay inline — correct behavior.

### Challenge 5: Inline `CreationInfo` → Blank Node References

**The problem.** Every SPDX element embeds a `*CreationInfo`. A document with 500 elements and one `CreationInfo` would, naively, emit that block 500 times. The output would be bloated and unidiomatic.

**The solution: Hash + deduplicate into shared blank nodes.**

SPDX 3.0 JSON-LD conventionally extracts identical `CreationInfo` objects into shared blank nodes:

```json
{
  "spdxId": "https://example.org/pkg1",
  "type": "software_Package",
  "creationInfo": "_:creationinfo"
}
```

The serializer hashes `CreationInfo` values by their content (`specVersion`, `created` timestamp, `createdBy` IDs, `createdUsing` IDs). Identical values receive the same blank node label. Even a single-use `CreationInfo` is emitted as a shared reference for consistency.

**Why blank nodes?** `CreationInfo` has no `SpdxID` in the SPDX model. It is metadata, not an independently addressable element. Blank nodes are JSON-LD's mechanism for shared anonymous resources.

**Alternative considered:** Inline `CreationInfo` on every element. Rejected because it produces unreadable output and violates SPDX spec conventions.

### Challenge 6: Value Objects Need `"type"` Too

**The problem.** `Hash` and `PackageVerificationCode` are not independent `@graph` elements (no `spdxId`), but JSON-LD consumers still need to know what they are. They need a `"type"` field.

**The solution: Signature-based detection.**

We detect value objects by their field signatures after marshaling:

- A map with `algorithm` and `hashValue` → inject `"type": "Hash"`
- A map with `packageVerificationCodeValue` → inject `"type": "PackageVerificationCode"`

**Why not add a `Type` field to the Go struct?** Because the Go model is format-agnostic. A `Hash` is a `Hash` regardless of serialization format. The `"type"` is a JSON-LD concern, not a domain concern.

### Challenge 7: Zero-Value Time Stamps Must Disappear

**The problem.** Go's `time.Time` zero value is `0001-01-01T00:00:00Z`. If a struct field of type `time.Time` is unset, `json.Marshal` emits that string — even with `omitempty`. (Go's `omitempty` does not work for `time.Time` because it is a struct, not a zero-value primitive.)

**The solution: Post-processing filter.**

After all other transformations are complete, we walk the final map and remove any string value that matches the zero-time pattern. An unset `time.Time` means "not provided," and `"0001-01-01T00:00:00Z"` is meaningless to a consumer.

## Part 4: The Full Pipeline

Putting it all together, the serializer runs these steps in order:

```text
Step 1: COLLECT
        Walk all typed slices → flatten → deduplicate by SpdxID

Step 2: CREATIONINFO DEDUPLICATION
        Hash all CreationInfo values → group identical ones
        → assign shared blank node IDs (_:creationinfo, _:creationinfo2, ...)

Step 3: PER-ELEMENT TRANSFORMATION
        For each element:
          a. Marshal struct → map[string]interface{} (bare names)
          b. Inject "type" from type registry
          c. Rename profile fields using URI-based prefix registry
          d. Replace CreationInfo with blank node reference
          e. Replace nested element maps with string references
          f. Strip zero-value time strings

Step 4: VALUE OBJECT TYPE INJECTION
        Detect Hash and PackageVerificationCode by signature
        → inject "type" field

Step 5: BUILD OUTPUT
        Wrap in {"@context": "...", "@graph": [...]}
        → marshal to JSON
```

Each step solves exactly one mismatch between the Go model and JSON-LD output. The pipeline is deterministic and reversible: parse the output back through the reader, and you recover the same Go structs.

## Part 5: Why This Design?

We could have built the serializer differently. Here are the alternatives we rejected and why:

| Alternative | Why We Rejected It |
|---|---|
| **Put prefixed names in Go struct tags** | Would lock the model into JSON-LD. The model would break for Turtle, RDF/XML, or in-memory use. |
| **Hardcode prefix mappings** | Would break when SPDX adds new fields or profiles. The ontology URI registry is the single source of truth. |
| **Hardcode reference field names** | Would require updating the serializer for every new element type SPDX adds. The generic rule is future-proof. |
| **Add `Type` fields to Go structs** | Would leak serialization concerns into the domain model. The model should not know about JSON-LD. |
| **Inline CreationInfo on every element** | Produces bloated, unidiomatic output that violates SPDX spec conventions. |
| **Skip CreationInfo deduplication** | A 500-element document would repeat the same block 500 times. Unacceptable for real-world SBOMs. |

The guiding principle is **separation of concerns**: the Go model represents the SPDX ontology faithfully using bare names and nested structs; the serializer handles all JSON-LD-specific transformations (prefixes, types, references, blank nodes) at the serialization layer.

## Summary: From Output Back to Code

If you look at a serialized SPDX 3.0 document and wonder "how did this get here?", the answer is:

1. **`"type"`** — injected from a registry that maps Go types to JSON-LD type strings.
2. **Prefixed fields** (`software_downloadLocation`) — renamed using a URI-based registry that derives prefixes from the official SPDX ontology.
3. **String references** (`from`, `to`, `createdBy`) — produced by a generic rule that replaces any nested map containing `spdxId` with just the ID string.
4. **Blank node `CreationInfo`** — deduplicated by hashing content and emitting shared references.
5. **Value object `type`** (`Hash`) — injected by signature detection after marshaling.
6. **No zero timestamps** — filtered out in post-processing.

The serializer is not `json.Marshal`. It is a **format bridge** that takes a clean, format-agnostic Go model and produces valid SPDX 3.0 JSON-LD by solving seven structural mismatches — one at a time, in a pipeline, with each step backed by a deliberate design choice.

*For the user-facing API and cookbook, see the [Serialization Guide](serialization-guide.md). For installation and quick-start examples, see the [README](../README.md).*
