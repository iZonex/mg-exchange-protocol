# MGEP Versioning & Compatibility

## Wire Format Version

The `version` byte in the frame header identifies the wire format version. Current: **1**.

## Compatibility Rules

### Rule 1: Core Block Fields Are Frozen After Release

Once a message type is released, its core block field order, types, and offsets NEVER change. This guarantees that a receiver can always decode a known message type without checking the version.

### Rule 2: New Fields Go to Optional Block

Schema evolution happens through the optional (flex) block. New optional fields are appended with incrementing field IDs. Old readers ignore unknown field IDs — this is safe and backward compatible.

### Rule 3: Field IDs Are Never Reused

If optional field ID 5 was once "settlement_date", it is always "settlement_date" even if deprecated. New fields get new IDs. This prevents misinterpretation.

### Rule 4: New Message Types Are Safe

Adding a new message type (e.g., `0x0D` in trading schema) is backward compatible. Old receivers dispatch it to `MessageKind::Unknown` and can ignore or reject it.

### Rule 5: Enum Values Are Append-Only

New enum variants are added at the end with incrementing values. Existing variant values never change. Value 0 is always reserved (unset/invalid).

### Rule 6: Schema ID Namespace

Schema IDs 0x0000–0x00FF are reserved for the MGEP standard. User-defined schemas use 0x0100–0xFFFE.

## Version Negotiation

During session establishment:
1. Client sends `Negotiate` with `max_message_size` and protocol capabilities
2. Server responds with accepted parameters
3. Both sides agree on the intersection of supported features

## Deprecation Process

1. Mark the field/message as deprecated in the schema (add `# DEPRECATED: reason`)
2. Keep it in the spec for at least 2 major versions
3. Implementations must still decode it but may ignore the value
4. After 2 versions, the field ID / message type is retired (never reused)

## Breaking Changes

If absolutely necessary (security fix, fundamental design flaw):
1. Increment the `version` byte
2. Document the migration in CHANGELOG.md
3. Provide a 6-month transition period where both versions are supported
4. Old version support can be dropped after transition period

Breaking changes require an MGEP Enhancement Proposal with explicit compatibility analysis.
