import Foundation

// TODO: DCMAW-21222 — TEMPORARY. These mirror the DCQL input types defined in
// `SharingValidationService` (branch feat/dcmaw-21222). They exist only so `DCQLMapper` compiles
// and is testable before that branch merges. On merge: delete this file and
// `import SharingValidationService` in DCQLMapper — the type names/fields match, so no mapper
// change is required. Only the fields the mapper consumes are mirrored here.

struct CredentialQuery: Sendable, Equatable {
    let id: String
    let format: String
    let meta: CredentialMeta?
    let claims: [ClaimQuery]?
}

struct CredentialMeta: Sendable, Equatable {
    let doctypeValue: String?
}

struct ClaimQuery: Sendable, Equatable {
    let path: [String]
    let intentToRetain: Bool
}
