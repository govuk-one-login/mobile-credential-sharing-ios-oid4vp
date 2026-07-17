import SwiftCBOR

/// Helpers for producing the bytes a COSE_Sign1 signature is computed over, per RFC 9052 §4.4.
///
/// The signature is never over the payload directly — it is over a `Sig_structure`:
/// `[ "Signature1", protected (bstr), external_aad (bstr), payload (bstr) ]`. Both the signer and any
/// conformant verifier must reconstruct the same structure, so the protected headers here must match
/// those emitted in the COSE_Sign1 itself.
enum COSESign1 {
    /// The CBOR-encoded protected header map `{1: -7}` (alg = ES256), shared between the bytes that are
    /// signed and the COSE_Sign1 that is emitted so the two are byte-identical.
    static var es256ProtectedHeaderBytes: [UInt8] {
        COSEAlgorithm.es256.protectedHeaderCBOR.encode()
    }

    /// Builds the CBOR-encoded `Sig_structure` for a COSE_Sign1 (RFC 9052 §4.4):
    /// `[ "Signature1", body_protected, external_aad, payload ]`.
    ///
    /// - `protectedHeaderBytes` is the spec's `body_protected`: the protected attributes of the body
    ///   structure serialised as a bstr — i.e. the CBOR-encoded protected header map. The spec allows a
    ///   zero-length bstr only when there are *no* protected attributes; mdoc always carries `alg: ES256`
    ///   (`{1: -7}`), so this is the serialised map, never empty. It must be byte-identical to the
    ///   protected header emitted as element [0] of the COSE_Sign1, or verification fails.
    /// - `external_aad` is an empty bstr — mdoc `DeviceAuth` uses no external additional authenticated data.
    /// - `payloadBytes` is the detached payload (the `DeviceAuthenticationBytes`).
    static func sigStructure(protectedHeaderBytes: [UInt8], payloadBytes: [UInt8]) -> [UInt8] {
        CBOR.array([
            .utf8String("Signature1"),
            .byteString(protectedHeaderBytes),
            .byteString([]),
            .byteString(payloadBytes)
        ]).encode()
    }
}
