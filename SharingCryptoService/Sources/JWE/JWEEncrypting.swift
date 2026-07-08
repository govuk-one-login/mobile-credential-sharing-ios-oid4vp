import Foundation

/// Produces a compact JWE (RFC 7516) for the OID4VP Authorization Response.
///
/// A protocol so the CryptoKit implementation can be swapped for a JOSE-library-backed one without
/// touching callers; conformers must agree on the RFC 7518 §4.6 (ECDH-ES + A256GCM) wire format.
public protocol JWEEncrypting: Sendable {
    /// Encrypts `plaintext` to the verifier as a five-segment compact JWE.
    ///
    /// - Parameters:
    ///   - plaintext: the response payload to encrypt.
    ///   - verifierKey: the verifier's EC P-256 encryption key.
    ///   - agreementPartyUInfo: `apu` — the mdocGeneratedNonce, supplied by the caller.
    ///   - agreementPartyVInfo: `apv` — the verifier's nonce from the Authorization Request.
    /// - Returns: the compact JWE string.
    func encrypt(
        plaintext: Data,
        verifierKey: VerifierPublicKeyMaterial,
        agreementPartyUInfo: Data,
        agreementPartyVInfo: Data
    ) throws(JWEEncryptionError) -> String
}
