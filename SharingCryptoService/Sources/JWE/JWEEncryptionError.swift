import Foundation

/// Failures raised while producing a compact JWE for the OID4VP response.
///
/// Every case is fatal to the send: an unencrypted response must never reach the verifier. Structural
/// problems with the verifier's advertised metadata (missing/incompatible JWK) are caught earlier during
/// request validation; this enum covers only the cryptographic assembly.
public enum JWEEncryptionError: LocalizedError, Equatable {
    /// The verifier's coordinates do not form a valid P-256 public point.
    case invalidVerifierKey
    /// ECDH key agreement with the verifier's key failed.
    case keyAgreementFailed
    /// The JWE protected header could not be serialised to JSON.
    case headerSerializationFailed
    /// AES-256-GCM content encryption failed.
    case encryptionFailed

    public var errorDescription: String? {
        switch self {
        case .invalidVerifierKey:
            "Verifier encryption key is not a valid P-256 public key"
        case .keyAgreementFailed:
            "ECDH-ES key agreement with the verifier key failed"
        case .headerSerializationFailed:
            "Failed to serialise the JWE protected header"
        case .encryptionFailed:
            "AES-256-GCM content encryption failed"
        }
    }
}
