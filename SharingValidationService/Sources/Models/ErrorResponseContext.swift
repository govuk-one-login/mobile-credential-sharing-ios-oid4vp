import Foundation

/// The minimum the wallet needs to send the verifier a JWE-encrypted error response: where to send it,
/// which key to encrypt to, and the verifier's nonce (the JWE `apv`).
///
/// Only obtainable from a signature-verified request object whose `response_uri`, encryption key, and
/// nonce are all present and well-formed — see ``RequestValidator/errorResponseContext(from:)``. When
/// any of these are missing there is nothing safe to encrypt to, so no context (and no error response)
/// exists.
public struct ErrorResponseContext: Sendable, Equatable {
    /// The verifier's HTTPS `response_uri` to PUT the encrypted error to.
    public let responseURI: URL

    /// The verifier's EC P-256 public key the error response is encrypted to.
    public let verifierEncryptionKey: VerifierEncryptionKey

    /// The verifier's nonce from the request, carried as the JWE `apv`.
    public let verifierNonce: String

    public init(
        responseURI: URL,
        verifierEncryptionKey: VerifierEncryptionKey,
        verifierNonce: String
    ) {
        self.responseURI = responseURI
        self.verifierEncryptionKey = verifierEncryptionKey
        self.verifierNonce = verifierNonce
    }
}
