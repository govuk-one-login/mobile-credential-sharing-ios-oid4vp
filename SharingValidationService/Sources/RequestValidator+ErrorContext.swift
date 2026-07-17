import Foundation

extension RequestValidator {
    /// Best-effort extraction of everything needed to send the verifier a JWE-encrypted error response.
    ///
    /// The OID4VP error response is encrypted to the verifier's key and PUT to its `response_uri`, so it
    /// can only be sent when the verified request object carries a valid HTTPS `response_uri`, a decodable
    /// P-256 encryption key, and a nonce. When any is absent or malformed, the response_uri or key is the
    /// very thing that is broken — there is nothing safe to encrypt to — so this returns `nil` and the
    /// caller aborts locally without contacting the verifier.
    ///
    /// - Parameter requestObject: the signature-verified request object.
    /// - Returns: the ``ErrorResponseContext`` when one can be formed, otherwise `nil`.
    public func errorResponseContext(from requestObject: VerifiedRequestObject) -> ErrorResponseContext? {
        guard let responseURIString = requestObject.responseURI,
              let responseURI = URL(string: responseURIString),
              responseURI.scheme?.lowercased() == "https" else {
            return nil
        }

        guard let clientMetadataData = requestObject.clientMetadataData,
              let verifierEncryptionKey = try? decodeVerifierEncryptionKey(from: clientMetadataData) else {
            return nil
        }

        guard let nonce = requestObject.nonce, !nonce.isEmpty else {
            return nil
        }

        return ErrorResponseContext(
            responseURI: responseURI,
            verifierEncryptionKey: verifierEncryptionKey,
            verifierNonce: nonce
        )
    }
}
