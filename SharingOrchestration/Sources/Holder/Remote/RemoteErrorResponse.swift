import Foundation
import SharingCryptoService
import SharingValidationService

/// The OID4VP Authorization Error Response object (RFC 6749 §5.2 shape) carried as the JWE plaintext:
/// `{"error": <code>, "error_description": <reason>}`, PUT to the verifier's `response_uri`.
struct OID4VPErrorObject: Encodable, Equatable {
    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }

    let error: String
    let errorDescription: String
}

/// A classified OID4VP error: the `error` code and human-readable `error_description` for the response.
struct OID4VPError: Equatable {
    let code: String
    let description: String
}

extension OID4VPError {
    /// The response sent when the user declines sharing on the consent screen (Step 8).
    static let userDeclined = OID4VPError(
        code: "access_denied",
        description: "User declined to share credential"
    )

    /// Classifies a thrown error into an OID4VP error response, or `nil` when the failure must stay
    /// local (no response sent to the verifier).
    ///
    /// - `ValidationError` maps via its own ``ValidationError/oid4vpErrorCode`` (mostly `invalid_request`).
    /// - Credential lookup and selective-disclosure failures map to `access_denied`.
    /// - Everything else — signature verification, JWE encryption, network — returns `nil`: either the
    ///   verifier is unauthenticated, or there is no usable channel/key to encrypt an error to.
    static func classify(_ error: Error) -> OID4VPError? {
        switch error {
        case let validationError as ValidationError:
            return OID4VPError(
                code: validationError.oid4vpErrorCode,
                description: validationError.localizedDescription
            )
        case let credentialError as CredentialRequestError:
            return accessDenied(credentialError)
        case let filterError as IssuerSignedFilterError:
            return OID4VPError(code: "access_denied", description: filterError.localizedDescription)
        default:
            return nil
        }
    }

    /// Credential-side failures that mean the wallet cannot satisfy the request map to `access_denied`;
    /// internal inconsistencies (e.g. a missing matched credential mid-flow) stay local.
    private static func accessDenied(_ error: CredentialRequestError) -> OID4VPError? {
        switch error {
        case .getCredentialsError, .noCredentialsReturned, .docTypeMismatch, .matchedCredentialNotFound:
            return OID4VPError(code: "access_denied", description: error.localizedDescription)
        case .msoDecodingFailed, .unsupportedDocumentRequestCount:
            return nil
        }
    }
}
