import Foundation

/// Validates a verified OID4VP request object against the engagement deeplink and OID4VP rules,
/// producing the ``ValidatedRequest`` the response is built from.
public struct RequestValidator {
    public init() {}

    // swiftlint:disable function_body_length
    /// Validates the request object's header, audience, response type/mode, `client_id` (and its
    /// certificate SAN), nonce, verifier encryption key, and DCQL query, returning the validated request.
    /// - Parameters:
    ///   - requestObject: the signature-verified request object claims.
    ///   - uriMetadata: the parsed engagement deeplink to cross-check `client_id` against.
    /// - Returns: a ``ValidatedRequest`` carrying everything needed to build the response.
    /// - Throws: ``ValidationError`` on the first rule that fails.
    public func validate(
        requestObject: VerifiedRequestObject,
        uriMetadata: URIMetadata
    ) throws(ValidationError) -> ValidatedRequest {
        guard requestObject.headerTyp == "JWT" else {
            throw .invalidTypHeader(requestObject.headerTyp)
        }

        guard requestObject.aud == "https://self-issued.me/v2" else {
            throw .invalidAudience(requestObject.aud)
        }

        guard requestObject.responseType == "vp_token" else {
            throw .invalidResponseType(requestObject.responseType ?? "nil")
        }

        guard requestObject.responseMode == "direct_post.jwt" else {
            throw .invalidResponseMode(requestObject.responseMode ?? "nil")
        }

        guard let responseURIString = requestObject.responseURI,
              let responseURI = URL(string: responseURIString) else {
            throw .missingResponseURI
        }

        guard responseURI.scheme?.lowercased() == "https" else {
            throw .responseURINotHTTPS
        }

        guard requestObject.redirectURI == nil else {
            throw .redirectURINotSupported
        }

        guard let nonce = requestObject.nonce, !nonce.isEmpty else {
            throw .missingNonceInRequestObject
        }

        guard URIParser.isASCIIURLSafe(nonce) else {
            throw .invalidNonceInRequestObject
        }

        guard requestObject.clientID == uriMetadata.clientID else {
            throw .clientIDMismatch
        }

        if case let .x509SanDns(dnsName) = uriMetadata.clientIdentifierPrefix {
            guard requestObject.leafCertificateSANs.contains(dnsName) else {
                throw .clientIDSANMismatch
            }
        }

        if let state = requestObject.state, !state.isEmpty {
            guard URIParser.isASCIIURLSafe(state) else {
                throw .invalidStateCharacters
            }
        }

        guard let clientMetadataData = requestObject.clientMetadataData else {
            throw .missingClientMetadata
        }

        let verifierEncryptionKey = try decodeVerifierEncryptionKey(from: clientMetadataData)

        guard let dcqlData = requestObject.dcqlQueryData else {
            throw .missingDCQLQuery
        }

        let dcqlQuery: DCQLQuery
        do {
            dcqlQuery = try JSONDecoder().decode(DCQLQuery.self, from: dcqlData)
        } catch {
            throw .invalidDCQLQuery(error.localizedDescription)
        }

        let supportedCredentials = dcqlQuery.credentials.filter { $0.format == "mso_mdoc" }
        guard !supportedCredentials.isEmpty else {
            throw .noSupportedCredentialQueries
        }

        let filteredQuery = DCQLQuery(
            credentials: supportedCredentials,
            credentialSets: dcqlQuery.credentialSets
        )

        return ValidatedRequest(
            dcqlQuery: filteredQuery,
            responseURI: responseURI,
            state: requestObject.state,
            nonce: nonce,
            clientID: uriMetadata.clientID,
            clientIdentifierPrefix: uriMetadata.clientIdentifierPrefix,
            verifierEncryptionKey: verifierEncryptionKey
        )
    }
    // swiftlint:enable function_body_length
}
