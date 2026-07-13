import Foundation

/// Parses an `mdoc-openid4vp://` engagement deeplink into its `client_id` and `request_uri`.
///
/// The deeplink carries only the two parameters needed to begin the flow; the remaining request
/// parameters live inside the signed request object fetched from `request_uri`.
public struct URIParser {
    static let asciiURLSafeCharacters = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )

    public init() {}

    /// Parses and validates the engagement deeplink.
    /// - Parameter uri: the `mdoc-openid4vp://` URL received by the app.
    /// - Returns: the extracted `client_id`, its identifier prefix, and the `request_uri`.
    /// - Throws: ``ValidationError`` if the scheme is wrong or `client_id`/`request_uri` are missing or malformed.
    public func parse(uri: URL) throws(ValidationError) -> URIMetadata {
        guard uri.scheme?.lowercased() == "mdoc-openid4vp" else {
            throw .missingScheme
        }

        guard let components = URLComponents(url: uri, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw .missingClientID
        }

        let params = Dictionary(
            queryItems.map { ($0.name, $0.value ?? "") },
            uniquingKeysWith: { first, _ in first }
        )

        // The engagement deeplink carries only client_id and request_uri; response_type and nonce live
        // inside the signed Request Object fetched from request_uri (validated later by RequestValidator).
        guard let clientID = params["client_id"], !clientID.isEmpty else {
            throw .missingClientID
        }

        guard let requestURIString = params["request_uri"], !requestURIString.isEmpty else {
            throw .missingRequestURI
        }

        guard let requestURI = URL(string: requestURIString),
              requestURI.scheme != nil,
              requestURI.host != nil else {
            throw .invalidRequestURI
        }

        let clientIdentifierPrefix = ClientIdentifierPrefix.parse(clientID: clientID)

        return URIMetadata(
            clientID: clientID,
            clientIdentifierPrefix: clientIdentifierPrefix,
            requestURI: requestURI
        )
    }

    static func isASCIIURLSafe(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { asciiURLSafeCharacters.contains($0) }
    }
}
