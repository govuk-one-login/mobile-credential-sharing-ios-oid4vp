import Foundation

public struct URIParser {
    static let asciiURLSafeCharacters = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )

    public init() {}

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
