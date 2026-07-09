import Foundation

public struct URIMetadata: Sendable, Equatable {
    public let clientID: String
    public let clientIdentifierPrefix: ClientIdentifierPrefix
    public let requestURI: URL

    public init(
        clientID: String,
        clientIdentifierPrefix: ClientIdentifierPrefix,
        requestURI: URL
    ) {
        self.clientID = clientID
        self.clientIdentifierPrefix = clientIdentifierPrefix
        self.requestURI = requestURI
    }
}
