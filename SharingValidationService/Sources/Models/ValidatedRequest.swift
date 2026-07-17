import Foundation

public struct ValidatedRequest: Sendable, Equatable {
    public let dcqlQuery: DCQLQuery
    /// The exact `response_uri` byte string as it appeared in the request JWT. Stored raw (not as a
    /// `URL`) because it is hashed verbatim into the OID4VP SessionTranscript — a `URL` round-trip via
    /// `absoluteString` can normalise percent-encoding and break the verifier's DeviceAuth validation.
    /// Preserved verbatim like `clientID`. Use ``responseURL`` when a `URL` is needed for the network call.
    public let responseURI: String
    public let state: String?
    public let nonce: String
    /// The full `client_id` tstr including its prefix (e.g. `x509_san_dns:verifier.example.com`),
    /// as required verbatim by the OID4VP SessionTranscript hash.
    public let clientID: String
    public let clientIdentifierPrefix: ClientIdentifierPrefix
    public let verifierEncryptionKey: VerifierEncryptionKey

    /// The `response_uri` parsed as a `URL` for the network call. The validator has already proven the
    /// raw value parses and is HTTPS, so this is effectively non-optional at use sites; it stays optional
    /// only because `URL(string:)` is fallible.
    public var responseURL: URL? { URL(string: responseURI) }

    public init(
        dcqlQuery: DCQLQuery,
        responseURI: String,
        state: String?,
        nonce: String,
        clientID: String,
        clientIdentifierPrefix: ClientIdentifierPrefix,
        verifierEncryptionKey: VerifierEncryptionKey
    ) {
        self.dcqlQuery = dcqlQuery
        self.responseURI = responseURI
        self.state = state
        self.nonce = nonce
        self.clientID = clientID
        self.clientIdentifierPrefix = clientIdentifierPrefix
        self.verifierEncryptionKey = verifierEncryptionKey
    }
}
