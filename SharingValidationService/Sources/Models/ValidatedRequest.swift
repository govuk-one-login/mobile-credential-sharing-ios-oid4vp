import Foundation

public struct ValidatedRequest: Sendable, Equatable {
    public let dcqlQuery: DCQLQuery
    public let responseURI: URL
    public let state: String?
    public let nonce: String
    /// The full `client_id` tstr including its prefix (e.g. `x509_san_dns:verifier.example.com`),
    /// as required verbatim by the OID4VP SessionTranscript hash.
    public let clientID: String
    public let clientIdentifierPrefix: ClientIdentifierPrefix
    public let verifierEncryptionKey: VerifierEncryptionKey

    public init(
        dcqlQuery: DCQLQuery,
        responseURI: URL,
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
