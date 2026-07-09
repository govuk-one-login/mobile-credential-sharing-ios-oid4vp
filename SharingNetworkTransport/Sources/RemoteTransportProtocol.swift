import Foundation

public protocol RemoteTransportProtocol: Sendable {
    func fetchRequestObject(from requestURI: URL) async throws -> String

    /// Uploads the encrypted Authorization Response to the verifier's presigned URL.
    ///
    /// The `response_uri` is a presigned S3 PUT target: the request body is the raw compact JWE and a
    /// successful upload returns no payload. Throws if the upload fails (e.g. a non-2xx status).
    func submitResponse(
        encryptedResponse jwe: String,
        to uploadURL: URL
    ) async throws
}
