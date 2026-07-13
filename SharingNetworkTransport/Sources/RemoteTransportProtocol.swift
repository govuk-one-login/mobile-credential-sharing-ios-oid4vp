import Foundation

/// The network operations for the OID4VP (Remote) flow: fetching the signed request object and
/// uploading the encrypted response.
public protocol RemoteTransportProtocol: Sendable {
    /// Fetches the signed Authorization Request Object from the verifier's `request_uri`.
    /// - Parameter requestURI: the presigned URL from the engagement deeplink.
    /// - Returns: the request object as a compact JWS string.
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
