import Foundation
@testable import SharingValidationService
import Testing

@Suite("RequestValidator errorResponseContext Tests")
struct RequestValidatorErrorContextTests {
    // Arbitrary well-formed 32-byte base64url coordinates; on-curve validity is the crypto module's concern.
    static let validEncryptionKeyX = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"
    static let validEncryptionKeyY = "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3s"
    
    /// Well-formed metadata used as the default so an explicit `nil` argument means "genuinely absent"
    /// rather than falling back to a valid value.
    private static let defaultClientMetadata: Data? = try? makeClientMetadata()

    let sut = RequestValidator()

    @Test("Returns context when response_uri, key, and nonce are all present and valid")
    func returnsContextForValidRequest() throws {
        let context = sut.errorResponseContext(from: makeRequestObject())

        let unwrapped = try #require(context)
        #expect(unwrapped.responseURI.absoluteString == "https://verifier.example.com/response")
        #expect(unwrapped.verifierNonce == "valid_nonce")
        #expect(unwrapped.verifierEncryptionKey.keyID == "verifier-key-1")
    }

    @Test("Returns nil when response_uri is missing")
    func nilWhenResponseURIMissing() {
        #expect(sut.errorResponseContext(from: makeRequestObject(responseURI: nil)) == nil)
    }

    @Test("Returns nil when response_uri is not HTTPS")
    func nilWhenResponseURINotHTTPS() {
        let object = makeRequestObject(responseURI: "http://verifier.example.com/response")
        #expect(sut.errorResponseContext(from: object) == nil)
    }

    @Test("Returns nil when client_metadata is missing")
    func nilWhenClientMetadataMissing() {
        #expect(sut.errorResponseContext(from: makeRequestObject(clientMetadataData: nil)) == nil)
    }

    @Test("Returns nil when the verifier key is malformed")
    func nilWhenKeyMalformed() throws {
        let object = makeRequestObject(clientMetadataData: try Self.makeClientMetadata(x: "QUJD"))
        #expect(sut.errorResponseContext(from: object) == nil)
    }

    @Test("Returns nil when nonce is missing")
    func nilWhenNonceMissing() {
        #expect(sut.errorResponseContext(from: makeRequestObject(nonce: nil)) == nil)
    }

    // MARK: - Helpers

    private func makeRequestObject(
        responseURI: String? = "https://verifier.example.com/response",
        nonce: String? = "valid_nonce",
        clientMetadataData: Data? = defaultClientMetadata
    ) -> VerifiedRequestObject {
        VerifiedRequestObject(
            headerTyp: "JWT",
            aud: "https://self-issued.me/v2",
            clientID: "x509_san_dns:verifier.example.com",
            responseType: "vp_token",
            responseMode: "direct_post.jwt",
            responseURI: responseURI,
            redirectURI: nil,
            nonce: nonce,
            state: nil,
            dcqlQueryData: nil,
            clientMetadataData: clientMetadataData,
            leafCertificateSANs: ["verifier.example.com"]
        )
    }


    private static func makeClientMetadata(
        x: String? = validEncryptionKeyX,
        y: String? = validEncryptionKeyY
    ) throws -> Data {
        let key: [String: Any] = [
            "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
            "x": x as Any, "y": y as Any, "kid": "verifier-key-1"
        ]
        let metadata: [String: Any] = ["jwks": ["keys": [key]]]
        return try JSONSerialization.data(withJSONObject: metadata)
    }
}
