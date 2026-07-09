import Foundation
@testable import SharingValidationService
import Testing

// swiftlint:disable file_length
@Suite("RequestValidator Tests")
// swiftlint:disable:next type_body_length
struct RequestValidatorTests {
    // A well-formed `client_metadata` carrying a single EC P-256 encryption JWK.
    // The coordinates are arbitrary 32-byte values; on-curve validity is the crypto module's concern.
    static let validEncryptionKeyX = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"
    static let validEncryptionKeyY = "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3s"

    let sut = RequestValidator()

    private func makeValidURIMetadata(clientID: String = "x509_san_dns:verifier.example.com") -> URIMetadata {
        URIMetadata(
            clientID: clientID,
            clientIdentifierPrefix: .x509SanDns(identifier: "verifier.example.com"),
            responseType: "vp_token",
            nonce: "uri_nonce",
            requestURI: URL(string: "https://verifier.example.com/request")!
        )
    }

    private func makeValidDCQLData() -> Data {
        let json = """
        {
            "credentials": [
                {
                    "id": "cred1",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [
                        { "path": ["org.iso.18013.5.1", "family_name"] },
                        { "path": ["org.iso.18013.5.1", "given_name"] }
                    ]
                }
            ]
        }
        """
        return Data(json.utf8)
    }

    private func makeValidRequestObject(
        headerTyp: String? = "oauth-authz-req+jwt",
        aud: String? = "https://self-issued.me/v2",
        clientID: String? = "x509_san_dns:verifier.example.com",
        responseType: String? = "vp_token",
        responseMode: String? = "direct_post.jwt",
        responseURI: String? = "https://verifier.example.com/response",
        redirectURI: String? = nil,
        nonce: String? = "valid_nonce",
        state: String? = nil,
        dcqlQueryData: Data? = nil,
        clientMetadataData: Data? = try? makeClientMetadata(),
        leafCertificateSANs: [String] = ["verifier.example.com"]
    ) -> VerifiedRequestObject {
        VerifiedRequestObject(
            headerTyp: headerTyp,
            aud: aud,
            clientID: clientID,
            responseType: responseType,
            responseMode: responseMode,
            responseURI: responseURI,
            redirectURI: redirectURI,
            nonce: nonce,
            state: state,
            dcqlQueryData: dcqlQueryData ?? makeValidDCQLData(),
            clientMetadataData: clientMetadataData,
            leafCertificateSANs: leafCertificateSANs
        )
    }

    // MARK: - Happy Path

    @Test("Validates complete valid request object")
    func validatesCompleteRequest() throws {
        let requestObject = makeValidRequestObject()
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.responseURI.absoluteString == "https://verifier.example.com/response")
        #expect(result.nonce == "valid_nonce")
        #expect(result.state == nil)
        #expect(result.clientID == "x509_san_dns:verifier.example.com")
        #expect(result.dcqlQuery.credentials.count == 1)
        #expect(result.dcqlQuery.credentials[0].format == "mso_mdoc")
    }

    @Test("Validates request with direct_post.jwt response mode")
    func validatesDirectPostJwtMode() throws {
        let requestObject = makeValidRequestObject(responseMode: "direct_post.jwt")
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.responseURI.absoluteString == "https://verifier.example.com/response")
    }

    @Test("Passes when state is nil")
    func passesWhenStateIsNil() throws {
        let requestObject = makeValidRequestObject(state: nil)
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.state == nil)
    }

    @Test("Preserves valid state in result")
    func preservesValidState() throws {
        let requestObject = makeValidRequestObject(state: "session~state.123")
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.state == "session~state.123")
    }

    @Test("Filters unsupported credential formats and returns only mso_mdoc")
    func filtersUnsupportedFormats() throws {
        let json = """
        {
            "credentials": [
                { "id": "cred1", "format": "jwt_vc", "claims": [] },
                { "id": "cred2", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
            ]
        }
        """
        let requestObject = makeValidRequestObject(dcqlQueryData: Data(json.utf8))
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.dcqlQuery.credentials.count == 1)
        #expect(result.dcqlQuery.credentials[0].id == "cred2")
    }

    // MARK: - Error Cases

    @Test("Throws invalidTypHeader when typ is wrong")
    func throwsInvalidTypHeaderWrongValue() {
        let requestObject = makeValidRequestObject(headerTyp: "JWT")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidTypHeader("JWT")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidTypHeader when typ is nil")
    func throwsInvalidTypHeaderNil() {
        let requestObject = makeValidRequestObject(headerTyp: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidTypHeader(nil)) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidAudience when aud is wrong")
    func throwsInvalidAudienceWrongValue() {
        let requestObject = makeValidRequestObject(aud: "https://verifier.example.com")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidAudience("https://verifier.example.com")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidAudience when aud is nil")
    func throwsInvalidAudienceNil() {
        let requestObject = makeValidRequestObject(aud: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidAudience(nil)) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws redirectURINotSupported when redirect_uri is present")
    func throwsRedirectURINotSupported() {
        let requestObject = makeValidRequestObject(redirectURI: "https://verifier.example.com/cb")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.redirectURINotSupported) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws missingClientMetadata when client_metadata is absent")
    func throwsMissingClientMetadata() {
        let requestObject = makeValidRequestObject(clientMetadataData: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.missingClientMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidResponseType when not vp_token")
    func throwsInvalidResponseType() {
        let requestObject = makeValidRequestObject(responseType: "code")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidResponseType("code")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidResponseMode when mode is fragment")
    func throwsInvalidResponseMode() {
        let requestObject = makeValidRequestObject(responseMode: "fragment")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidResponseMode("fragment")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidResponseMode when mode is direct_post without JWE")
    func throwsInvalidResponseModeForDirectPost() {
        let requestObject = makeValidRequestObject(responseMode: "direct_post")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidResponseMode("direct_post")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidResponseMode when mode is nil")
    func throwsInvalidResponseModeNil() {
        let requestObject = makeValidRequestObject(responseMode: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidResponseMode("nil")) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws missingResponseURI when response_uri nil")
    func throwsMissingResponseURI() {
        let requestObject = makeValidRequestObject(responseURI: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.missingResponseURI) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws responseURINotHTTPS when scheme is http")
    func throwsResponseURINotHTTPS() {
        let requestObject = makeValidRequestObject(responseURI: "http://verifier.example.com/response")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.responseURINotHTTPS) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws missingNonceInRequestObject when nonce nil")
    func throwsMissingNonce() {
        let requestObject = makeValidRequestObject(nonce: nil)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.missingNonceInRequestObject) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws missingNonceInRequestObject when nonce empty")
    func throwsMissingNonceEmpty() {
        let requestObject = makeValidRequestObject(nonce: "")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.missingNonceInRequestObject) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidNonceInRequestObject when nonce has bad chars")
    func throwsInvalidNonceChars() {
        let requestObject = makeValidRequestObject(nonce: "nonce with spaces")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidNonceInRequestObject) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws clientIDMismatch when IDs differ")
    func throwsClientIDMismatch() {
        let requestObject = makeValidRequestObject(clientID: "different-client")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.clientIDMismatch) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws clientIDSANMismatch when DNS name is absent from leaf cert SANs")
    func throwsClientIDSANMismatch() {
        let requestObject = makeValidRequestObject(leafCertificateSANs: ["other.example.com"])
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.clientIDSANMismatch) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws clientIDSANMismatch when leaf cert SANs are empty")
    func throwsClientIDSANMismatchWhenEmpty() {
        let requestObject = makeValidRequestObject(leafCertificateSANs: [])
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.clientIDSANMismatch) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Passes when DNS name matches one of several leaf cert SANs")
    func passesWhenSANMatchesAmongMany() throws {
        let requestObject = makeValidRequestObject(
            leafCertificateSANs: ["a.example.com", "verifier.example.com", "b.example.com"]
        )
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.nonce == "valid_nonce")
    }

    @Test("Skips SAN check when client_id prefix is not x509_san_dns")
    func skipsSANCheckForNonX509Prefix() throws {
        let clientID = "did:example:123"
        let requestObject = makeValidRequestObject(clientID: clientID, leafCertificateSANs: [])
        let uriMetadata = URIMetadata(
            clientID: clientID,
            clientIdentifierPrefix: .did(identifier: "example:123"),
            responseType: "vp_token",
            nonce: "uri_nonce",
            requestURI: URL(string: "https://verifier.example.com/request")!
        )

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.clientIdentifierPrefix == .did(identifier: "example:123"))
    }

    @Test("Throws invalidStateCharacters when state has invalid chars")
    func throwsInvalidStateChars() {
        let requestObject = makeValidRequestObject(state: "state with spaces")
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidStateCharacters) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws missingDCQLQuery when dcqlQueryData nil")
    func throwsMissingDCQL() throws {
        let modified = VerifiedRequestObject(
            headerTyp: "oauth-authz-req+jwt",
            aud: "https://self-issued.me/v2",
            clientID: "x509_san_dns:verifier.example.com",
            responseType: "vp_token",
            responseMode: "direct_post.jwt",
            responseURI: "https://verifier.example.com/response",
            redirectURI: nil,
            nonce: "valid_nonce",
            state: nil,
            dcqlQueryData: nil,
            clientMetadataData: try Self.makeClientMetadata(),
            leafCertificateSANs: ["verifier.example.com"]
        )
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.missingDCQLQuery) {
            try sut.validate(requestObject: modified, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidDCQLQuery when JSON is malformed")
    func throwsInvalidDCQLMalformed() {
        let requestObject = makeValidRequestObject(dcqlQueryData: Data("not json".utf8))
        let uriMetadata = makeValidURIMetadata()

        #expect {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        } throws: { error in
            guard let vpError = error as? ValidationError,
                  case .invalidDCQLQuery = vpError else {
                return false
            }
            return true
        }
    }

    @Test("Throws noSupportedCredentialQueries when no mso_mdoc format")
    func throwsNoSupportedFormats() {
        let json = """
        { "credentials": [{ "id": "c1", "format": "jwt_vc" }] }
        """
        let requestObject = makeValidRequestObject(dcqlQueryData: Data(json.utf8))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.noSupportedCredentialQueries) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    // MARK: - Verifier Encryption Key

    @Test("Decodes verifier encryption key onto the validated request")
    func decodesVerifierEncryptionKey() throws {
        let requestObject = makeValidRequestObject()
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.verifierEncryptionKey.xCoordinate.count == 32)
        #expect(result.verifierEncryptionKey.yCoordinate.count == 32)
        #expect(result.verifierEncryptionKey.keyID == "verifier-key-1")
    }

    @Test("Decodes verifier encryption key when kid is absent")
    func decodesVerifierEncryptionKeyWithoutKeyID() throws {
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(kid: nil))
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.verifierEncryptionKey.keyID == nil)
    }

    @Test("Selects the encryption key when a signing key is also present")
    func selectsEncryptionKeyAmongMany() throws {
        let signingKey: [String: Any] = [
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "x": Self.validEncryptionKeyX, "y": Self.validEncryptionKeyY, "kid": "sig-key"
        ]
        let encryptionKey: [String: Any] = [
            "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
            "x": Self.validEncryptionKeyX, "y": Self.validEncryptionKeyY, "kid": "enc-key"
        ]
        let metadata = try JSONSerialization.data(withJSONObject: ["jwks": ["keys": [signingKey, encryptionKey]]])
        let requestObject = makeValidRequestObject(clientMetadataData: metadata)
        let uriMetadata = makeValidURIMetadata()

        let result = try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)

        #expect(result.verifierEncryptionKey.keyID == "enc-key")
    }

    @Test("Throws invalidVerifierMetadata when jwks is absent")
    func throwsInvalidVerifierMetadataNoJWKS() {
        let requestObject = makeValidRequestObject(clientMetadataData: Data("{}".utf8))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when keys array is empty")
    func throwsInvalidVerifierMetadataEmptyKeys() throws {
        let metadata = try JSONSerialization.data(withJSONObject: ["jwks": ["keys": []]])
        let requestObject = makeValidRequestObject(clientMetadataData: metadata)
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when only a signing key is present")
    func throwsInvalidVerifierMetadataSigningKeyOnly() throws {
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(use: "sig"))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when curve is not P-256")
    func throwsInvalidVerifierMetadataWrongCurve() throws {
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(crv: "P-384"))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when alg is missing")
    func throwsInvalidVerifierMetadataMissingAlg() throws {
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(alg: nil))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when a coordinate is the wrong length")
    func throwsInvalidVerifierMetadataShortCoordinate() throws {
        // "QUJD" decodes to "ABC" — 3 bytes, not 32.
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(x: "QUJD"))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    @Test("Throws invalidVerifierMetadata when a coordinate is not base64url")
    func throwsInvalidVerifierMetadataNonBase64Coordinate() throws {
        let requestObject = makeValidRequestObject(clientMetadataData: try Self.makeClientMetadata(y: "not base64!!"))
        let uriMetadata = makeValidURIMetadata()

        #expect(throws: ValidationError.invalidVerifierMetadata) {
            try sut.validate(requestObject: requestObject, uriMetadata: uriMetadata)
        }
    }

    private static func makeClientMetadata(
        kty: String = "EC",
        crv: String = "P-256",
        use: String = "enc",
        alg: String? = "ECDH-ES",
        x: String? = validEncryptionKeyX,
        y: String? = validEncryptionKeyY,
        kid: String? = "verifier-key-1"
    ) throws -> Data {
        var key: [String: Any] = ["kty": kty, "crv": crv, "use": use]
        key["alg"] = alg
        key["x"] = x
        key["y"] = y
        key["kid"] = kid
        let metadata: [String: Any] = ["jwks": ["keys": [key]]]
        return try JSONSerialization.data(withJSONObject: metadata)
    }
}
