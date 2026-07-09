import Foundation
@testable import SharingValidationService
import Testing

@Suite("URIParser Tests")
struct URIParserTests {
    let sut = URIParser()

    // MARK: - Happy Path

    @Test("Parses valid engagement URI with client_id and request_uri")
    func parsesValidURI() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=verifier.example.com&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2F123")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientID == "verifier.example.com")
        #expect(result.requestURI.absoluteString == "https://verifier.example.com/request/123")
    }

    @Test("Parses a real-shape URI: raw-colon client_id and a presigned S3 request_uri with nested query")
    func parsesRealShapeURI() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=x509_san_dns:verifier.example.gov.uk&request_uri=https%3A%2F%2Fverifier-be-dev-requests.s3.eu-west-2.amazonaws.com%2Ftx_1bc9c477%3FX-Amz-Algorithm%3DAWS4-HMAC-SHA256%26X-Amz-Expires%3D300%26X-Amz-Signature%3Da8c88ea84dc0e5fa0cec529711251b48")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientID == "x509_san_dns:verifier.example.gov.uk")
        #expect(result.clientIdentifierPrefix == .x509SanDns(identifier: "verifier.example.gov.uk"))
        #expect(result.requestURI.host == "verifier-be-dev-requests.s3.eu-west-2.amazonaws.com")
    }

    // MARK: - Client Identifier Prefix

    @Test("Parses URI with x509_san_dns client_id prefix")
    func parsesX509SanDnsPrefix() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=x509_san_dns%3Averifier.example.com&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .x509SanDns(identifier: "verifier.example.com"))
    }

    @Test("Parses URI with x509_san_uri client_id prefix")
    func parsesX509SanUriPrefix() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=x509_san_uri%3Ahttps%3A%2F%2Fverifier.example.com&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .x509SanUri(identifier: "https://verifier.example.com"))
    }

    @Test("Parses URI with did client_id prefix")
    func parsesDidPrefix() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=did%3Aexample%3A123abc&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .did(identifier: "example:123abc"))
    }

    @Test("Parses URI with redirect_uri client_id prefix")
    func parsesRedirectUriPrefix() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fexample.com%2Fcb&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .redirectUri(identifier: "https://example.com/cb"))
    }

    @Test("Parses URI with verifier_attestation client_id prefix")
    func parsesVerifierAttestationPrefix() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=verifier_attestation%3Averifier-id-xyz&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .verifierAttestation(identifier: "verifier-id-xyz"))
    }

    @Test("Parses URI with pre-registered client_id (no known prefix)")
    func parsesPreRegisteredClientID() throws {
        let uri = URL(string: "mdoc-openid4vp://?client_id=my-verifier-app&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        let result = try sut.parse(uri: uri)

        #expect(result.clientIdentifierPrefix == .preRegistered(fullClientID: "my-verifier-app"))
    }

    // MARK: - Error Cases

    @Test("Throws missingScheme for non-mdoc-openid4vp URI")
    func throwsMissingSchemeForWrongScheme() {
        let uri = URL(string: "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        #expect(throws: ValidationError.missingScheme) {
            try sut.parse(uri: uri)
        }
    }

    @Test("Throws missingClientID when client_id absent")
    func throwsMissingClientID() {
        let uri = URL(string: "mdoc-openid4vp://?request_uri=https%3A%2F%2Fexample.com%2Freq")!

        #expect(throws: ValidationError.missingClientID) {
            try sut.parse(uri: uri)
        }
    }

    @Test("Throws missingClientID when client_id is empty")
    func throwsMissingClientIDWhenEmpty() {
        let uri = URL(string: "mdoc-openid4vp://?client_id=&request_uri=https%3A%2F%2Fexample.com%2Freq")!

        #expect(throws: ValidationError.missingClientID) {
            try sut.parse(uri: uri)
        }
    }

    @Test("Throws missingRequestURI when request_uri absent")
    func throwsMissingRequestURI() {
        let uri = URL(string: "mdoc-openid4vp://?client_id=verifier")!

        #expect(throws: ValidationError.missingRequestURI) {
            try sut.parse(uri: uri)
        }
    }

    @Test("Throws invalidRequestURI when request_uri is not a valid URL")
    func throwsInvalidRequestURI() {
        let uri = URL(string: "mdoc-openid4vp://?client_id=verifier&request_uri=not%20a%20valid%20url")!

        #expect(throws: ValidationError.invalidRequestURI) {
            try sut.parse(uri: uri)
        }
    }

    // MARK: - Nonce Validation Helper

    // isASCIIURLSafe is retained for RequestValidator's request-object nonce/state checks.

    @Test("isASCIIURLSafe accepts alphanumeric with -._~")
    func acceptsValidNonceChars() {
        #expect(URIParser.isASCIIURLSafe("abcXYZ0123-._~"))
    }

    @Test("isASCIIURLSafe rejects spaces")
    func rejectsSpaces() {
        #expect(!URIParser.isASCIIURLSafe("has space"))
    }

    @Test("isASCIIURLSafe rejects @#$% characters")
    func rejectsSpecialCharacters() {
        #expect(!URIParser.isASCIIURLSafe("bad@#$%"))
    }

    @Test("isASCIIURLSafe rejects forward slash")
    func rejectsForwardSlash() {
        #expect(!URIParser.isASCIIURLSafe("path/segment"))
    }
}
