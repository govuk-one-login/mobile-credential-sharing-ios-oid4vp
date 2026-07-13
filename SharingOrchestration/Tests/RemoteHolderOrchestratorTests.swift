import Foundation
import SharingCryptoService
import SharingNetworkTransport
@testable import SharingOrchestration
import SharingValidationService
import Testing

@MainActor
@Suite("RemoteHolderOrchestrator Tests")
struct RemoteHolderOrchestratorTests {
    // Valid on-curve P-256 coordinates, so the JWE encrypter can genuinely encrypt in the happy path.
    private static let validEncryptionKeyX = "n-1U0E8Lzhw3-siUNeCoxZ_hnzk3zRaxr3h_CWhmU20"
    private static let validEncryptionKeyY = "1BGNUjUn56xMzHHuNBdsnepTxyubagfVZ_csJVJ_YaQ"

    // A well-formed engagement URI whose client_id matches the request object's SAN + client_id.
    let deeplink = URL(string: "mdoc-openid4vp://?client_id=x509_san_dns%3Averifier.example.com"
        + "&request_uri=https%3A%2F%2Fverifier.example.com%2Freq")!

    private func makeVerifiedJWT(
        encryptionKeyX: String = validEncryptionKeyX,
        encryptionKeyY: String = validEncryptionKeyY
    ) -> VerifiedJWT {
        let header = Data(#"{"typ":"JWT","alg":"ES256"}"#.utf8)
        let payload = Data("""
        {
            "aud": "https://self-issued.me/v2",
            "client_id": "x509_san_dns:verifier.example.com",
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "client_metadata": {
                "jwks": {
                    "keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "use": "enc",
                            "alg": "ECDH-ES",
                            "x": "\(encryptionKeyX)",
                            "y": "\(encryptionKeyY)",
                            "kid": "verifier-key-1"
                        }
                    ]
                }
            },
            "dcql_query": {
                "credentials": [
                    {
                        "id": "mdl",
                        "format": "mso_mdoc",
                        "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                        "claims": [
                            { "path": ["org.iso.18013.5.1", "family_name"] },
                            { "path": ["org.iso.18013.5.1", "given_name"] }
                        ]
                    }
                ]
            }
        }
        """.utf8)
        return VerifiedJWT(
            headerData: header,
            payloadData: payload,
            leafCertificateSANs: ["verifier.example.com"]
        )
    }

    private func makeSUT(
        transport: RemoteTransportProtocol,
        verifier: SignatureVerifying,
        handler: MockCredentialRequestHandler = MockCredentialRequestHandler(),
        jweEncrypter: JWEEncrypting = MockJWEEncrypter()
    ) -> (RemoteHolderOrchestrator, RecordingDelegate) {
        let sut = RemoteHolderOrchestrator(
            deeplink: deeplink,
            remoteTransport: transport,
            credentialRequestHandler: handler,
            signatureVerifier: verifier,
            jweEncrypter: jweEncrypter
        )
        let delegate = RecordingDelegate()
        sut.delegate = delegate
        return (sut, delegate)
    }

    // MARK: - Happy Path

    @Test("Runs fetch → validate → retrieve+filter → awaitingUserConsent and stores the mapped DeviceRequest")
    func happyPath() async throws {
        let handler = MockCredentialRequestHandler()
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT())),
            handler: handler
        )

        await sut.processRequest()

        #expect(delegate.states.map(\.kind) == [.remoteFetchingRequest, .remoteValidatingRequest, .awaitingUserConsent])
        guard case let .awaitingUserConsent(deviceRequest) = sut.session?.currentState else {
            Issue.record("Expected awaitingUserConsent")
            return
        }
        #expect(deviceRequest.docRequests.first?.itemsRequest.docType == .mdl)
        #expect(deviceRequest.docRequests.first?.itemsRequest.nameSpaces.first?.elements.map(\.identifier)
            == ["family_name", "given_name"])
        #expect(sut.verifierIdentifier == "verifier.example.com")
        #expect(handler.didCallFilterIssuerSigned == true)
    }

    @Test("verifierIdentifier is nil before the request is validated")
    func verifierIdentifierNilBeforeValidation() {
        let (sut, _) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT()))
        )

        #expect(sut.verifierIdentifier == nil)
    }

    // MARK: - Failure Paths

    @Test("Fetch error transitions to failed")
    func fetchErrorFails() async {
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(error: URLError(.notConnectedToInternet)),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT()))
        )

        await sut.processRequest()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Signature verification failure transitions to failed")
    func verificationFailureFails() async {
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .failure(.invalidSignature))
        )

        await sut.processRequest()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Validation failure (wrong audience) transitions to failed")
    func validationFailureFails() async {
        let header = Data(#"{"typ":"JWT","alg":"ES256"}"#.utf8)
        let payload = Data(#"{"aud":"wrong","response_type":"vp_token"}"#.utf8)
        let badJWT = VerifiedJWT(headerData: header, payloadData: payload, leafCertificateSANs: [])
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(badJWT))
        )

        await sut.processRequest()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Credential retrieval failure transitions to failed")
    func credentialRetrievalFailureFails() async {
        let handler = MockCredentialRequestHandler()
        handler.errorToThrow = CredentialRequestError.noCredentialsReturned
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT())),
            handler: handler
        )

        await sut.processRequest()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Selective-disclosure filter failure transitions to failed")
    func filterFailureFails() async {
        let handler = MockCredentialRequestHandler()
        handler.filterErrorToThrow = IssuerSignedFilterError.noMatchingAttributes
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT())),
            handler: handler
        )

        await sut.processRequest()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Malformed deeplink (missing scheme) transitions to failed before fetching")
    func malformedDeeplinkFails() async {
        let sut = RemoteHolderOrchestrator(
            deeplink: URL(string: "https://not-openid4vp.example.com")!,
            remoteTransport: MockRemoteTransport(jwt: "any.jwt.value"),
            credentialRequestHandler: MockCredentialRequestHandler(),
            signatureVerifier: MockSignatureVerifier(result: .success(makeVerifiedJWT()))
        )
        let delegate = RecordingDelegate()
        sut.delegate = delegate

        await sut.processRequest()

        #expect(delegate.states.map(\.kind) == [.failed])
    }

    // MARK: - User Decision

    @Test("Approval assembles, encrypts, and submits the response, reaching success")
    func approveSubmitsResponseAndSucceeds() async throws {
        let handler = MockCredentialRequestHandler()
        let transport = MockRemoteTransport(jwt: "any.jwt.value")
        let encrypter = MockJWEEncrypter()
        let (sut, delegate) = makeSUT(
            transport: transport,
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT())),
            handler: handler,
            jweEncrypter: encrypter
        )
        await sut.processRequest()

        // Drive the async response building directly (mirrors ISO's prepareDeviceSignedResponse test approach).
        try sut.session?.transition(to: .processingResponse)
        await sut.prepareResponse()

        // Transcript, nonce, and the signed DeviceAuth are on the session.
        #expect(sut.session?.sessionTranscript != nil)
        #expect(sut.session?.mdocGeneratedNonce?.count == 32)
        #expect(sut.session?.deviceSigned != nil)
        #expect(handler.didCallSignDeviceAuthenticationBytes == true)

        // The JWE plaintext is the OID4VP response object: base64url CBOR DeviceResponse under vp_token/mDL.
        let plaintext = try #require(encrypter.capturedPlaintext)
        let json = try #require(try JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
        let vpToken = try #require(json["vp_token"] as? [String: Any])
        let mdl = try #require(vpToken["mDL"] as? String)
        #expect(Data(base64URLEncoded: mdl) != nil)
        #expect(json.count == 1)

        // The produced JWE was PUT to the request's response URI, and the flow succeeded.
        let submitted = try #require(transport.submitted)
        #expect(submitted.url.absoluteString == "https://verifier.example.com/response")
        #expect(submitted.jwe == encrypter.stubbedJWE)
        #expect(delegate.states.last?.kind == .success)
    }

    @Test("Submit failure transitions to failed")
    func submitFailureFails() async throws {
        let transport = MockRemoteTransport(jwt: "any.jwt.value", submitError: URLError(.timedOut))
        let (sut, delegate) = makeSUT(
            transport: transport,
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT()))
        )
        await sut.processRequest()

        try sut.session?.transition(to: .processingResponse)
        await sut.prepareResponse()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("Off-curve verifier key transitions to failed at encryption")
    func invalidVerifierKeyFails() async throws {
        // Coordinates that decode to 32 bytes (so validation passes) but are not a P-256 point.
        let offCurveJWT = makeVerifiedJWT(
            encryptionKeyX: "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio",
            encryptionKeyY: "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3s"
        )
        // Use the real encrypter (not the mock default) so the off-curve key is actually rejected.
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(offCurveJWT)),
            jweEncrypter: ECDHESJWEEncrypter()
        )
        await sut.processRequest()

        try sut.session?.transition(to: .processingResponse)
        await sut.prepareResponse()

        #expect(delegate.states.last?.kind == .failed)
    }

    @Test("userDidDeny transitions to cancelled and clears the session")
    func denyCancels() async {
        let (sut, delegate) = makeSUT(
            transport: MockRemoteTransport(jwt: "any.jwt.value"),
            verifier: MockSignatureVerifier(result: .success(makeVerifiedJWT()))
        )
        await sut.processRequest()

        sut.userDidDeny()

        #expect(delegate.states.last?.kind == .cancelled)
        #expect(sut.session == nil)
    }
}

private final class RecordingDelegate: HolderOrchestratorDelegate {
    var states: [HolderSessionState] = []

    func orchestrator(didUpdateState state: HolderSessionState?) {
        if let state {
            states.append(state)
        }
    }
}
