import Foundation
import SharingCryptoService
@testable import SharingOrchestration
import SharingValidationService
import Testing

@Suite("RemoteHolderSession Tests")
struct RemoteHolderSessionTests {
    private func makeValidatedRequest() throws -> ValidatedRequest {
        ValidatedRequest(
            dcqlQuery: DCQLQuery(credentials: [], credentialSets: nil),
            responseURI: try #require(URL(string: "https://verifier.example.com/response")),
            state: nil,
            nonce: "abc123",
            clientID: "x509_san_dns:verifier.example.com",
            clientIdentifierPrefix: .x509SanDns(identifier: "verifier.example.com"),
            verifierEncryptionKey: VerifierEncryptionKey(
                xCoordinate: Array(repeating: 0x2a, count: 32),
                yCoordinate: Array(repeating: 0x7b, count: 32),
                keyID: "verifier-key-1"
            )
        )
    }

    private func makeDeviceRequest() -> DeviceRequest {
        DeviceRequest(docRequests: [
            DocRequest(itemsRequest: ItemsRequest(docType: .mdl, nameSpaces: []))
        ])
    }

    // MARK: - transition

    @Test("Legal transition updates the current state")
    func legalTransitionSucceeds() throws {
        let sut = RemoteHolderSession()

        try sut.transition(to: .remoteFetchingRequest)

        #expect(sut.currentState == .remoteFetchingRequest)
    }

    @Test("Illegal transition throws and leaves state unchanged")
    func illegalTransitionThrows() {
        let sut = RemoteHolderSession()

        #expect(throws: HolderSessionTransitionError.self) {
            // .notStarted cannot jump straight to .awaitingUserConsent
            try sut.transition(to: .awaitingUserConsent(makeDeviceRequest()))
        }
        #expect(sut.currentState == .notStarted)
    }

    // MARK: - setValidatedRequest

    @Test("setValidatedRequest stores the request when in remoteValidatingRequest state")
    func setValidatedRequestSucceeds() throws {
        let sut = RemoteHolderSession()
        try sut.transition(to: .remoteFetchingRequest)
        try sut.transition(to: .remoteValidatingRequest)

        let validatedRequest = try makeValidatedRequest()
        let deviceRequest = makeDeviceRequest()
        try sut.setValidatedRequest(validatedRequest, deviceRequest: deviceRequest)

        #expect(sut.validatedRequest == validatedRequest)
        #expect(sut.deviceRequest == deviceRequest)
    }

    @Test("setValidatedRequest throws when called from the wrong state")
    func setValidatedRequestThrowsFromWrongState() {
        let sut = RemoteHolderSession()

        #expect(throws: SessionError.incorrectSessionState(HolderSessionStateKind.notStarted.rawValue)) {
            try sut.setValidatedRequest(makeValidatedRequest(), deviceRequest: makeDeviceRequest())
        }
        #expect(sut.validatedRequest == nil)
        #expect(sut.deviceRequest == nil)
    }

    // MARK: - CredentialSessionProtocol setters

    @Test("setMatchedCredential and setIssuerSigned store values in remoteValidatingRequest state")
    func credentialSettersSucceed() throws {
        let sut = RemoteHolderSession()
        try sut.transition(to: .remoteFetchingRequest)
        try sut.transition(to: .remoteValidatingRequest)

        let credential = Credential(id: "cred-1", rawCredential: Data())
        let issuerSigned = IssuerSigned(nameSpaces: [:], issuerAuth: [])
        try sut.setMatchedCredential(credential)
        try sut.setIssuerSigned(issuerSigned)

        #expect(sut.matchedCredential?.id == "cred-1")
        #expect(sut.issuerSigned != nil)
    }

    @Test("setMatchedCredential throws when called from the wrong state")
    func setMatchedCredentialThrowsFromWrongState() {
        let sut = RemoteHolderSession()

        #expect(throws: SessionError.incorrectSessionState(HolderSessionStateKind.notStarted.rawValue)) {
            try sut.setMatchedCredential(Credential(id: "cred-1", rawCredential: Data()))
        }
        #expect(sut.matchedCredential == nil)
    }

    @Test("setIssuerSigned throws when called from the wrong state")
    func setIssuerSignedThrowsFromWrongState() {
        let sut = RemoteHolderSession()

        #expect(throws: SessionError.incorrectSessionState(HolderSessionStateKind.notStarted.rawValue)) {
            try sut.setIssuerSigned(IssuerSigned(nameSpaces: [:], issuerAuth: []))
        }
        #expect(sut.issuerSigned == nil)
    }

    // MARK: - setSessionTranscript

    private func makeTranscript() -> SessionTranscript {
        SessionTranscript(
            deviceEngagementBytes: nil,
            eReaderKeyBytes: nil,
            handover: .oid4vp(
                clientIdHash: Array(repeating: 0xaa, count: 32),
                responseUriHash: Array(repeating: 0xbb, count: 32),
                nonce: "abc123"
            )
        )
    }

    @Test("setSessionTranscript stores values in processingResponse state")
    func setSessionTranscriptSucceeds() throws {
        let sut = RemoteHolderSession()
        try sut.transition(to: .remoteFetchingRequest)
        try sut.transition(to: .remoteValidatingRequest)
        try sut.transition(to: .awaitingUserConsent(makeDeviceRequest()))
        try sut.transition(to: .processingResponse)

        let nonce: [UInt8] = Array(repeating: 0x2a, count: 32)
        try sut.setSessionTranscript(makeTranscript(), bytes: [0x01, 0x02], mdocGeneratedNonce: nonce)

        #expect(sut.sessionTranscript != nil)
        #expect(sut.sessionTranscriptBytes == [0x01, 0x02])
        #expect(sut.mdocGeneratedNonce == nonce)
    }

    @Test("setSessionTranscript throws when called from the wrong state")
    func setSessionTranscriptThrowsFromWrongState() {
        let sut = RemoteHolderSession()

        #expect(throws: SessionError.incorrectSessionState(HolderSessionStateKind.notStarted.rawValue)) {
            try sut.setSessionTranscript(makeTranscript(), bytes: [0x01], mdocGeneratedNonce: [0x02])
        }
        #expect(sut.sessionTranscript == nil)
        #expect(sut.mdocGeneratedNonce == nil)
    }
}
