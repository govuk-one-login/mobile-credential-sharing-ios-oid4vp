import Foundation
import SharingCryptoService
import SharingNetworkTransport
import SharingPrerequisiteGate
import SharingValidationService
import SwiftCBOR

/// Orchestrates the OID4VP (Remote) presentation flow initiated by an `mdoc-openid4vp://` deeplink.
///
/// Mirrors `ISOHolderOrchestrator` but drives the request-side pipeline: parse the engagement URI,
/// fetch and verify the signed Authorization Request Object, validate it, map the DCQL query to an
/// ISO `DeviceRequest`, then await user consent. On approval it builds the `SessionTranscript`, signs
/// the `DeviceAuth`, assembles the `DeviceResponse`, JWE-encrypts it and PUTs it to the verifier's
/// `response_uri`.
@MainActor
public class RemoteHolderOrchestrator: HolderOrchestratorProtocol {
    private(set) var session: RemoteHolderSessionProtocol?
    public weak var delegate: HolderOrchestratorDelegate?

    /// The verifier's DNS name (or other identifier) from the validated request, once available.
    public var verifierIdentifier: String? {
        session?.validatedRequest?.clientIdentifierPrefix.identifier
    }

    private let deeplink: URL
    private let remoteTransport: RemoteTransportProtocol
    private let uriParser: URIParser
    private let signatureVerifier: SignatureVerifying
    private let requestValidator: RequestValidator
    private let dcqlMapper: DCQLMapper
    private let credentialRequestHandler: CredentialRequestHandlerProtocol
    private let sessionTranscriptBuilder: OID4VPSessionTranscriptBuilder
    private let cryptoService: CryptoServiceProtocol
    private let jweEncrypter: JWEEncrypting

    /// Creates an orchestrator for a single Remote sharing journey.
    /// - Parameters:
    ///   - deeplink: the `mdoc-openid4vp://` engagement URL that started the journey.
    ///   - remoteTransport: fetches the request object and submits the response.
    ///   - credentialRequestHandler: retrieves the credential, filters it, and signs the DeviceAuth.
    /// The remaining parameters are collaborators with production defaults, overridable for testing.
    public init(
        deeplink: URL,
        remoteTransport: RemoteTransportProtocol,
        credentialRequestHandler: CredentialRequestHandlerProtocol,
        uriParser: URIParser = URIParser(),
        signatureVerifier: SignatureVerifying = JWTSignatureVerifier(),
        requestValidator: RequestValidator = RequestValidator(),
        dcqlMapper: DCQLMapper = DCQLMapper(),
        sessionTranscriptBuilder: OID4VPSessionTranscriptBuilder = OID4VPSessionTranscriptBuilder(),
        cryptoService: CryptoServiceProtocol = CryptoService(sessionDecryption: SessionDecryption()),
        jweEncrypter: JWEEncrypting = ECDHESJWEEncrypter()
    ) {
        self.deeplink = deeplink
        self.remoteTransport = remoteTransport
        self.credentialRequestHandler = credentialRequestHandler
        self.uriParser = uriParser
        self.signatureVerifier = signatureVerifier
        self.requestValidator = requestValidator
        self.dcqlMapper = dcqlMapper
        self.sessionTranscriptBuilder = sessionTranscriptBuilder
        self.cryptoService = cryptoService
        self.jweEncrypter = jweEncrypter
    }

    public func start() {
        print("Remote Presentation Session started")
        Task {
            await processRequest()
        }
    }

    func processRequest() async {
        if session == nil {
            session = RemoteHolderSession()
        }
        guard let session = getSession() else { return }
        do {
            let uriMetadata = try uriParser.parse(uri: deeplink)

            try session.transition(to: .remoteFetchingRequest)
            delegate?.orchestrator(didUpdateState: session.currentState)

            let jwt = try await remoteTransport.fetchRequestObject(from: uriMetadata.requestURI)

            try session.transition(to: .remoteValidatingRequest)
            delegate?.orchestrator(didUpdateState: session.currentState)

            let verifiedJWT = try signatureVerifier.verify(jwt: jwt)
            let requestObject = try VerifiedRequestObject(
                headerData: verifiedJWT.headerData,
                payloadData: verifiedJWT.payloadData,
                leafCertificateSANs: verifiedJWT.leafCertificateSANs
            )
            let validatedRequest = try requestValidator.validate(
                requestObject: requestObject,
                uriMetadata: uriMetadata
            )

            let deviceRequest = try buildDeviceRequest(from: validatedRequest)
            try session.setValidatedRequest(validatedRequest, deviceRequest: deviceRequest)

            // Retrieve the matching credential and filter it to the requested
            // attributes (selective disclosure) before showing consent, mirroring the ISO flow.
            try await credentialRequestHandler.requestAndValidateCredential(for: deviceRequest, in: session)
            try credentialRequestHandler.filterIssuerSigned(for: deviceRequest, in: session)

            try session.transition(to: .awaitingUserConsent(deviceRequest))
            delegate?.orchestrator(didUpdateState: session.currentState)
        } catch {
            handleFailure(error)
        }
    }

    /// The `RequestValidator` guarantees at least one `mso_mdoc` credential query survives, so the
    /// PoC maps the first one to a single-document `DeviceRequest`.
    private func buildDeviceRequest(from request: ValidatedRequest) throws -> DeviceRequest {
        guard let credential = request.dcqlQuery.credentials.first else {
            throw SessionError.generic("No credential query in validated request")
        }
        let itemsRequest = try dcqlMapper.mapToItemsRequest(credential)
        return DeviceRequest(docRequests: [DocRequest(itemsRequest: itemsRequest)])
    }

    public func userDidApprove() {
        guard let session = getSession() else { return }
        do {
            try session.transition(to: .processingResponse)
            delegate?.orchestrator(didUpdateState: session.currentState)
            Task {
                await prepareResponse()
            }
        } catch {
            handleFailure(error)
        }
    }

    /// Builds and submits the device-signed response after user approval: build the `SessionTranscript`,
    /// sign the `DeviceAuth`, then assemble → encode → JWE-encrypt → PUT.
    func prepareResponse() async {
        guard let session = getSession() else { return }
        do {
            try buildSessionTranscript(in: session)

            // Build the DeviceAuthentication bytes, sign them via the consumer's device key,
            // and assemble the COSE_Sign1 DeviceSigned.
            try cryptoService.constructDeviceAuthenticationBytes(in: session)
            try await credentialRequestHandler.signDeviceAuthenticationBytes(in: session)
            try cryptoService.generateDeviceSigned(in: session)

            try await assembleAndSubmitResponse(in: session)

            try session.transition(to: .success)
            delegate?.orchestrator(didUpdateState: session.currentState)
        } catch {
            handleFailure(error)
        }
    }

    /// Assembles the `DeviceResponse` from the disclosed credential and device signature, wraps it in the
    /// OID4VP `vp_token` response object, JWE-encrypts it for the verifier, and PUTs it to the `response_uri`.
    private func assembleAndSubmitResponse(in session: RemoteHolderSessionProtocol) async throws {
        guard let request = session.validatedRequest else {
            throw SessionError.generic("Validated request missing while assembling the response")
        }
        guard let docType = session.docType,
              let issuerSigned = session.issuerSigned,
              let deviceSigned = session.deviceSigned else {
            throw SessionError.generic("Response elements missing while assembling the response")
        }

        // Build the single-document DeviceResponse and CBOR-encode it.
        let document = Document(docType: docType, issuerSigned: issuerSigned, deviceSigned: deviceSigned)
        let deviceResponse = DeviceResponse(documents: [document], status: .ok)
        let deviceResponseBytes = Data(deviceResponse.encode(options: CBOROptions()))

        // Wrap in the OID4VP Authorization Response object: the base64url CBOR DeviceResponse under vp_token.
        let plaintext = try encodeVPToken(deviceResponseBytes: deviceResponseBytes)

        // JWE-encrypt for the verifier. apu = mdocGeneratedNonce, apv = the verifier's nonce.
        let jwe = try jweEncrypter.encrypt(
            plaintext: plaintext,
            verifierKey: verifierKey(from: request.verifierEncryptionKey),
            agreementPartyUInfo: Data(session.mdocGeneratedNonce ?? []),
            agreementPartyVInfo: Data(request.nonce.utf8)
        )

        // PUT the compact JWE to the presigned response URL.
        try await remoteTransport.submitResponse(encryptedResponse: jwe, to: request.responseURI)
    }

    /// Encodes the OID4VP Authorization Response object: the base64url CBOR `DeviceResponse` nested under
    /// `vp_token`, keyed by the credential identifier. This JSON is the plaintext the JWE encrypts.
    private func encodeVPToken(deviceResponseBytes: Data) throws -> Data {
        let authorizationResponse = AuthorizationResponse(
            vpToken: ["mDL": deviceResponseBytes.base64URLEncodedString()]
        )
        do {
            return try JSONEncoder().encode(authorizationResponse)
        } catch {
            throw SessionError.generic("Failed to encode the vp_token response object")
        }
    }

    /// Bridges the validation module's decoded key to the crypto module's key type (field-identical).
    private func verifierKey(from key: VerifierEncryptionKey) -> VerifierPublicKeyMaterial {
        VerifierPublicKeyMaterial(
            xCoordinate: key.xCoordinate,
            yCoordinate: key.yCoordinate,
            keyID: key.keyID
        )
    }

    /// Binds the response to this request by building the OID4VP `SessionTranscript` and the
    /// `mdocGeneratedNonce` reused as the JWE `apu`, storing both for the response-building steps.
    private func buildSessionTranscript(in session: RemoteHolderSessionProtocol) throws {
        guard let request = session.validatedRequest else {
            throw SessionError.generic("Validated request missing while building the session transcript")
        }
        let transcript = sessionTranscriptBuilder.build(
            clientID: request.clientID,
            responseURI: request.responseURI.absoluteString,
            verifierNonce: request.nonce
        )
        try session.setSessionTranscript(
            transcript.sessionTranscript,
            bytes: transcript.sessionTranscriptBytes,
            mdocGeneratedNonce: transcript.mdocGeneratedNonce
        )
    }

    public func userDidDeny() {
        transitionToCancel()
        session = nil
    }

    public func cancel() {
        transitionToCancel()
        session = nil
    }

    public func resolve(_: MissingPrerequisite) {
        // Remote flow has no prerequisite gate; nothing to resolve.
    }

    private func transitionToCancel() {
        guard let session = getSession() else { return }
        do {
            try session.transition(to: .cancelled)
            delegate?.orchestrator(didUpdateState: session.currentState)
        } catch {
            delegate?.orchestrator(didUpdateState: .failed(.generic(error.localizedDescription)))
        }
    }

    private func handleFailure(_ error: Error) {
        let sessionError = (error as? SessionError) ?? .generic(error.localizedDescription)
        try? session?.transition(to: .failed(sessionError))
        delegate?.orchestrator(didUpdateState: .failed(sessionError))
    }

    private func getSession() -> RemoteHolderSessionProtocol? {
        guard let session else {
            delegate?.orchestrator(didUpdateState: .failed(.generic("Session is not available.")))
            return nil
        }
        return session
    }
}

/// The OID4VP Authorization Response object carried as the JWE plaintext: a `vp_token` map keyed by the
/// credential identifier, whose value is the base64url-encoded CBOR `DeviceResponse`.
private struct AuthorizationResponse: Encodable {
    enum CodingKeys: String, CodingKey {
        case vpToken = "vp_token"
    }

    let vpToken: [String: String]
}
