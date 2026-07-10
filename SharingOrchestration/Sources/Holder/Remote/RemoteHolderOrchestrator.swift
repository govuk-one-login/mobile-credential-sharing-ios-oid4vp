import Foundation
import SharingCryptoService
import SharingNetworkTransport
import SharingPrerequisiteGate
import SharingValidationService

/// Orchestrates the OID4VP (Remote) presentation flow initiated by an `openid4vp://` deeplink.
///
/// Mirrors `ISOHolderOrchestrator` but drives the request-side pipeline: parse the engagement URI,
/// fetch and verify the signed Authorization Request Object, validate it, map the DCQL query to an
/// ISO `DeviceRequest`, then await user consent.
///
/// On approval it builds the SessionTranscript (Step 11) and the signed DeviceAuth (Step 12). Response
/// assembly/encryption/submission (Steps 13–16) is not yet implemented, so the flow still ends in `.failed`.
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

    public init(
        deeplink: URL,
        remoteTransport: RemoteTransportProtocol,
        credentialRequestHandler: CredentialRequestHandlerProtocol,
        uriParser: URIParser = URIParser(),
        signatureVerifier: SignatureVerifying = JWTSignatureVerifier(),
        requestValidator: RequestValidator = RequestValidator(),
        dcqlMapper: DCQLMapper = DCQLMapper(),
        sessionTranscriptBuilder: OID4VPSessionTranscriptBuilder = OID4VPSessionTranscriptBuilder(),
        cryptoService: CryptoServiceProtocol = CryptoService(sessionDecryption: SessionDecryption())
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

    /// Builds the device-signed response after user approval. Steps 11–12 are wired: build the
    /// SessionTranscript, then construct + sign + assemble the DeviceAuth. Steps 13–16 (DeviceResponse
    /// assembly, CBOR, JWE-of-response, PUT to response_uri) remain, so the flow still cannot complete.
    /// TODO: DCMAW-21231 — implement Steps 13–16.
    func prepareResponse() async {
        guard let session = getSession() else { return }
        do {
            try buildSessionTranscript(in: session)

            // Step 12: build the DeviceAuthentication bytes, sign them via the consumer's device key,
            // and assemble the COSE_Sign1 DeviceSigned.
            try cryptoService.constructDeviceAuthenticationBytes(in: session)
            try await credentialRequestHandler.signDeviceAuthenticationBytes(in: session)
            try cryptoService.generateDeviceSigned(in: session)

            try session.transition(to: .failed(.generic("Response building not yet implemented")))
            delegate?.orchestrator(didUpdateState: session.currentState)
        } catch {
            handleFailure(error)
        }
    }

    /// Step 11: binds the response to this request by building the OID4VP `SessionTranscript` and the
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
