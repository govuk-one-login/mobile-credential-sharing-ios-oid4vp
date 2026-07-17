import Foundation
import SharingCryptoService
import SharingValidationService

// MARK: - RemoteHolderSession protocol

/// The in-flight state for the OID4VP (Remote) flow: the validated request and mapped device request,
/// the matched credential and disclosed items, and the response-construction artefacts. State-changing
/// operations are gated to the session's current lifecycle state.
public protocol RemoteHolderSessionProtocol:
    CredentialSessionProtocol, ResponseConstructionSessionProtocol, Sendable {
    var currentState: HolderSessionState { get }
    var verifiedRequestObject: VerifiedRequestObject? { get }
    var validatedRequest: ValidatedRequest? { get }
    var deviceRequest: DeviceRequest? { get }
    var sessionTranscriptBytes: [UInt8]? { get }
    var mdocGeneratedNonce: [UInt8]? { get }

    func transition(to state: HolderSessionState) throws
    func setVerifiedRequestObject(_ requestObject: VerifiedRequestObject) throws
    func setValidatedRequest(_ request: ValidatedRequest, deviceRequest: DeviceRequest) throws
    func setSessionTranscript(
        _ transcript: SessionTranscript,
        bytes: [UInt8],
        mdocGeneratedNonce: [UInt8]
    ) throws
}

// MARK: - RemoteHolderSession
/// In-flight state for the OID4VP (Remote) presentation flow. Mirrors `ISOHolderSession` but holds
/// the request-side artefacts (validated request + mapped `DeviceRequest`) rather than BLE/crypto engagement data.
public final class RemoteHolderSession: RemoteHolderSessionProtocol, @unchecked Sendable {
    public private(set) var currentState: HolderSessionState = .notStarted
    public private(set) var verifiedRequestObject: VerifiedRequestObject?
    public private(set) var validatedRequest: ValidatedRequest?
    public private(set) var deviceRequest: DeviceRequest?

    // CredentialSessionProtocol
    public private(set) var matchedCredential: Credential?
    public private(set) var issuerSigned: IssuerSigned?

    // Response-building artefacts (SessionTranscript + nonce)
    public private(set) var sessionTranscript: SessionTranscript?
    public private(set) var sessionTranscriptBytes: [UInt8]?
    public private(set) var mdocGeneratedNonce: [UInt8]?

    // ResponseConstructionSessionProtocol (DeviceAuth)
    public private(set) var deviceAuthenticationBytes: Data?
    public private(set) var signatureBytes: Data?
    public private(set) var deviceSigned: DeviceSigned?

    /// The requested document type, taken from the mapped device request. The Remote flow validates a
    /// single-document request, so the first doc request's docType is authoritative.
    public var docType: DocType? {
        deviceRequest?.docRequests.first?.itemsRequest.docType
    }

    init(_ initialState: HolderSessionState = .notStarted) {
        self.currentState = initialState
    }

    public func transition(to state: HolderSessionState) throws {
        guard currentState.canTransition(to: state) else {
            throw HolderSessionTransitionError.invalidTransition(from: currentState, to: state)
        }
        currentState = state
        print("State transitioned to: \(currentState)")
    }

    public func setVerifiedRequestObject(_ requestObject: VerifiedRequestObject) throws {
        guard currentState.kind == .remoteValidatingRequest else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.verifiedRequestObject = requestObject
    }

    public func setValidatedRequest(_ request: ValidatedRequest, deviceRequest: DeviceRequest) throws {
        guard currentState.kind == .remoteValidatingRequest else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.validatedRequest = request
        self.deviceRequest = deviceRequest
    }

    public func setMatchedCredential(_ credential: Credential) throws {
        guard currentState.kind == .remoteValidatingRequest else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.matchedCredential = credential
    }

    public func setIssuerSigned(_ issuerSigned: IssuerSigned) throws {
        guard currentState.kind == .remoteValidatingRequest else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.issuerSigned = issuerSigned
    }

    public func setSessionTranscript(
        _ transcript: SessionTranscript,
        bytes: [UInt8],
        mdocGeneratedNonce: [UInt8]
    ) throws {
        guard currentState.kind == .processingResponse else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.sessionTranscript = transcript
        self.sessionTranscriptBytes = bytes
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }

    public func setDeviceAuthenticationBytes(_ bytes: Data) throws {
        guard currentState.kind == .processingResponse else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.deviceAuthenticationBytes = bytes
    }

    public func setSignatureBytes(_ bytes: Data) throws {
        guard currentState.kind == .processingResponse else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.signatureBytes = bytes
    }

    public func setDeviceSigned(deviceSigned: DeviceSigned) throws {
        guard currentState.kind == .processingResponse else {
            throw SessionError.incorrectSessionState(currentState.kind.rawValue)
        }
        self.deviceSigned = deviceSigned
    }
}
