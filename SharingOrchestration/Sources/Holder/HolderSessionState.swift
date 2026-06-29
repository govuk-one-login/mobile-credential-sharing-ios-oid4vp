import SharingCryptoService
import SharingPrerequisiteGate
import UIKit

// MARK: - SharingSessionState

public enum SharingSessionState: Equatable, Hashable, Sendable {

    /// Null-value object declaring that a User hasn't started a journey yet.
    case notStarted

    /// Device is checking prerequisites for the journey.
    case preflight(missingPrerequisites: [MissingPrerequisite])

    // BLE-specific states
    /// Device is ready to present encoded engagement data.
    case bleReadyToPresent

    /// Device is actively presenting engagement data.
    case blePresentingEngagement(qrCode: UIImage)

    /// Device has established initial connection to a verifier
    case bleProcessingEstablishment

    // Common states
    /// A request has been received & validated, awaiting users consent to share.
    case awaitingUserConsent(DeviceRequest)

    /// User is generating the response proof.
    case processingResponse

    /// The journey was successful
    case success

    /// There was an irrecoverable error
    case failed(SessionError)

    /// Journey has been cancelled by either Holder or Verifier
    case cancelled

    var kind: SharingSessionStateKind {
        switch self {
        case .notStarted: return .notStarted
        case .preflight: return .preflight
        case .bleReadyToPresent: return .bleReadyToPresent
        case .blePresentingEngagement: return .blePresentingEngagement
        case .bleProcessingEstablishment: return .bleProcessingEstablishment
        case .awaitingUserConsent: return .awaitingUserConsent
        case .processingResponse: return .processingResponse
        case .success: return .success
        case .failed: return .failed
        case .cancelled: return .cancelled
        }
    }

    var legalStateTransitions: [SharingSessionStateKind: [SharingSessionStateKind]] {
        [
            .notStarted: [.preflight, .bleReadyToPresent, .failed, .cancelled],
            .preflight: [.preflight, .bleReadyToPresent, .failed, .cancelled],
            .bleReadyToPresent: [.blePresentingEngagement, .failed, .cancelled],
            .blePresentingEngagement: [.bleProcessingEstablishment, .failed, .cancelled],
            .bleProcessingEstablishment: [.awaitingUserConsent, .failed, .cancelled],
            .awaitingUserConsent: [.processingResponse, .failed, .cancelled],
            .processingResponse: [.success, .failed, .cancelled],
            .success: [],
            .failed: [],
            .cancelled: []
        ]
    }
}

enum SharingSessionStateKind: String, Hashable {
    case notStarted
    case preflight
    case bleReadyToPresent
    case blePresentingEngagement
    case bleProcessingEstablishment
    case awaitingUserConsent
    case processingResponse
    case success
    case failed
    case cancelled
}

// MARK: - State Transitions

extension SharingSessionState {
    /// Defines whether the current state can transition to the next state.
    func canTransition(to nextState: SharingSessionState) -> Bool {
        guard let transitions = legalStateTransitions[self.kind] else {
            print("Error: Missing transition entry for \(self.kind)")
            return false
        }
        return transitions.contains(nextState.kind)
    }
}

enum SharingSessionTransitionError: LocalizedError, Equatable {
    case invalidTransition(from: SharingSessionState, to: SharingSessionState? = nil)

    var errorDescription: String? {
        switch self {
        case .invalidTransition(from: let from, to: let to):
            return "Invalid state transition: \(from.kind.rawValue) -> \(to?.kind.rawValue ?? "nil")"
        }
    }
}
