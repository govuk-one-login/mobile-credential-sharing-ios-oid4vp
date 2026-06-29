import Foundation
import SharingPrerequisiteGate

@MainActor
public protocol SharingOrchestratorProtocol: AnyObject {
    var delegate: SharingOrchestratorDelegate? { get set }
    func userDidApprove()
    func userDidDeny()
    func cancel()
}

public protocol SharingOrchestratorDelegate: AnyObject {
    func orchestrator(didUpdateState state: SharingSessionState?)
}

@MainActor
public protocol BLEHolderOrchestratorProtocol: SharingOrchestratorProtocol {
    func startPresentation()
    func resolve(_ missingPrerequisite: MissingPrerequisite)
}
