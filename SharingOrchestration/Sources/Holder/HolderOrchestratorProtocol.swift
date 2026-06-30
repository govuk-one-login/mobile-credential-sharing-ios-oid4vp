import Foundation
import SharingPrerequisiteGate

@MainActor
public protocol HolderOrchestratorProtocol: AnyObject {
    var delegate: HolderOrchestratorDelegate? { get set }
    func userDidApprove()
    func userDidDeny()
    func cancel()
}

public protocol HolderOrchestratorDelegate: AnyObject {
    func orchestrator(didUpdateState state: SharingSessionState?)
}

@MainActor
public protocol ISOHolderOrchestratorProtocol: HolderOrchestratorProtocol {
    func startPresentation()
    func resolve(_ missingPrerequisite: MissingPrerequisite)
}
