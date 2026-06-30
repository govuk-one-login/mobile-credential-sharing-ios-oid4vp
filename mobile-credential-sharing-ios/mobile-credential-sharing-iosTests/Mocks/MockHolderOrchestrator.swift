import SharingOrchestration
import SharingPrerequisiteGate

class MockHolderOrchestrator: ISOHolderOrchestratorProtocol {
    weak var delegate: (any HolderOrchestratorDelegate)?

    var session: ISOHolderSession?
    var startPresentationCalled = false
    var cancelPresentationCalled = false

    func startPresentation() {
        startPresentationCalled = true
    }

    func resolve(_ missingPrerequisite: MissingPrerequisite) {
    }

    func userDidApprove() {
    }

    func userDidDeny() {
    }

    func cancel() {
        cancelPresentationCalled = true
    }
}
