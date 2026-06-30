import SharingOrchestration
import SharingPrerequisiteGate

class MockHolderOrchestrator: HolderOrchestratorProtocol {
    weak var delegate: (any HolderOrchestratorDelegate)?

    var session: ISOHolderSession?
    var startPresentationCalled = false
    var cancelPresentationCalled = false

    func start() {
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
