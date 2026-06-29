import SharingOrchestration
import SharingPrerequisiteGate

class MockHolderOrchestrator: BLEHolderOrchestratorProtocol {
    weak var delegate: (any SharingOrchestratorDelegate)?

    var session: BLEHolderSession?
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
