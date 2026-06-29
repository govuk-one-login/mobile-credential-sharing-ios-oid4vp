import SharingOrchestration
import SharingPrerequisiteGate

class MockHolderOrchestrator: BLEHolderOrchestratorProtocol {
    weak var delegate: (any SharingOrchestratorDelegate)?

    var session: BLEHolderSession?
    var startPresentationCalled = false
    var cancelPresentationCalled = false
    var resolveCalled = false
    var userDidApproveCalled = false
    var userDidDenyCalled = false

    func startPresentation() {
        startPresentationCalled = true
    }

    func resolve(_ missingPrerequisite: MissingPrerequisite) {
        resolveCalled = true
    }

    func userDidApprove() {
        userDidApproveCalled = true
    }

    func userDidDeny() {
        userDidDenyCalled = true
    }

    func cancel() {
        cancelPresentationCalled = true
    }
}
