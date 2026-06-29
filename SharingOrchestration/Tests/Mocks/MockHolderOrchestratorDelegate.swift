import SharingOrchestration

class MockHolderOrchestratorDelegate: SharingOrchestratorDelegate {
    var stateToRender: SharingSessionState?

    func orchestrator(didUpdateState state: SharingSessionState?) {
        stateToRender = state
    }
}
