import SharingOrchestration

class MockHolderOrchestratorDelegate: HolderOrchestratorDelegate {
    var stateToRender: SharingSessionState?

    func orchestrator(didUpdateState state: SharingSessionState?) {
        stateToRender = state
    }
}
