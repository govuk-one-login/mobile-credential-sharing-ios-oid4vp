import Foundation
import SharingNetworkTransport

final class MockRemoteTransport: RemoteTransportProtocol {
    let jwt: String?
    let fetchError: (any Error & Sendable)?
    let submitError: (any Error & Sendable)?

    // Records the submitted response for assertions. Lock-guarded to satisfy `Sendable`.
    private let lock = NSLock()
    nonisolated(unsafe) private var _submitted: (jwe: String, url: URL)?
    var submitted: (jwe: String, url: URL)? {
        lock.withLock { _submitted }
    }

    init(jwt: String, submitError: (any Error & Sendable)? = nil) {
        self.jwt = jwt
        self.fetchError = nil
        self.submitError = submitError
    }

    init(error: any Error & Sendable) {
        self.jwt = nil
        self.fetchError = error
        self.submitError = nil
    }

    func fetchRequestObject(from requestURI: URL) async throws -> String {
        if let fetchError { throw fetchError }
        return jwt ?? ""
    }

    func submitResponse(encryptedResponse jwe: String, to uploadURL: URL) async throws {
        if let submitError { throw submitError }
        lock.withLock { _submitted = (jwe, uploadURL) }
    }
}
