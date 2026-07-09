import Foundation
import Networking
@testable import SharingNetworkTransport
import Testing

@Suite("SharingNetworkingClient Tests")
struct SharingNetworkingClientTests {

    // MARK: - fetchRequestObject

    @Test("fetchRequestObject returns JWT string on success")
    func fetchSuccess() async throws {
        let expectedJWT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciJ9.sig"
        let mock = MockNetworkClient(responseData: Data(expectedJWT.utf8))

        let client = SharingNetworkingClient(networkClient: { mock })
        let result = try await client.fetchRequestObject(
            from: URL(string: "https://verifier.example.com/request/abc")!
        )

        #expect(result == expectedJWT)
    }

    @Test("fetchRequestObject passes correct URL with GET method")
    func fetchPassesCorrectRequest() async throws {
        let mock = MockNetworkClient(responseData: Data("jwt".utf8))
        let url = URL(string: "https://verifier.example.com/request/123")!

        let client = SharingNetworkingClient(networkClient: { mock })
        _ = try await client.fetchRequestObject(from: url)

        let captured = mock.capturedRequests.first
        #expect(captured?.url == url)
        #expect(captured?.httpMethod == "GET")
    }

    @Test("fetchRequestObject throws encodingFailed for invalid UTF-8")
    func fetchInvalidUTF8() async throws {
        let invalidBytes: [UInt8] = [0xFF, 0xFE, 0xFD]
        let mock = MockNetworkClient(responseData: Data(invalidBytes))

        let client = SharingNetworkingClient(networkClient: { mock })

        await #expect(throws: NetworkTransportError.self) {
            try await client.fetchRequestObject(
                from: URL(string: "https://verifier.example.com/request")!
            )
        }
    }

    @Test("fetchRequestObject propagates network error")
    func fetchNetworkError() async throws {
        let mock = MockNetworkClient(error: URLError(.notConnectedToInternet))

        let client = SharingNetworkingClient(networkClient: { mock })

        await #expect(throws: (any Error).self) {
            try await client.fetchRequestObject(
                from: URL(string: "https://verifier.example.com/request")!
            )
        }
    }

    // MARK: - submitResponse

    @Test("submitResponse sends a PUT to the presigned URL")
    func submitSendsPutToUploadURL() async throws {
        let mock = MockNetworkClient(responseData: Data())
        let uploadURL = URL(string: "https://bucket.s3.example.com/response?X-Amz-Signature=abc")!

        let client = SharingNetworkingClient(networkClient: { mock })
        try await client.submitResponse(
            encryptedResponse: "encrypted.jwe.token",
            to: uploadURL
        )

        let captured = mock.capturedRequests.first
        #expect(captured?.url == uploadURL)
        #expect(captured?.httpMethod == "PUT")
        #expect(captured?.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
    }

    @Test("submitResponse sends the raw JWE as the request body")
    func submitSendsRawJWEBody() async throws {
        let mock = MockNetworkClient(responseData: Data())
        let jwe = "header..iv.ciphertext.tag"

        let client = SharingNetworkingClient(networkClient: { mock })
        try await client.submitResponse(
            encryptedResponse: jwe,
            to: URL(string: "https://bucket.s3.example.com/response")!
        )

        let body = try #require(mock.capturedRequests.first?.httpBody)
        #expect(String(data: body, encoding: .utf8) == jwe)
    }

    @Test("submitResponse propagates network error")
    func submitNetworkError() async throws {
        let mock = MockNetworkClient(error: URLError(.timedOut))

        let client = SharingNetworkingClient(networkClient: { mock })

        await #expect(throws: (any Error).self) {
            try await client.submitResponse(
                encryptedResponse: "token",
                to: URL(string: "https://bucket.s3.example.com/response")!
            )
        }
    }
}

private final class MockNetworkClient: NetworkClientProtocol, Sendable {
    let responseData: Data
    let error: Error?

    private let lock = NSLock()
    nonisolated(unsafe) private var _capturedRequests = [URLRequest]()
    
    var capturedRequests: [URLRequest] {
        lock.withLock {
            _capturedRequests
        }
    }

    init(responseData: Data = Data(), error: Error? = nil) {
        self.responseData = responseData
        self.error = error
    }

    func request(_ request: URLRequest) -> RequestBuilder {
        lock.withLock {
            _capturedRequests.append(request)
        }
        return RequestBuilder(client: self, request: request)
    }

    func makeRequest(_ request: NetworkRequest) async throws -> Data {
        if let error { throw error }
        return responseData
    }
}
