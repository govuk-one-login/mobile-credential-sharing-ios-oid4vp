import Foundation
import SharingCryptoService

/// Captures the plaintext handed to the encrypter so tests can assert the vp_token envelope, and returns
/// a fixed JWE string so the submitted value can be checked without a real encryption round-trip.
final class MockJWEEncrypter: JWEEncrypting {
    let stubbedJWE = "stub.jwe.value.for.test"

    private let lock = NSLock()
    nonisolated(unsafe) private var _capturedPlaintext: Data?
    var capturedPlaintext: Data? {
        lock.withLock { _capturedPlaintext }
    }

    func encrypt(
        plaintext: Data,
        verifierKey: VerifierPublicKeyMaterial,
        agreementPartyUInfo: Data,
        agreementPartyVInfo: Data
    ) throws(JWEEncryptionError) -> String {
        lock.withLock { _capturedPlaintext = plaintext }
        return stubbedJWE
    }
}
