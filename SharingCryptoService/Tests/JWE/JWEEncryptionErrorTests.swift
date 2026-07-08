import Foundation
@testable import SharingCryptoService
import Testing

@Suite("JWEEncryptionError Tests")
struct JWEEncryptionErrorTests {
    @Test("Each case has a descriptive message")
    func errorDescriptions() {
        #expect(
            JWEEncryptionError.invalidVerifierKey.errorDescription
                == "Verifier encryption key is not a valid P-256 public key"
        )
        #expect(
            JWEEncryptionError.keyAgreementFailed.errorDescription
                == "ECDH-ES key agreement with the verifier key failed"
        )
        #expect(
            JWEEncryptionError.headerSerializationFailed.errorDescription
                == "Failed to serialise the JWE protected header"
        )
        #expect(
            JWEEncryptionError.encryptionFailed.errorDescription
                == "AES-256-GCM content encryption failed"
        )
    }
}
