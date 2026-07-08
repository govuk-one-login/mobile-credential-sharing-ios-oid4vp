import CryptoKit
import Foundation

/// The verifier's EC P-256 encryption key, as raw coordinate bytes plus optional key id.
///
/// This is the crypto module's own value type so the JWE encrypter stays independent of the validation
/// module. The orchestrator builds it from the validated request's decoded key.
public struct VerifierPublicKeyMaterial: Sendable, Equatable {
    public let xCoordinate: [UInt8]
    public let yCoordinate: [UInt8]
    public let keyID: String?

    public init(xCoordinate: [UInt8], yCoordinate: [UInt8], keyID: String?) {
        self.xCoordinate = xCoordinate
        self.yCoordinate = yCoordinate
        self.keyID = keyID
    }

    /// Reconstructs the P-256 public key from the coordinates, reusing the uncompressed X9.63 layout
    /// (`0x04 || x || y`) that ``COSEKey`` conversions use.
    func publicKey() throws(JWEEncryptionError) -> P256.KeyAgreement.PublicKey {
        let x963 = Data([0x04] + xCoordinate + yCoordinate)
        guard let key = try? P256.KeyAgreement.PublicKey(x963Representation: x963) else {
            throw .invalidVerifierKey
        }
        return key
    }
}
