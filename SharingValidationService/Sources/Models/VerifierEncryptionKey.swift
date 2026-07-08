import Foundation

/// The verifier's EC P-256 public key for encrypting the Authorization Response, decoded from
/// `client_metadata.jwks.keys[]`.
///
/// This is a pure value type carrying only the raw coordinate bytes and optional key id — the
/// validation module performs no cryptography. The crypto module reconstructs a usable key from
/// these coordinates when building the JWE.
public struct VerifierEncryptionKey: Sendable, Equatable {
    /// The `x` coordinate of the P-256 public point (32 bytes).
    public let xCoordinate: [UInt8]

    /// The `y` coordinate of the P-256 public point (32 bytes).
    public let yCoordinate: [UInt8]

    /// The JWK `kid`, echoed into the JWE protected header so the verifier can select the key. May be absent.
    public let keyID: String?

    public init(xCoordinate: [UInt8], yCoordinate: [UInt8], keyID: String?) {
        self.xCoordinate = xCoordinate
        self.yCoordinate = yCoordinate
        self.keyID = keyID
    }
}
