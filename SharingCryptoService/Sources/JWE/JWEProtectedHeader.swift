import Foundation

/// The JWE protected header for an ECDH-ES + A256GCM compact JWE (RFC 7518 §4.6).
///
/// `apu`/`apv` are the base64url-encoded agreement party info values, and `epk` carries the wallet's
/// ephemeral public key. Encoded with sorted keys so serialisation is deterministic — the base64url
/// header doubles as the AEAD additional authenticated data.
struct JWEProtectedHeader: Encodable {
    struct EphemeralPublicKey: Encodable {
        let kty = "EC"
        let crv = "P-256"
        let x: String
        let y: String
    }

    let alg = "ECDH-ES"
    let enc = "A256GCM"
    let epk: EphemeralPublicKey
    let apu: String
    let apv: String
    let kid: String?

    /// Serialises to the compact JWE first segment: `base64url(UTF-8(JSON))`.
    func encodedSegment() throws(JWEEncryptionError) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let json = try? encoder.encode(self) else {
            throw .headerSerializationFailed
        }
        return json.base64URLEncodedString()
    }
}
