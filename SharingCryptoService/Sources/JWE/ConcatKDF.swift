import CryptoKit
import Foundation

/// The Concat KDF (NIST SP 800-56A §5.8.1) with SHA-256, as required by JWE ECDH-ES (RFC 7518 §4.6).
///
/// CryptoKit provides only the ANSI X9.63 and HKDF derivations, neither of which matches the Concat
/// construction JWE mandates, so the concatenation is assembled here and hashed with CryptoKit's SHA-256.
/// For the JWE key lengths in use (≤ 256 bits) the derived key is the first `keyDataLength` bits of a
/// single hash round, so no counter loop is needed; the round counter is still prepended for correctness.
enum ConcatKDF {
    /// Derives a symmetric key from an ECDH shared secret.
    ///
    /// - Parameters:
    ///   - sharedSecret: the ECDH shared secret `Z` (its raw bytes are hashed directly).
    ///   - algorithmID: the AlgorithmID content, e.g. ASCII `"A256GCM"` (length-prefixed internally).
    ///   - partyUInfo: the raw `apu` bytes (length-prefixed internally; *not* base64url).
    ///   - partyVInfo: the raw `apv` bytes (length-prefixed internally; *not* base64url).
    ///   - keyDataLengthBits: the desired key length in bits; also encoded as SuppPubInfo.
    /// - Returns: a `SymmetricKey` of `keyDataLengthBits / 8` bytes.
    static func deriveKey(
        sharedSecret: some ContiguousBytes,
        algorithmID: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        keyDataLengthBits: UInt32
    ) -> SymmetricKey {
        var input = Data()
        input.append(bigEndianBytes(1)) // round counter
        input.append(contentsOf: sharedSecret.withUnsafeBytes(Array.init))
        input.append(lengthPrefixed(algorithmID))
        input.append(lengthPrefixed(partyUInfo))
        input.append(lengthPrefixed(partyVInfo))
        input.append(bigEndianBytes(keyDataLengthBits)) // SuppPubInfo; SuppPrivInfo is empty

        let digest = SHA256.hash(data: input)
        let keyByteCount = Int(keyDataLengthBits) / 8
        let derivedKey = Array(digest).prefix(keyByteCount)
        return SymmetricKey(data: Data(derivedKey))
    }

    /// Prefixes `data` with its length as a 32-bit big-endian integer, per the Concat KDF OtherInfo format.
    private static func lengthPrefixed(_ data: Data) -> Data {
        bigEndianBytes(UInt32(data.count)) + data
    }

    private static func bigEndianBytes(_ value: UInt32) -> Data {
        Data(withUnsafeBytes(of: value.bigEndian, Array.init))
    }
}
