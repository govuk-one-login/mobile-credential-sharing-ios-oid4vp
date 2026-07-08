import CryptoKit
import Foundation

/// Produces a compact JWE using ECDH-ES direct key agreement (P-256) and A256GCM, per RFC 7518 §4.6.
///
/// A fresh ephemeral key pair is generated for each call; its public part is carried in the header `epk`
/// so the verifier can re-derive the content encryption key. The empty encrypted-key segment reflects
/// direct key agreement — the CEK is derived, never wrapped.
public struct ECDHESJWEEncrypter: JWEEncrypting {
    /// Supplies the wallet's ephemeral key. Overridable so tests can pin it for a deterministic round-trip;
    /// production generates a fresh key per call.
    private let makeEphemeralKey: @Sendable () -> P256.KeyAgreement.PrivateKey

    public init() {
        self.makeEphemeralKey = { P256.KeyAgreement.PrivateKey() }
    }

    init(makeEphemeralKey: @escaping @Sendable () -> P256.KeyAgreement.PrivateKey) {
        self.makeEphemeralKey = makeEphemeralKey
    }

    public func encrypt(
        plaintext: Data,
        verifierKey: VerifierPublicKeyMaterial,
        agreementPartyUInfo: Data,
        agreementPartyVInfo: Data
    ) throws(JWEEncryptionError) -> String {
        let verifierPublicKey = try verifierKey.publicKey()

        let ephemeralPrivateKey = makeEphemeralKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        guard let sharedSecret = try? ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: verifierPublicKey) else {
            throw .keyAgreementFailed
        }

        let contentEncryptionKey = ConcatKDF.deriveKey(
            sharedSecret: sharedSecret,
            algorithmID: Data("A256GCM".utf8),
            partyUInfo: agreementPartyUInfo,
            partyVInfo: agreementPartyVInfo,
            keyDataLengthBits: 256
        )

        let header = JWEProtectedHeader(
            epk: JWEProtectedHeader.EphemeralPublicKey(
                x: Data(ephemeralPublicKey.xCoordinate).base64URLEncodedString(),
                y: Data(ephemeralPublicKey.yCoordinate).base64URLEncodedString()
            ),
            apu: agreementPartyUInfo.base64URLEncodedString(),
            apv: agreementPartyVInfo.base64URLEncodedString(),
            kid: verifierKey.keyID
        )
        let headerSegment = try header.encodedSegment()

        // RFC 7516 §5.1: the AAD for the content encryption is ASCII(BASE64URL(protected header)).
        let additionalData = Data(headerSegment.utf8)
        let initializationVector = AES.GCM.Nonce()

        guard let sealedBox = try? AES.GCM.seal(
            plaintext,
            using: contentEncryptionKey,
            nonce: initializationVector,
            authenticating: additionalData
        ) else {
            throw .encryptionFailed
        }

        // Compact serialisation; the encrypted-key segment is empty for direct key agreement.
        return [
            headerSegment,
            "",
            Data(initializationVector).base64URLEncodedString(),
            sealedBox.ciphertext.base64URLEncodedString(),
            sealedBox.tag.base64URLEncodedString()
        ].joined(separator: ".")
    }
}
