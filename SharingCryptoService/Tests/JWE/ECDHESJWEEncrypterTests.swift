import CryptoKit
import Foundation
@testable import SharingCryptoService
import Testing

@Suite("ECDHESJWEEncrypter Tests")
struct ECDHESJWEEncrypterTests {
    /// Builds verifier key material from a real P-256 key so the coordinates are genuinely on-curve.
    private func makeVerifierKey(
        from privateKey: P256.KeyAgreement.PrivateKey,
        keyID: String? = "verifier-key-1"
    ) -> VerifierPublicKeyMaterial {
        VerifierPublicKeyMaterial(
            xCoordinate: privateKey.publicKey.xCoordinate,
            yCoordinate: privateKey.publicKey.yCoordinate,
            keyID: keyID
        )
    }

    // MARK: - Structure

    @Test("Produces a five-segment compact JWE with an empty encrypted-key segment")
    func producesCompactStructure() throws {
        let sut = ECDHESJWEEncrypter()
        let verifierKey = makeVerifierKey(from: P256.KeyAgreement.PrivateKey())

        let jwe = try sut.encrypt(
            plaintext: Data("payload".utf8),
            verifierKey: verifierKey,
            agreementPartyUInfo: Data("nonce-u".utf8),
            agreementPartyVInfo: Data("nonce-v".utf8)
        )

        let segments = jwe.components(separatedBy: ".")
        #expect(segments.count == 5)
        #expect(segments[1].isEmpty)

        let iv = try #require(Data(base64URLEncoded: segments[2]))
        let tag = try #require(Data(base64URLEncoded: segments[4]))
        #expect(iv.count == 12)
        #expect(tag.count == 16)
    }

    @Test("Protected header carries the ECDH-ES / A256GCM parameters and epk")
    func headerCarriesExpectedParameters() throws {
        let sut = ECDHESJWEEncrypter()
        let verifierKey = makeVerifierKey(from: P256.KeyAgreement.PrivateKey())

        let jwe = try sut.encrypt(
            plaintext: Data("payload".utf8),
            verifierKey: verifierKey,
            agreementPartyUInfo: Data("Alice".utf8),
            agreementPartyVInfo: Data("Bob".utf8)
        )

        let headerSegment = try #require(jwe.components(separatedBy: ".").first)
        let headerData = try #require(Data(base64URLEncoded: headerSegment))
        let header = try #require(try JSONSerialization.jsonObject(with: headerData) as? [String: Any])

        #expect(header["alg"] as? String == "ECDH-ES")
        #expect(header["enc"] as? String == "A256GCM")
        #expect(header["kid"] as? String == "verifier-key-1")
        #expect(header["apu"] as? String == Data("Alice".utf8).base64URLEncodedString())
        #expect(header["apv"] as? String == Data("Bob".utf8).base64URLEncodedString())

        let epk = try #require(header["epk"] as? [String: Any])
        #expect(epk["kty"] as? String == "EC")
        #expect(epk["crv"] as? String == "P-256")
        #expect(epk["x"] is String)
        #expect(epk["y"] is String)
    }

    @Test("Omits kid from the header when the verifier key has none")
    func omitsKidWhenAbsent() throws {
        let sut = ECDHESJWEEncrypter()
        let verifierKey = makeVerifierKey(from: P256.KeyAgreement.PrivateKey(), keyID: nil)

        let jwe = try sut.encrypt(
            plaintext: Data("payload".utf8),
            verifierKey: verifierKey,
            agreementPartyUInfo: Data(),
            agreementPartyVInfo: Data()
        )

        let headerSegment = try #require(jwe.components(separatedBy: ".").first)
        let headerData = try #require(Data(base64URLEncoded: headerSegment))
        let header = try #require(try JSONSerialization.jsonObject(with: headerData) as? [String: Any])

        #expect(header["kid"] == nil)
    }

    // MARK: - Round trip

    @Test("Verifier can re-derive the key and decrypt the payload")
    func roundTripDecrypts() throws {
        let verifierPrivateKey = P256.KeyAgreement.PrivateKey()
        let sut = ECDHESJWEEncrypter()
        let plaintext = Data("the selectively disclosed response".utf8)
        let apu = Data("mdoc-generated-nonce".utf8)
        let apv = Data("verifier-nonce".utf8)

        let jwe = try sut.encrypt(
            plaintext: plaintext,
            verifierKey: makeVerifierKey(from: verifierPrivateKey),
            agreementPartyUInfo: apu,
            agreementPartyVInfo: apv
        )

        // Reproduce the verifier side: read epk, agree, derive the CEK, and open the sealed box.
        let segments = jwe.components(separatedBy: ".")
        let headerSegment = segments[0]
        let headerData = try #require(Data(base64URLEncoded: headerSegment))
        let header = try #require(try JSONSerialization.jsonObject(with: headerData) as? [String: Any])
        let epk = try #require(header["epk"] as? [String: Any])
        let epkX = try #require(Data(base64URLEncoded: try #require(epk["x"] as? String)))
        let epkY = try #require(Data(base64URLEncoded: try #require(epk["y"] as? String)))

        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: Data([0x04]) + epkX + epkY
        )
        let sharedSecret = try verifierPrivateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        let contentEncryptionKey = ConcatKDF.deriveKey(
            sharedSecret: sharedSecret,
            algorithmID: Data("A256GCM".utf8),
            partyUInfo: apu,
            partyVInfo: apv,
            keyDataLengthBits: 256
        )

        let iv = try #require(Data(base64URLEncoded: segments[2]))
        let ciphertext = try #require(Data(base64URLEncoded: segments[3]))
        let tag = try #require(Data(base64URLEncoded: segments[4]))
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: iv),
            ciphertext: ciphertext,
            tag: tag
        )
        let decrypted = try AES.GCM.open(
            sealedBox,
            using: contentEncryptionKey,
            authenticating: Data(headerSegment.utf8)
        )

        #expect(decrypted == plaintext)
    }

    // MARK: - Failure

    @Test("Throws invalidVerifierKey for off-curve coordinates")
    func throwsForInvalidVerifierKey() {
        let sut = ECDHESJWEEncrypter()
        let invalidKey = VerifierPublicKeyMaterial(
            xCoordinate: Array(repeating: 0xff, count: 32),
            yCoordinate: Array(repeating: 0xff, count: 32),
            keyID: nil
        )

        #expect(throws: JWEEncryptionError.invalidVerifierKey) {
            try sut.encrypt(
                plaintext: Data("payload".utf8),
                verifierKey: invalidKey,
                agreementPartyUInfo: Data(),
                agreementPartyVInfo: Data()
            )
        }
    }
}
