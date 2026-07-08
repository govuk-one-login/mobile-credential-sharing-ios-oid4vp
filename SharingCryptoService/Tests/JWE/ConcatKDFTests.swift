import CryptoKit
import Foundation
@testable import SharingCryptoService
import Testing

@Suite("ConcatKDF Tests")
struct ConcatKDFTests {
    // RFC 7518 Appendix C — the worked ECDH-ES example. `Z` is the agreement output; apu="Alice",
    // apv="Bob", AlgorithmID="A128GCM", keydatalen=128. This is the authoritative correctness vector.
    private static let appendixCZ: [UInt8] = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
        38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
        140, 254, 144, 196
    ]

    private static let appendixCDerivedKey: [UInt8] = [
        86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
    ]

    @Test("Reproduces the RFC 7518 Appendix C derived key")
    func matchesAppendixCVector() {
        let key = ConcatKDF.deriveKey(
            sharedSecret: Data(Self.appendixCZ),
            algorithmID: Data("A128GCM".utf8),
            partyUInfo: Data("Alice".utf8),
            partyVInfo: Data("Bob".utf8),
            keyDataLengthBits: 128
        )

        #expect(Array(key.withUnsafeBytes(Array.init)) == Self.appendixCDerivedKey)
    }

    @Test("Derives a 256-bit key for A256GCM")
    func derives256BitKey() {
        let key = ConcatKDF.deriveKey(
            sharedSecret: Data(Self.appendixCZ),
            algorithmID: Data("A256GCM".utf8),
            partyUInfo: Data("apu".utf8),
            partyVInfo: Data("apv".utf8),
            keyDataLengthBits: 256
        )

        #expect(key.bitCount == 256)
    }

    @Test("Is deterministic for identical inputs")
    func isDeterministic() {
        func derive() -> [UInt8] {
            ConcatKDF.deriveKey(
                sharedSecret: Data(Self.appendixCZ),
                algorithmID: Data("A256GCM".utf8),
                partyUInfo: Data(),
                partyVInfo: Data(),
                keyDataLengthBits: 256
            ).withUnsafeBytes(Array.init)
        }

        #expect(derive() == derive())
    }

    @Test("Empty apu and apv still derive a key")
    func emptyPartyInfoDerivesKey() {
        let key = ConcatKDF.deriveKey(
            sharedSecret: Data(Self.appendixCZ),
            algorithmID: Data("A256GCM".utf8),
            partyUInfo: Data(),
            partyVInfo: Data(),
            keyDataLengthBits: 256
        )

        #expect(key.bitCount == 256)
    }
}
