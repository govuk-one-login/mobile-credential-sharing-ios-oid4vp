import CryptoKit
import Foundation
@testable import SharingCryptoService
import SwiftCBOR
import Testing

@Suite("OID4VPSessionTranscriptBuilder Tests")
struct OID4VPSessionTranscriptBuilderTests {
    private let clientID = "x509_san_dns:verifier.example.com"
    private let responseURI = "https://verifier.example.com/response"
    private let verifierNonce = "verifier-nonce-123"
    private let fixedNonce: [UInt8] = Array(repeating: 0x2a, count: 32)

    private func makeSUT(nonce: [UInt8]) -> OID4VPSessionTranscriptBuilder {
        OID4VPSessionTranscriptBuilder(makeNonce: { nonce })
    }

    /// Independently recomputes SHA-256(CBOR([value, nonce])) to check the builder's hashing.
    private func expectedHash(of value: String, nonce: [UInt8]) -> [UInt8] {
        let encoded = CBOR.array([.utf8String(value), .byteString(nonce)]).encode()
        return Array(SHA256.hash(data: Data(encoded)))
    }

    private func decodeTranscriptArray(_ bytes: [UInt8]) throws -> [CBOR] {
        let decoded = try #require(try CBOR.decode(bytes))
        guard case let .tagged(tag, .byteString(inner)) = decoded else {
            Issue.record("Expected Tag 24 wrapping")
            return []
        }
        #expect(tag == .encodedCBORDataItem)
        let innerDecoded = try #require(try CBOR.decode(inner))
        guard case let .array(elements) = innerDecoded else {
            Issue.record("Expected SessionTranscript to be a CBOR array")
            return []
        }
        return elements
    }

    @Test("Transcript is [null, null, [clientIdHash, responseUriHash, nonce]]")
    func transcriptStructure() throws {
        let result = makeSUT(nonce: fixedNonce).build(
            clientID: clientID,
            responseURI: responseURI,
            verifierNonce: verifierNonce
        )

        let elements = try decodeTranscriptArray(result.sessionTranscriptBytes)
        #expect(elements.count == 3)
        #expect(elements[0] == .null)
        #expect(elements[1] == .null)

        guard case let .array(handover) = elements[2] else {
            Issue.record("Expected OID4VPHandover array")
            return
        }
        #expect(handover.count == 3)
        #expect(handover[0] == .byteString(expectedHash(of: clientID, nonce: fixedNonce)))
        #expect(handover[1] == .byteString(expectedHash(of: responseURI, nonce: fixedNonce)))
        #expect(handover[2] == .utf8String(verifierNonce))
    }

    @Test("Client id and response uri hashes are 32 bytes")
    func hashesAreCorrectLength() {
        let result = makeSUT(nonce: fixedNonce).build(
            clientID: clientID,
            responseURI: responseURI,
            verifierNonce: verifierNonce
        )

        guard case let .oid4vp(clientIdHash, responseUriHash, nonce) = result.sessionTranscript.handover else {
            Issue.record("Expected an OID4VP handover")
            return
        }
        #expect(clientIdHash.count == 32)
        #expect(responseUriHash.count == 32)
        #expect(nonce == verifierNonce)
    }

    @Test("mdocGeneratedNonce is returned and used in the hashes")
    func mdocGeneratedNonceIsReturned() {
        let result = makeSUT(nonce: fixedNonce).build(
            clientID: clientID,
            responseURI: responseURI,
            verifierNonce: verifierNonce
        )

        #expect(result.mdocGeneratedNonce == fixedNonce)
    }

    @Test("Building is deterministic for a fixed nonce")
    func deterministicForFixedNonce() {
        let sut = makeSUT(nonce: fixedNonce)
        let first = sut.build(clientID: clientID, responseURI: responseURI, verifierNonce: verifierNonce)
        let second = sut.build(clientID: clientID, responseURI: responseURI, verifierNonce: verifierNonce)

        #expect(first.sessionTranscriptBytes == second.sessionTranscriptBytes)
        #expect(first.mdocGeneratedNonce == second.mdocGeneratedNonce)
    }

    @Test("Default builder generates a fresh 32-byte nonce each time")
    func defaultBuilderGeneratesFreshNonce() {
        let sut = OID4VPSessionTranscriptBuilder()
        let first = sut.build(clientID: clientID, responseURI: responseURI, verifierNonce: verifierNonce)
        let second = sut.build(clientID: clientID, responseURI: responseURI, verifierNonce: verifierNonce)

        #expect(first.mdocGeneratedNonce.count == 32)
        #expect(first.mdocGeneratedNonce != second.mdocGeneratedNonce)
    }
}
