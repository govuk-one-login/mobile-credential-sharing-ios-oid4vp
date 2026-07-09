import Foundation
@testable import SharingCryptoService
import SwiftCBOR
import Testing

@Suite("SessionTranscript tests")
struct SessionTranscriptTests {
    @Test("Successfully encodes with QR")
    func sessionTranscriptCanBeEncodedToCBORwithQR() async throws {
        let deviceEngagementBytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let eReaderKeyBytes: [UInt8] = [0x09, 0x0A, 0x0B, 0x0C]
        let sessionTranscript = SessionTranscript(
            deviceEngagementBytes: deviceEngagementBytes,
            eReaderKeyBytes: eReaderKeyBytes,
            handover: .qr
        )
        
        #expect(sessionTranscript.toCBOR(options: CBOROptions()) == [
            .tagged(.encodedCBORDataItem, .byteString(deviceEngagementBytes)),
            .tagged(.encodedCBORDataItem, .byteString(eReaderKeyBytes)),
            .null
        ])
    }

    @Test("Encodes an OID4VP handover with null engagement fields")
    func sessionTranscriptEncodesOID4VPHandover() throws {
        let clientIdHash: [UInt8] = Array(repeating: 0xaa, count: 32)
        let responseUriHash: [UInt8] = Array(repeating: 0xbb, count: 32)
        let sessionTranscript = SessionTranscript(
            deviceEngagementBytes: nil,
            eReaderKeyBytes: nil,
            handover: .oid4vp(clientIdHash: clientIdHash, responseUriHash: responseUriHash, nonce: "abc123")
        )

        #expect(sessionTranscript.toCBOR(options: CBOROptions()) == [
            .null,
            .null,
            .array([
                .byteString(clientIdHash),
                .byteString(responseUriHash),
                .utf8String("abc123")
            ])
        ])
    }
}
