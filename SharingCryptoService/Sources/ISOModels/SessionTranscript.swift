import SwiftCBOR

public struct SessionTranscript {
    // Optional because OID4VP has no proximity engagement or reader key exchange: both are CBOR null.
    // The ISO/proximity flow always supplies both.
    let deviceEngagementBytes: [UInt8]?
    let eReaderKeyBytes: [UInt8]?
    let handover: Handover

    public init(
        deviceEngagementBytes: [UInt8]?,
        eReaderKeyBytes: [UInt8]?,
        handover: Handover
    ) {
        self.deviceEngagementBytes = deviceEngagementBytes
        self.eReaderKeyBytes = eReaderKeyBytes
        self.handover = handover
    }
}

extension SessionTranscript: CBOREncodable {
    public func toCBOR(options: CBOROptions) -> CBOR {
        return [
            engagementCBOR(deviceEngagementBytes),
            engagementCBOR(eReaderKeyBytes),
            handover.toCBOR
        ]
    }

    private func engagementCBOR(_ bytes: [UInt8]?) -> CBOR {
        guard let bytes else { return .null }
        return .tagged(.encodedCBORDataItem, .byteString(bytes))
    }
}

public enum Handover {
    case qr
    case nfc([CBOR])
    case oid4vp(clientIdHash: [UInt8], responseUriHash: [UInt8], nonce: String)

    var toCBOR: CBOR {
        switch self {
        case .qr:
            return .null
        case .nfc(let cborArray):
            return .array(cborArray)
        case let .oid4vp(clientIdHash, responseUriHash, nonce):
            return .array([
                .byteString(clientIdHash),
                .byteString(responseUriHash),
                .utf8String(nonce)
            ])
        }
    }
}
