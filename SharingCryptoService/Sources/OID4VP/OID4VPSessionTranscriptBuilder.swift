import CryptoKit
import Foundation
import SwiftCBOR

/// The OID4VP `SessionTranscript` plus the artefacts derived alongside it.
///
/// Not `Sendable`: `SessionTranscript`'s `Handover` carries `[CBOR]`, and SwiftCBOR's `CBOR` is not
/// `Sendable`. This is an ephemeral return value consumed synchronously by the builder's caller — it
/// never crosses an isolation boundary, so `Sendable` is unnecessary (and would need an escape hatch).
public struct OID4VPTranscript {
    /// The transcript itself, for later CBOR use (e.g. the DeviceAuthentication payload).
    public let sessionTranscript: SessionTranscript
    /// The Tag-24 wrapped, CBOR-encoded transcript — the payload the DeviceAuth signature covers (Step 12).
    public let sessionTranscriptBytes: [UInt8]
    /// The wallet's fresh nonce, reused as the JWE `apu` when encrypting the response (Step 15).
    public let mdocGeneratedNonce: [UInt8]
}

/// Builds the OID4VP `SessionTranscript` (Step 11), binding the response to this specific request.
///
/// The transcript is `[null, null, OID4VPHandover]` where the handover hashes `client_id` and
/// `response_uri` together with a freshly generated `mdocGeneratedNonce`, alongside the verifier's nonce.
/// This binding is what mitigates replay/relay of a captured response.
public struct OID4VPSessionTranscriptBuilder {
    /// Supplies the `mdocGeneratedNonce`. Overridable so tests can pin it; production generates 32
    /// secure-random bytes per call.
    private let makeNonce: @Sendable () -> [UInt8]

    public init() {
        self.makeNonce = { Array(SymmetricKey(size: .bits256).withUnsafeBytes(Array.init)) }
    }

    init(makeNonce: @escaping @Sendable () -> [UInt8]) {
        self.makeNonce = makeNonce
    }

    public func build(
        clientID: String,
        responseURI: String,
        verifierNonce: String
    ) -> OID4VPTranscript {
        let mdocGeneratedNonce = makeNonce()

        let handover = Handover.oid4vp(
            clientIdHash: hash(clientID, with: mdocGeneratedNonce),
            responseUriHash: hash(responseURI, with: mdocGeneratedNonce),
            nonce: verifierNonce
        )
        let sessionTranscript = SessionTranscript(
            deviceEngagementBytes: nil,
            eReaderKeyBytes: nil,
            handover: handover
        )
        let sessionTranscriptBytes = sessionTranscript.asDataItem(options: CBOROptions()).encode()

        return OID4VPTranscript(
            sessionTranscript: sessionTranscript,
            sessionTranscriptBytes: sessionTranscriptBytes,
            mdocGeneratedNonce: mdocGeneratedNonce
        )
    }

    /// SHA-256 over `CBOR([ value, mdocGeneratedNonce ])`, per the OID4VPHandover hash definition.
    private func hash(_ value: String, with mdocGeneratedNonce: [UInt8]) -> [UInt8] {
        let encoded = CBOR.array([
            .utf8String(value),
            .byteString(mdocGeneratedNonce)
        ]).encode()
        return Array(SHA256.hash(data: Data(encoded)))
    }
}
