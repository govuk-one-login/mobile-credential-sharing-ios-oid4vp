import Foundation

extension RequestValidator {
    /// Decodes the verifier's encryption key from `client_metadata.jwks.keys[]`.
    ///
    /// OID4VP encrypted responses require an ephemeral EC P-256 key advertised for encryption. The
    /// first key with `kty:"EC"`, `crv:"P-256"`, `use:"enc"` and `alg:"ECDH-ES"` and well-formed
    /// 32-byte coordinates is selected. A missing or malformed key is fatal: without it the response
    /// cannot be encrypted, and an unencrypted response must never be sent.
    func decodeVerifierEncryptionKey(
        from clientMetadata: Data
    ) throws(ValidationError) -> VerifierEncryptionKey {
        guard let metadata = try? JSONSerialization.jsonObject(with: clientMetadata) as? [String: Any],
              let jwks = metadata["jwks"] as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]] else {
            throw .invalidVerifierMetadata
        }

        guard let key = keys.first(where: Self.isEncryptionKey) else {
            throw .invalidVerifierMetadata
        }

        guard let xCoordinate = Self.decodeCoordinate(key["x"]),
              let yCoordinate = Self.decodeCoordinate(key["y"]) else {
            throw .invalidVerifierMetadata
        }

        return VerifierEncryptionKey(
            xCoordinate: xCoordinate,
            yCoordinate: yCoordinate,
            keyID: key["kid"] as? String
        )
    }

    private static func isEncryptionKey(_ key: [String: Any]) -> Bool {
        key["kty"] as? String == "EC"
            && key["crv"] as? String == "P-256"
            && key["use"] as? String == "enc"
            && key["alg"] as? String == "ECDH-ES"
    }

    /// Decodes a base64url JWK coordinate, requiring exactly the 32 bytes of a P-256 coordinate.
    private static func decodeCoordinate(_ value: Any?) -> [UInt8]? {
        guard let encoded = value as? String,
              let data = Data(base64URLEncodedCoordinate: encoded),
              data.count == 32 else {
            return nil
        }
        return [UInt8](data)
    }
}

private extension Data {
    /// Decodes an unpadded base64url string. Named to avoid colliding with the crypto module's public
    /// `Data(base64URLEncoded:)`, which this module cannot import.
    init?(base64URLEncodedCoordinate string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        self = data
    }
}
