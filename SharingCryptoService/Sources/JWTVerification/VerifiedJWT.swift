import Foundation

public struct VerifiedJWT: Sendable, Equatable {
    public let headerData: Data
    public let payloadData: Data
}
