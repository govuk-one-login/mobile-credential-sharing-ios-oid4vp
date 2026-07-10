import SharingCryptoService

struct MockSignatureVerifier: SignatureVerifying {
    let result: Result<VerifiedJWT, JWTVerificationError>

    func verify(jwt: String) throws(JWTVerificationError) -> VerifiedJWT {
        switch result {
        case let .success(verified): return verified
        case let .failure(error): throw error
        }
    }
}
