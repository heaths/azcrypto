package azcrypto

type algorithm interface {
	Sign(algorithm SignatureAlgorithm, digest []byte) (SignResult, error)
	Verify(algorithm SignatureAlgorithm, digest, signature []byte) (VerifyResult, error)
}
