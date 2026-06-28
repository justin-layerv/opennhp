package qurlv2

import conformance "github.com/layervai/qurl-conformance"

// Test-only loaders that feed the pinned public module's embedded conformance
// bytes into the production byte-parsers. Living in a _test.go file keeps
// github.com/layervai/qurl-conformance out of the production import graph (the
// parsers in conformance.go / vectors.go take []byte and never reference the
// module), so qurl-conformance is compiled into the test binary only -- matching
// how qurl-go consumes the same vectors.

// loadConformanceFile strictly parses the qURL v2 conformance artifact from the
// pinned module's embedded bytes (conformance.QV2Vectors). It returns an error
// (never an empty/zero document) when the bytes are malformed or are not the qURL
// v2 conformance artifact, so a consumer test FAILS rather than silently skipping.
func loadConformanceFile() (*ConformanceFile, error) {
	return parseConformanceFile(conformance.QV2Vectors())
}

// loadVectorFile strictly parses the issuer-signature vector file from the pinned
// module's embedded bytes (conformance.IssuerSignatureVectors). It returns an
// error (never an empty/zero document) if the bytes are malformed, so a consumer
// test FAILS rather than silently skipping the contract.
func loadVectorFile() (*VectorFile, error) {
	return parseVectorFile(conformance.IssuerSignatureVectors())
}
