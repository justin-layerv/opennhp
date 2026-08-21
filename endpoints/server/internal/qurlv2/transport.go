package qurlv2

import (
	"errors"
	"fmt"
	"strings"
)

// The qv2t1 transport is a non-cryptographic, share-safe envelope around the
// canonical qv2 fragment. It chunks each base64url field so no dot-separated URL
// component exceeds the cross-client limit, then reconstructs the byte-identical
// canonical fragment before the existing parser and signature verifier run.
const (
	TransportPrefix          = "qv2t1"
	TransportComponentMax    = 240
	TransportMaxLength       = 6826
	transportHeaderParts     = 4
	transportFieldCount      = 3
	transportClaimsMaxLength = 6144
	transportClaimsMaxChunks = 26
	transportSecretMaxLength = 512
	transportSecretMaxChunks = 3
	transportSigMaxLength    = 128
	transportSigMaxChunks    = 1
)

// ErrTransport is returned when a qv2t1 outer fragment violates its framing
// contract. Inner qv2 parse, signature, liveness, and relay errors remain owned
// by their existing downstream sentinels.
var ErrTransport = errors.New("qurlv2: invalid transport fragment")

type transportFieldBound struct {
	maxEncodedLength int
	maxChunks        int
}

var transportFieldBounds = [transportFieldCount]transportFieldBound{
	{maxEncodedLength: transportClaimsMaxLength, maxChunks: transportClaimsMaxChunks},
	{maxEncodedLength: transportSecretMaxLength, maxChunks: transportSecretMaxChunks},
	{maxEncodedLength: transportSigMaxLength, maxChunks: transportSigMaxChunks},
}

// DecodeTransport validates a qv2t1 fragment body and reconstructs the exact
// canonical qv2 fragment body. The caller must pass the body without a leading
// '#'; accepting legacy qv2 or a URL here would blur the outer transport trust
// boundary.
//
// The total-length check deliberately precedes Split, count parsing, or any
// count-driven allocation. DecodeTransport does not interpret the reconstructed
// claims, secret, or signature; callers pass the result to ParseFragment and the
// normal authentication gates.
func DecodeTransport(body string) (string, error) {
	if len(body) > TransportMaxLength {
		return "", transportErrorf("length %d exceeds %d", len(body), TransportMaxLength)
	}

	parts := strings.Split(body, ".")
	if len(parts) < transportHeaderParts {
		return "", transportErrorf("expected prefix and three count tokens")
	}
	if parts[0] != TransportPrefix {
		return "", transportErrorf("prefix must be %q", TransportPrefix)
	}

	var counts [transportFieldCount]int
	for i, bound := range transportFieldBounds {
		count, err := parseTransportCount(parts[i+1], bound.maxChunks)
		if err != nil {
			return "", transportErrorf("count %d: %v", i+1, err)
		}
		counts[i] = count
	}

	wantParts := transportHeaderParts + counts[0] + counts[1] + counts[2]
	if len(parts) != wantParts {
		return "", transportErrorf("declared chunks require %d parts, got %d", wantParts, len(parts))
	}

	var fields [transportFieldCount]string
	partIndex := transportHeaderParts
	for fieldIndex, count := range counts {
		chunks := parts[partIndex : partIndex+count]
		partIndex += count

		fieldLength := 0
		for chunkIndex, chunk := range chunks {
			if len(chunk) == 0 || len(chunk) > TransportComponentMax {
				return "", transportErrorf("field %d chunk %d length %d is outside 1..%d", fieldIndex+1, chunkIndex+1, len(chunk), TransportComponentMax)
			}
			if chunkIndex < len(chunks)-1 && len(chunk) != TransportComponentMax {
				return "", transportErrorf("field %d non-final chunk %d length is %d, want %d", fieldIndex+1, chunkIndex+1, len(chunk), TransportComponentMax)
			}
			if !isBase64URLChunk(chunk) {
				return "", transportErrorf("field %d chunk %d contains a non-base64url byte", fieldIndex+1, chunkIndex+1)
			}
			fieldLength += len(chunk)
		}
		if fieldLength > transportFieldBounds[fieldIndex].maxEncodedLength {
			return "", transportErrorf("field %d length %d exceeds %d", fieldIndex+1, fieldLength, transportFieldBounds[fieldIndex].maxEncodedLength)
		}
		fields[fieldIndex] = strings.Join(chunks, "")
	}

	return FragmentPrefix + "." + strings.Join(fields[:], "."), nil
}

func parseTransportCount(token string, max int) (int, error) {
	if token == "" || token[0] == '0' {
		return 0, errors.New("count must be canonical positive decimal")
	}

	value := 0
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, errors.New("count must contain ASCII decimal digits only")
		}
		digit := int(token[i] - '0')
		if value > max/10 || value == max/10 && digit > max%10 {
			return 0, fmt.Errorf("count exceeds %d", max)
		}
		value = value*10 + digit
	}
	return value, nil
}

func isBase64URLChunk(chunk string) bool {
	for i := 0; i < len(chunk); i++ {
		b := chunk[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func transportErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTransport, fmt.Sprintf(format, args...))
}
