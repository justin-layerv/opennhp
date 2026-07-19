package common

// header flags (bit 0 - bit 11)
const (
	NHP_FLAG_EXTENDEDLENGTH = 1 << iota
	NHP_FLAG_COMPRESS
	// NHP_FLAG_HUB_LST_COOKIE_PROOF marks the assignment-Hub-only NHP_LST
	// return-routability proof. Its cookie is mixed into the existing header
	// digest; it does not add bytes to the Curve header. The flag is deliberately
	// distinct from NHP_RKN, whose overload-cookie semantics remain unchanged.
	NHP_FLAG_HUB_LST_COOKIE_PROOF
)

const (
	CIPHER_SCHEME_CURVE int = 0
)
