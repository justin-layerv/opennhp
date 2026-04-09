//go:build smoke

package smoke

import "fmt"

// derivedEndpoints holds the default URLs for a given NHP environment.
// Tests and TestMain read these as fallbacks; explicit env vars take
// precedence.
//
// NOTE: NHPServerBaseURL is the nhp-server's NLB endpoint at
// resolve.qurl.link.*, NOT api.layerv.* (which is QURL service).
// /health/* and /plugins/* are served on the NHP server; /v1/* is
// served on the QURL API.
type derivedEndpoints struct {
	NHPServerBaseURL string
	QURLAPIBaseURL   string
}

// deriveEndpoints returns the default URL set for the named environment.
// Adding a new environment (e.g., staging) means adding a case here —
// no test body needs to change.
func deriveEndpoints(env string) (derivedEndpoints, error) {
	switch env {
	case "sandbox":
		return derivedEndpoints{
			NHPServerBaseURL: "https://resolve.qurl.link.layerv.xyz",
			QURLAPIBaseURL:   "https://api.layerv.xyz",
		}, nil
	case "prod":
		return derivedEndpoints{
			NHPServerBaseURL: "https://resolve.qurl.link",
			QURLAPIBaseURL:   "https://api.layerv.ai",
		}, nil
	default:
		return derivedEndpoints{}, fmt.Errorf("unknown environment %q (want sandbox or prod)", env)
	}
}
