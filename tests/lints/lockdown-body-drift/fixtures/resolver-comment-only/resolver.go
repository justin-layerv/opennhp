//go:build ignore

package fixture

// Fixture: the SSM parameter name /env/nhp/qurl/internal-lockdown-body is
// mentioned only in THIS comment; the load-bearing code below names a
// different parameter. check 4b must catch the rename despite the comment.
func resolve() string { return "/" + "sandbox" + "/nhp/qurl/renamed-body" }
