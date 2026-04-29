//go:build ignore

package fixture

/*
 * Doc block above the real declaration. Continuation line below
 * mentions the old name; the `^[[:space:]]*\*` pre-filter must skip
 * it so the script's all-matches collector finds only the real one.
 *
 * redirectURLField = "old_name_pre_refactor"
 */
const redirectURLField = "redirect_url"
