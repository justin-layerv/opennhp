// Prettier config (#2556). These are Prettier 3's current defaults, pinned
// explicitly so the repo's formatting stays anchored to these exact rules
// rather than silently shifting if a future Prettier major changes a default —
// matching this repo's pin-everything discipline (Go patch versions, action
// SHAs, tarball checksums). Kept as prettier.config.js, not .prettierrc.json,
// so it can carry this rationale and is not swept up by the root .gitignore's
// `.*` dotfile rule (which would otherwise leave the CI format gate config-less).
export default {
  printWidth: 80,
  semi: true,
  singleQuote: false,
  trailingComma: "all",
};
