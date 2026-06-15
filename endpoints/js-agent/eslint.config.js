import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

// Flat config (#2556): the repo's first JS/TS lint discipline, mirroring the
// golangci-lint gate on the Go side. typescript-eslint's plain `recommended`
// (not the type-checked variant — this 3-file package doesn't need a
// parserOptions.project graph). `eslint-config-prettier` goes last so it turns
// off every stylistic rule that would fight Prettier — ESLint owns correctness,
// Prettier owns formatting (`npm run format:check`).
export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  // The Node build script (`scripts/bundle.mjs`) is plain JS, so typescript-eslint's
  // no-undef-off (it trusts tsc) doesn't apply — declare the Node globals it uses.
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      sourceType: "module",
      globals: { process: "readonly", console: "readonly" },
    },
  },
  prettier,
);
