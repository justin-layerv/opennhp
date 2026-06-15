// Regression guard for #2556: browser `src/` must NOT see Node globals.
//
// Under `tsconfig.json` (`types: []`, browser DOM lib only) `Buffer` does not
// exist, so `typeof Buffer` below is a type error that the `@ts-expect-error`
// directive absorbs — this file typechecks clean today. If someone re-adds Node
// types to the `src` tsconfig (e.g. `"types": ["node"]`), `Buffer` resolves, the
// directive becomes unused, and `tsc -p tsconfig.json` fails with TS2578
// ("Unused '@ts-expect-error' directive"). Node types stay scoped to
// `tsconfig.test.json` (the `test/` runtime); see that file and the README.
//
// This is a compile-time-only fixture: it exports a type (erased at build),
// is imported by nothing (ships no runtime code), and is not a `*.test.ts`
// file (vitest never executes it).
//
// @ts-expect-error -- Buffer must be absent in browser src; Node types are test-only (#2556).
export type _NodeIsolationGuard = typeof Buffer;
