// Strict JSON parsing for qURL v2 — the browser/headless port of the Go strict
// parser (`qurl-service` internal/qurlv2/parse.go), enforcing the same rules so
// the two verifiers agree on which payloads are well-formed.
//
// The browser's built-in `JSON.parse` does the WRONG thing for several
// signature/admission-bypass hazards, so this file does NOT rely on it for the
// structural pass:
//
//   - Duplicate keys: `JSON.parse` silently collapses to last-wins, and a
//     `reviver` callback sees the already-collapsed object, so neither catches a
//     duplicate. Only a token walk over the original text can.
//   - Integer-only time fields: every JSON number becomes a JS double, so after
//     parsing, `1e9`, `1.0`, and `1000000000` are indistinguishable and
//     `Number.isInteger` accepts all three. Go gets integer-only for free from
//     int64 unmarshal; here we must inspect the raw number LITERAL text and reject
//     a fractional/exponent/signed/leading-zero form.
//   - null in a scalar field: `JSON.parse` yields `null`, which would coerce; the
//     walk rejects any null value outright.
//   - Unknown fields: rejected against an explicit allowlist during the walk.
//
// So this module hand-rolls a minimal JSON scanner that yields the raw literal
// text for each top-level value, enforces the structural rules, and then converts
// each allowlisted field with type discipline. Nested arrays/objects are scanned
// only enough to stay balanced (a scalar field carrying one is rejected by type).
import {
  ALLOWED_CLAIM_KEYS,
  ALLOWED_SECRET_KEYS,
  CLAIM_FIELDS,
  Claims,
  decodeResourcePublicKey,
  decodeX25519PrivateKey,
  decodeX25519PublicKey,
  MAX_UNIX_SECONDS,
  QURL_V2_ISSUER,
  QURL_V2_VERSION,
  REQUIRED_CLAIM_KEYS,
  REQUIRED_SECRET_KEYS,
  Secret,
  SECRET_FIELD_PRIVATE_KEY,
  StrictParseError,
} from "./claims.js";

/** A top-level member's raw value text plus a coarse kind, from the scanner. */
interface RawMember {
  /** The exact source substring of the value (e.g. `"-1"`, `"\"abc\""`, `"[1]"`). */
  text: string;
  kind: "string" | "number" | "boolean" | "null" | "array" | "object";
}

/**
 * Scans a JSON object's top-level members WITHOUT interpreting nested values,
 * returning each key's raw value text and kind. Rejects, in one pass:
 *   - a top-level value that is not a single object;
 *   - keys not in `allowed` (unknown fields);
 *   - duplicate keys;
 *   - any value that is JSON null;
 *   - trailing content after the closing brace.
 *
 * Type enforcement beyond null is the caller's job (it inspects each RawMember).
 */
function scanStrictObject(
  raw: string,
  allowed: ReadonlySet<string>,
): Map<string, RawMember> {
  const s = raw;
  const n = s.length;
  let i = 0;

  const skipWs = (): void => {
    while (i < n) {
      const c = s.charCodeAt(i);
      // Per JSON (RFC 8259): only space, tab, LF, CR are insignificant whitespace.
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        i += 1;
      } else {
        break;
      }
    }
  };

  skipWs();
  if (s[i] !== "{") {
    throw new StrictParseError("top-level value must be a JSON object");
  }
  i += 1;

  const members = new Map<string, RawMember>();
  skipWs();
  if (s[i] === "}") {
    i += 1;
    skipWs();
    if (i !== n) {
      throw new StrictParseError("trailing data after JSON object");
    }
    return members;
  }

  for (;;) {
    skipWs();
    if (s[i] !== '"') {
      throw new StrictParseError("expected a string object key");
    }
    const key = scanString();
    if (!allowed.has(key)) {
      throw new StrictParseError(`unknown field ${JSON.stringify(key)}`);
    }
    if (members.has(key)) {
      throw new StrictParseError(`duplicate key ${JSON.stringify(key)}`);
    }

    skipWs();
    if (s[i] !== ":") {
      throw new StrictParseError(
        `expected ':' after key ${JSON.stringify(key)}`,
      );
    }
    i += 1;
    skipWs();

    const member = scanValue();
    if (member.kind === "null") {
      throw new StrictParseError(`field ${JSON.stringify(key)} is null`);
    }
    members.set(key, member);

    skipWs();
    const c = s[i];
    if (c === ",") {
      i += 1;
      continue;
    }
    if (c === "}") {
      i += 1;
      break;
    }
    throw new StrictParseError("expected ',' or '}' in object");
  }

  skipWs();
  if (i !== n) {
    throw new StrictParseError("trailing data after JSON object");
  }
  return members;

  // --- scanners (closures over i/s/n) ---

  // Scans a JSON string starting at the opening quote and returns its decoded
  // value, advancing i past the closing quote. Used for keys; string VALUES are
  // re-parsed via JSON.parse from their raw text in the caller (so escape handling
  // matches the platform exactly), but keys must be decoded here to compare.
  function scanString(): string {
    const start = i;
    if (s[i] !== '"') {
      throw new StrictParseError("expected string");
    }
    i += 1;
    while (i < n) {
      const c = s[i];
      if (c === "\\") {
        i += 2; // skip the escaped char (enough to stay balanced; JSON.parse validates)
        continue;
      }
      if (c === '"') {
        i += 1;
        const rawStr = s.slice(start, i);
        try {
          return JSON.parse(rawStr) as string;
        } catch {
          throw new StrictParseError(`malformed string literal ${rawStr}`);
        }
      }
      i += 1;
    }
    throw new StrictParseError("unterminated string");
  }

  // Scans one JSON value, returning its raw text and kind, advancing i past it.
  // Arrays/objects are scanned only for balance (no member interpretation).
  function scanValue(): RawMember {
    const c = s[i];
    if (c === undefined) {
      throw new StrictParseError(
        "unexpected end of input where a value was expected",
      );
    }
    if (c === '"') {
      const start = i;
      scanString();
      return { text: s.slice(start, i), kind: "string" };
    }
    if (c === "{" || c === "[") {
      const start = i;
      scanContainer();
      return {
        text: s.slice(start, i),
        kind: c === "{" ? "object" : "array",
      };
    }
    if (c === "t" || c === "f") {
      return {
        text: scanLiteral(c === "t" ? "true" : "false"),
        kind: "boolean",
      };
    }
    if (c === "n") {
      return { text: scanLiteral("null"), kind: "null" };
    }
    // Number: a leading '-' or a digit.
    if (c === "-" || (c >= "0" && c <= "9")) {
      return { text: scanNumber(), kind: "number" };
    }
    throw new StrictParseError(`unexpected character ${JSON.stringify(c)}`);
  }

  function scanLiteral(word: string): string {
    if (s.startsWith(word, i)) {
      i += word.length;
      return word;
    }
    throw new StrictParseError(`expected literal ${word}`);
  }

  // Scans a number token's raw text (sign, digits, optional fraction/exponent)
  // WITHOUT validating it as canonical JSON — the caller applies the strict
  // integer-only rule to time fields by inspecting this text. The character set
  // here is permissive on purpose (it captures the whole literal, including the
  // forms we reject downstream); structural number validity for non-time numbers
  // is enforced when the field is converted.
  function scanNumber(): string {
    const start = i;
    while (i < n) {
      const c = s[i]!;
      if (
        (c >= "0" && c <= "9") ||
        c === "-" ||
        c === "+" ||
        c === "." ||
        c === "e" ||
        c === "E"
      ) {
        i += 1;
      } else {
        break;
      }
    }
    const text = s.slice(start, i);
    if (text === "" || text === "-") {
      throw new StrictParseError("malformed number");
    }
    return text;
  }

  // Scans a balanced array/object (including nested ones and strings within), for
  // the drain-only path. The opening delimiter is at i.
  //
  // DEPENDS ON: no allowed claim/secret field is container-typed. This counts
  // nesting depth but treats `}` and `]` interchangeably, so a malformed `[1}`
  // scans as "balanced". That is harmless ONLY because this is drain-only and any
  // container-valued field is rejected by the later typed check (every allowed
  // field is a scalar). If a container-typed field is ever added to the schema,
  // this needs real bracket-matching (assert the closer matches its opener).
  function scanContainer(): void {
    const open = s[i];
    const close = open === "{" ? "}" : "]";
    let depth = 0;
    for (; i < n;) {
      const c = s[i];
      if (c === '"') {
        scanString();
        continue;
      }
      if (c === "{" || c === "[") {
        depth += 1;
        i += 1;
        continue;
      }
      if (c === "}" || c === "]") {
        depth -= 1;
        i += 1;
        if (depth === 0) {
          return;
        }
        continue;
      }
      i += 1;
    }
    throw new StrictParseError(
      `unterminated ${open === "{" ? "object" : "array"} (want ${close})`,
    );
  }
}

/** Rejects with StrictParseError if any required key is missing. */
function requireKeys(
  members: Map<string, RawMember>,
  required: readonly string[],
): void {
  for (const k of required) {
    if (!members.has(k)) {
      throw new StrictParseError(`missing required field ${JSON.stringify(k)}`);
    }
  }
}

/** Reads a required string member, asserting its kind is string. */
function requireString(members: Map<string, RawMember>, field: string): string {
  const m = members.get(field);
  if (!m || m.kind !== "string") {
    throw new StrictParseError(
      `field ${JSON.stringify(field)} must be a string`,
    );
  }
  return JSON.parse(m.text) as string;
}

/** Reads an optional string member (absent → undefined), asserting kind if present. */
function optionalString(
  members: Map<string, RawMember>,
  field: string,
): string | undefined {
  const m = members.get(field);
  if (!m) {
    return undefined;
  }
  if (m.kind !== "string") {
    throw new StrictParseError(
      `field ${JSON.stringify(field)} must be a string`,
    );
  }
  return JSON.parse(m.text) as string;
}

/** Reads a required JSON number member, asserting kind. Returns the raw literal text. */
function requireNumberText(
  members: Map<string, RawMember>,
  field: string,
): string {
  const m = members.get(field);
  if (!m || m.kind !== "number") {
    throw new StrictParseError(
      `field ${JSON.stringify(field)} must be a number`,
    );
  }
  return m.text;
}

// Integer-literal shape: optional single leading minus is NOT allowed for time
// fields (they must be non-negative), an integer has no fraction/exponent, and no
// redundant leading zeros (except a lone "0"). We additionally reject any '+',
// '.', 'e', 'E', and a leading '-' here so floats/exponents/signed forms fail
// before numeric conversion — the integer-only rule Go gets from int64 unmarshal.
const INTEGER_LITERAL = /^(0|[1-9][0-9]*)$/;

/** Parses a non-negative integer Unix-seconds field from its raw literal text. */
function parseUnixSecondsField(field: string, text: string): number {
  if (!INTEGER_LITERAL.test(text)) {
    throw new StrictParseError(
      `${field} must be a non-negative integer Unix second (no float/exponent/sign), got ${JSON.stringify(text)}`,
    );
  }
  const val = Number(text);
  // INTEGER_LITERAL already excludes negatives; this guards the (impossible-given-
  // the-regex) edge and documents the range contract.
  if (!Number.isSafeInteger(val) || val < 0) {
    throw new StrictParseError(
      `${field} is out of the safe integer range, got ${JSON.stringify(text)}`,
    );
  }
  if (val === 0) {
    throw new StrictParseError(`${field} is required and must be non-zero`);
  }
  if (val > MAX_UNIX_SECONDS) {
    throw new StrictParseError(
      `${field}=${val} exceeds max allowed Unix second ${MAX_UNIX_SECONDS}`,
    );
  }
  return val;
}

/** Reads the required integer version `v`, asserting it equals the pinned version. */
function requireVersion(members: Map<string, RawMember>): number {
  const text = requireNumberText(members, CLAIM_FIELDS.v);
  if (!INTEGER_LITERAL.test(text)) {
    throw new StrictParseError(
      `v must be an integer, got ${JSON.stringify(text)}`,
    );
  }
  const v = Number(text);
  if (v !== QURL_V2_VERSION) {
    throw new StrictParseError(`v must be ${QURL_V2_VERSION}, got ${v}`);
  }
  return v;
}

/**
 * Strict-parses the decoded claims JSON text (the bytes produced by base64url-
 * decoding Part 1, as a UTF-8 string) into a {@link Claims}. Rejects every
 * strict-schema violation in the design's "Parsing rules" before returning.
 */
export function parseClaims(rawText: string): Claims {
  const members = scanStrictObject(rawText, ALLOWED_CLAIM_KEYS);
  requireKeys(members, REQUIRED_CLAIM_KEYS);

  const v = requireVersion(members);

  const iss = requireString(members, CLAIM_FIELDS.iss);
  if (iss !== QURL_V2_ISSUER) {
    throw new StrictParseError(
      `iss must be ${JSON.stringify(QURL_V2_ISSUER)}, got ${JSON.stringify(iss)}`,
    );
  }

  const kid = requireString(members, CLAIM_FIELDS.kid);
  if (kid === "") {
    throw new StrictParseError("kid is empty");
  }

  const iat = parseUnixSecondsField(
    CLAIM_FIELDS.iat,
    requireNumberText(members, CLAIM_FIELDS.iat),
  );
  const nbf = parseUnixSecondsField(
    CLAIM_FIELDS.nbf,
    requireNumberText(members, CLAIM_FIELDS.nbf),
  );
  const exp = parseUnixSecondsField(
    CLAIM_FIELDS.exp,
    requireNumberText(members, CLAIM_FIELDS.exp),
  );

  const jti = requireString(members, CLAIM_FIELDS.jti);
  if (jti === "") {
    throw new StrictParseError("jti is empty");
  }

  // Clock-free ordering bounds (issued/not-before <= expires). These catch a
  // structurally-incoherent claim at parse time; LIVENESS (exp/nbf vs now) is the
  // admission caller's job — this library has no trusted clock. We do not enforce
  // nbf>=iat (a backdated nbf is harmless given admission's nbf/exp-vs-now checks).
  if (iat > exp) {
    throw new StrictParseError(`iat (${iat}) must be <= exp (${exp})`);
  }
  if (nbf > exp) {
    throw new StrictParseError(`nbf (${nbf}) must be <= exp (${exp})`);
  }

  const cellPublicKeyB64 = requireString(
    members,
    CLAIM_FIELDS.cellPublicKeyB64,
  );
  const relayUrl = requireString(members, CLAIM_FIELDS.relayUrl);
  const resourcePublicKeyB64 = requireString(
    members,
    CLAIM_FIELDS.resourcePublicKeyB64,
  );
  const qurlUserPublicKeyB64 = requireString(
    members,
    CLAIM_FIELDS.qurlUserPublicKeyB64,
  );

  // Decode + length-check each key field against its OWN expected size. relay_url
  // must be present and non-empty here; the HTTPS + allowlist checks are a
  // post-verify step (validateRelayUrl), NOT part of the parser, because relay_url
  // is acted on only after signature verification succeeds.
  decodeX25519PublicKey(CLAIM_FIELDS.cellPublicKeyB64, cellPublicKeyB64);
  decodeX25519PublicKey(
    CLAIM_FIELDS.qurlUserPublicKeyB64,
    qurlUserPublicKeyB64,
  );
  decodeResourcePublicKey(resourcePublicKeyB64);
  if (relayUrl === "") {
    throw new StrictParseError("relay_url is empty");
  }

  // cell_id is the one optional present-string claim allowed to be empty. Absent
  // and present-empty are both "no cell", so normalize a present-empty value to
  // undefined — the two forms are then INDISTINGUISHABLE downstream (an
  // `=== undefined` check, not only a truthy check, treats them alike), matching
  // the documented intent and the Go side where there is no undefined/empty split.
  const cellIdRaw = optionalString(members, CLAIM_FIELDS.cellId);
  const cellId = cellIdRaw === "" ? undefined : cellIdRaw;

  return {
    v,
    iss,
    kid,
    iat,
    nbf,
    exp,
    jti,
    cellPublicKeyB64,
    ...(cellId !== undefined ? { cellId } : {}),
    relayUrl,
    resourcePublicKeyB64,
    qurlUserPublicKeyB64,
  };
}

/**
 * Strict-parses the decoded secret JSON text (Part 2) into a {@link Secret} with
 * the same strict profile, and decode+length-checks the per-qURL private key (the
 * PoP credential) at parse time rather than deferring to the knock path.
 */
export function parseSecret(rawText: string): Secret {
  const members = scanStrictObject(rawText, ALLOWED_SECRET_KEYS);
  requireKeys(members, REQUIRED_SECRET_KEYS);

  const qurlUserPrivateKeyB64 = requireString(
    members,
    SECRET_FIELD_PRIVATE_KEY,
  );
  if (qurlUserPrivateKeyB64 === "") {
    throw new StrictParseError(`${SECRET_FIELD_PRIVATE_KEY} is empty`);
  }
  decodeX25519PrivateKey(SECRET_FIELD_PRIVATE_KEY, qurlUserPrivateKeyB64);

  return { qurlUserPrivateKeyB64 };
}
