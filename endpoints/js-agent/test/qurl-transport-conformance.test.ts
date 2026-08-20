import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import {
  decodeQurlV2Transport,
  QURL_V2_TRANSPORT_CHUNK_CHARS,
  QURL_V2_TRANSPORT_MAX_CHARS,
  QURL_V2_TRANSPORT_PREFIX,
  QurlV2TransportError,
} from "../src/qurl/transport";

// Exact artifact from the immutable npm release. The package lock pins the
// tarball integrity; this hash independently pins the artifact bytes.
const SOURCE_VERSION = "0.12.4";
const SOURCE_SHA256 =
  "d6211e9109b5c38123d53ca23979ffe8acb524302c9661e8626ea4d49834cdc9";
const FIXTURE_PATH = createRequire(import.meta.url).resolve(
  "@layervai/qurl-conformance/qv2_conformance_vectors.json",
);

type JsonRecord = Record<string, unknown>;

interface TransportContract {
  prefix: string;
  canonicalPrefix: string;
  componentMax: number;
  maxTransportLength: number;
  fields: {
    claims: { maxEncodedLength: number; maxChunks: number };
    secret: { maxEncodedLength: number; maxChunks: number };
    signature: { maxEncodedLength: number; maxChunks: number };
  };
}

interface TransportVector {
  name: string;
  expect: "accept" | "reject";
  transportFragment: string;
  canonicalFragment?: string;
  rejectClass?: string;
}

interface TransportFixture {
  schemaVersion: number;
  className: string;
  classInput: string;
  entryPoint: string;
  contract: TransportContract;
  vectors: TransportVector[];
}

function record(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonRecord;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${label} must be a safe integer`);
  }
  return value;
}

function parseFieldContract(
  value: unknown,
  label: string,
): { maxEncodedLength: number; maxChunks: number } {
  const field = record(value, label);
  return {
    maxEncodedLength: number(
      field.max_encoded_length,
      `${label}.max_encoded_length`,
    ),
    maxChunks: number(field.max_chunks, `${label}.max_chunks`),
  };
}

function parseTransportFixture(raw: string): TransportFixture {
  const root = record(JSON.parse(raw) as unknown, "fixture");
  const schemaVersion = number(root.schema_version, "schema_version");
  if (schemaVersion !== 2) {
    throw new Error(`schema_version must be 2, got ${schemaVersion}`);
  }

  const rawContract = record(root.transport_contract, "transport_contract");
  const rawFields = record(rawContract.fields, "transport_contract.fields");
  const contract: TransportContract = {
    prefix: string(rawContract.prefix, "transport_contract.prefix"),
    canonicalPrefix: string(
      rawContract.canonical_prefix,
      "transport_contract.canonical_prefix",
    ),
    componentMax: number(
      rawContract.component_max,
      "transport_contract.component_max",
    ),
    maxTransportLength: number(
      rawContract.max_transport_length,
      "transport_contract.max_transport_length",
    ),
    fields: {
      claims: parseFieldContract(
        rawFields.claims,
        "transport_contract.fields.claims",
      ),
      secret: parseFieldContract(
        rawFields.secret,
        "transport_contract.fields.secret",
      ),
      signature: parseFieldContract(
        rawFields.signature,
        "transport_contract.fields.signature",
      ),
    },
  };

  const rawClasses = record(root.classes, "classes");
  const transportClasses = Object.entries(rawClasses).filter(
    ([, value]) => record(value, "class").input === "transport_fragment",
  );
  if (transportClasses.length !== 1) {
    throw new Error(
      `expected exactly one transport_fragment class, got ${transportClasses.length}`,
    );
  }
  const [className, rawTransportClass] = transportClasses[0]!;
  const transportClass = record(rawTransportClass, `classes.${className}`);
  const classInput = string(transportClass.input, "transport class input");
  const entryPoint = string(
    transportClass.entry_point,
    "transport class entry_point",
  );
  const vectors = array(transportClass.vectors, "transport class vectors").map(
    (value, index): TransportVector => {
      const rawVector = record(value, `transport vector[${index}]`);
      const expectation = string(
        rawVector.expect,
        `transport vector[${index}].expect`,
      );
      if (expectation !== "accept" && expectation !== "reject") {
        throw new Error(
          `transport vector[${index}].expect must be accept or reject`,
        );
      }
      const vector: TransportVector = {
        name: string(rawVector.name, `transport vector[${index}].name`),
        expect: expectation,
        transportFragment: string(
          rawVector.transport_fragment,
          `transport vector[${index}].transport_fragment`,
        ),
      };
      if (expectation === "accept") {
        vector.canonicalFragment = string(
          rawVector.canonical_fragment,
          `transport vector[${index}].canonical_fragment`,
        );
      } else {
        vector.rejectClass = string(
          rawVector.reject_class,
          `transport vector[${index}].reject_class`,
        );
      }
      return vector;
    },
  );

  return {
    schemaVersion,
    className,
    classInput,
    entryPoint,
    contract,
    vectors,
  };
}

const fixtureBytes = readFileSync(FIXTURE_PATH);
const fixture = parseTransportFixture(fixtureBytes.toString("utf8"));

describe(`qv2t1 transport conformance from npm ${SOURCE_VERSION}`, () => {
  it("pins the exact upstream schema-v2 fixture bytes", () => {
    expect(createHash("sha256").update(fixtureBytes).digest("hex")).toBe(
      SOURCE_SHA256,
    );
  });

  it("pins the normative transport contract and all 39 vector identities", () => {
    expect(fixture.schemaVersion).toBe(2);
    expect(fixture.className).toBe("transport");
    expect(fixture.classInput).toBe("transport_fragment");
    expect(fixture.entryPoint).toBe(
      "DecodeTransport(body) -> canonical qv2 fragment",
    );
    expect(fixture.contract).toEqual({
      prefix: "qv2t1",
      canonicalPrefix: "qv2",
      componentMax: 240,
      maxTransportLength: 6826,
      fields: {
        claims: { maxEncodedLength: 6144, maxChunks: 26 },
        secret: { maxEncodedLength: 512, maxChunks: 3 },
        signature: { maxEncodedLength: 128, maxChunks: 1 },
      },
    });
    expect(QURL_V2_TRANSPORT_PREFIX).toBe(fixture.contract.prefix);
    expect(QURL_V2_TRANSPORT_CHUNK_CHARS).toBe(fixture.contract.componentMax);
    expect(QURL_V2_TRANSPORT_MAX_CHARS).toBe(
      fixture.contract.maxTransportLength,
    );
    expect(fixture.vectors).toHaveLength(39);
    expect(
      fixture.vectors.filter((vector) => vector.expect === "accept"),
    ).toHaveLength(6);
    expect(
      fixture.vectors.filter((vector) => vector.expect === "reject"),
    ).toHaveLength(33);
    expect(new Set(fixture.vectors.map((vector) => vector.name)).size).toBe(39);
    expect(
      new Set(
        fixture.vectors
          .filter((vector) => vector.expect === "reject")
          .map((vector) => vector.rejectClass),
      ),
    ).toEqual(new Set(["transport"]));
  });

  for (const vector of fixture.vectors) {
    it(`${vector.expect}s ${vector.name}`, () => {
      if (vector.expect === "accept") {
        expect(decodeQurlV2Transport(vector.transportFragment)).toBe(
          vector.canonicalFragment,
        );
        return;
      }
      expect(() => decodeQurlV2Transport(vector.transportFragment)).toThrow(
        QurlV2TransportError,
      );
    });
  }
});
