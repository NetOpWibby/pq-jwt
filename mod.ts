/**
 * mod.ts — Post-quantum JWT module for Deno
 *
 * Two signing modes:
 *
 *   1. ML-DSA only  — Uses ML-DSA (FIPS 204) via @oqs/liboqs-js.
 *      alg header:  "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87"
 *
 *   2. Hybrid       — ML-DSA + Ed25519 signed in parallel over the same
 *      signing input. Both signatures are concatenated into a single Base64url
 *      blob. BOTH must pass verification. If either algorithm is later broken
 *      (classical or quantum), the other still protects the token.
 *      alg header:  "ML-DSA-44+Ed25519" | "ML-DSA-65+Ed25519" | "ML-DSA-87+Ed25519"
 *
 * Hybrid signature layout (raw bytes, fixed split at verification time):
 *   [ ML-DSA signature (variant-specific length) | Ed25519 signature (64 bytes) ]
 *
 * ML-DSA signature lengths (bytes):
 *   ML-DSA-44 → 2420
 *   ML-DSA-65 → 3293
 *   ML-DSA-87 → 4595
 *
 * ⚠️  @oqs/liboqs-js is research/prototyping software and has not been formally
 *     audited. The hybrid mode provides defence-in-depth during the transition
 *     period. Follow NIST PQC guidance for production deployments.
 */

/*** IMPORT ------------------------------------------- ***/

import * as ed from "@noble/ed25519";
import { createMLDSA44, createMLDSA65, createMLDSA87 } from "@oqs/liboqs-js/sig";

/*** UTILITY ------------------------------------------ ***/

/** Fixed byte length of an Ed25519 signature (RFC 8032, §5.1.6). */
const ED25519_SIG_LENGTH = 64;

/** Fixed byte length of an Ed25519 public key (RFC 8032, §5.1.5). */
const ED25519_PK_LENGTH = 32;

/** Fixed byte length of an Ed25519 secret key seed (RFC 8032, §5.1.5). */
const ED25519_SK_LENGTH = 32;

/**
 * Byte length of the uint32 big-endian length prefix stored at the start of
 * every hybrid signature blob.  Encodes the ML-DSA signature length so the
 * verifier can split the blob without relying on hardcoded constants.
 *
 * Hybrid signature layout:
 *   [0..3]               — mlDsaSigLen as uint32 big-endian
 *   [4..4+mlDsaSigLen-1] — ML-DSA signature bytes
 *   [4+mlDsaSigLen..]    — Ed25519 signature bytes (always 64)
 */
const HYBRID_PREFIX_LENGTH = 4;

/*** EXPORT ------------------------------------------- ***/

/**
 * Approximate sizes of hybrid keypair components, for planning purposes.
 * Ed25519 keys are always 32 bytes each.
 * Sizes are in bytes (raw, before Base64url encoding).
 */
export const KEY_SIZES: Record<MlDsaVariant, { ed25519SecretKey: number; ed25519PublicKey: number; mlDsaPublicKey: number; mlDsaSecretKey: number; }> = {
  "ML-DSA-44": {
    ed25519PublicKey: ED25519_PK_LENGTH,
    ed25519SecretKey: ED25519_SK_LENGTH,
    mlDsaPublicKey: 1312,
    mlDsaSecretKey: 2560
  },
  "ML-DSA-65": {
    ed25519PublicKey: ED25519_PK_LENGTH,
    ed25519SecretKey: ED25519_SK_LENGTH,
    mlDsaPublicKey: 1952,
    mlDsaSecretKey: 4032
  },
  "ML-DSA-87": {
    ed25519PublicKey: ED25519_PK_LENGTH,
    ed25519SecretKey: ED25519_SK_LENGTH,
    mlDsaPublicKey: 2592,
    mlDsaSecretKey: 4896
  }
};

/**
 * Supported ML-DSA parameter sets (FIPS 204).
 * Higher numbers mean larger keys/signatures and stronger security margins:
 *   - ML-DSA-44 → NIST security level 2 (≈AES-128)
 *   - ML-DSA-65 → NIST security level 3 (≈AES-192) — recommended default
 *   - ML-DSA-87 → NIST security level 5 (≈AES-256)
 */
export type MlDsaVariant = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";

/**
 * Hybrid algorithm identifiers placed in the JWT `alg` header.
 * Each variant pairs an ML-DSA parameter set with Ed25519 for
 * classical + post-quantum defence-in-depth.
 */
export type HybridVariant =
  | "ML-DSA-44+Ed25519"
  | "ML-DSA-65+Ed25519"
  | "ML-DSA-87+Ed25519";

/**
 * Union of every algorithm identifier this module may place in the
 * JWT `alg` header — ML-DSA only or hybrid ML-DSA + Ed25519.
 */
export type Algorithm = MlDsaVariant | HybridVariant;

/**
 * JOSE header emitted for every token produced by this module.
 * `typ` is always `"JWT"`; `alg` identifies the signing scheme.
 */
export interface JwtHeader {
  alg: Algorithm;
  typ: "JWT";
}

/**
 * ML-DSA-only keypair returned by {@link generateKeyPair}.
 * Store `secretKey` securely; `publicKey` is safe to distribute.
 */
export interface KeyPair {
  /** Base64url-encoded ML-DSA public key. */
  publicKey: string;
  /** Base64url-encoded ML-DSA secret key. */
  secretKey: string;
}

/**
 * Hybrid keypair containing both ML-DSA and Ed25519 keys.
 * Store all secret keys securely. Distribute all public keys to verifiers.
 */
export interface HybridKeyPair {
  /** Ed25519 keypair, both values Base64url-encoded. */
  ed25519: {
    /** Base64url-encoded Ed25519 public key (32 bytes raw). */
    publicKey: string;
    /** Base64url-encoded Ed25519 secret key seed (32 bytes raw). */
    secretKey: string;
  };
  /** ML-DSA keypair, both values Base64url-encoded. */
  mlDsa: {
    /** Base64url-encoded ML-DSA public key. */
    publicKey: string;
    /** Base64url-encoded ML-DSA secret key. */
    secretKey: string;
  };
  /** ML-DSA parameter set this keypair was generated for. */
  variant: MlDsaVariant;
}

/**
 * Public half of a {@link HybridKeyPair}, suitable for distribution
 * to verifiers. Both keys are required to verify a hybrid token.
 */
export interface HybridPublicKeys {
  /** Base64url-encoded Ed25519 public key. */
  ed25519PublicKey: string;
  /** Base64url-encoded ML-DSA public key. */
  mlDsaPublicKey: string;
}

/**
 * Decoded JWT claims set. Standard registered claims (`exp`, `iat`,
 * `iss`, `sub`) are typed explicitly; arbitrary additional claims
 * are permitted via the index signature.
 */
export interface JwtPayload {
  [key: string]: unknown;
  /** Expiration time as a Unix timestamp in seconds (RFC 7519 §4.1.4). */
  exp?: number;
  /** Issued-at time as a Unix timestamp in seconds (RFC 7519 §4.1.6). */
  iat?: number;
  /** Issuer claim (RFC 7519 §4.1.1). */
  iss?: string;
  /** Subject claim (RFC 7519 §4.1.2). */
  sub?: string;
}

/**
 * Options accepted by {@link sign} when producing an ML-DSA-only token.
 */
export interface SignOptions {
  /** ML-DSA parameter set to use. Defaults to `"ML-DSA-65"`. */
  algorithm?: MlDsaVariant;
  /** Lifetime in seconds from now. If set, adds an `exp` claim. */
  expiresIn?: number;
  /** Value for the `iss` claim, if any. */
  issuer?: string;
  /** Value for the `sub` claim, if any. */
  subject?: string;
}

/**
 * Options accepted by {@link hybridSign} when producing a hybrid
 * ML-DSA + Ed25519 token.
 */
export interface HybridSignOptions {
  /** Lifetime in seconds from now. If set, adds an `exp` claim. */
  expiresIn?: number;
  /** Value for the `iss` claim, if any. */
  issuer?: string;
  /** Value for the `sub` claim, if any. */
  subject?: string;
  /**
   * Override the ML-DSA parameter set. Defaults to the `variant`
   * stored on the supplied {@link HybridKeyPair}.
   */
  variant?: MlDsaVariant;
}

/**
 * Options accepted by {@link verify} when validating an ML-DSA-only token.
 */
export interface VerifyOptions {
  /** Expected ML-DSA parameter set. Defaults to `"ML-DSA-65"`. */
  algorithm?: MlDsaVariant;
  /** Require the `iss` claim to equal this value. */
  issuer?: string;
  /** Require the `sub` claim to equal this value. */
  subject?: string;
}

/**
 * Options accepted by {@link hybridVerify} when validating a hybrid
 * ML-DSA + Ed25519 token.
 */
export interface HybridVerifyOptions {
  /** Require the `iss` claim to equal this value. */
  issuer?: string;
  /** Require the `sub` claim to equal this value. */
  subject?: string;
  /** Expected ML-DSA parameter set. Defaults to `"ML-DSA-65"`. */
  variant?: MlDsaVariant;
}

/**
 * Error raised for any failure during signing, decoding, or verification.
 * The `code` field carries a stable machine-readable identifier so callers
 * can branch on failure modes without parsing error messages.
 *
 * Known codes:
 *   - `ERR_MALFORMED`          — token structure or encoding is invalid
 *   - `ERR_TYPE`               — header `typ` is not `"JWT"`
 *   - `ERR_ALGORITHM`          — header `alg` does not match expectations
 *   - `ERR_SIGNATURE`          — ML-DSA-only signature check failed
 *   - `ERR_SIGNATURE_MLDSA`    — hybrid ML-DSA signature check failed
 *   - `ERR_SIGNATURE_ED25519`  — hybrid Ed25519 signature check failed
 *   - `ERR_EXPIRED`            — `exp` claim is in the past
 *   - `ERR_ISSUER`             — `iss` claim did not match the expected issuer
 *   - `ERR_SUBJECT`            — `sub` claim did not match the expected subject
 */
export class JwtError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = "JwtError";
  }
}

/**
 * Decode a JWT without verifying the signature.
 * Useful for inspecting claims before committing to verification.
 * Never trust the output of this for authorization decisions.
 */
export function decode(token: string): { header: JwtHeader; payload: JwtPayload; } {
  const parts = token.split(".");

  if (parts.length !== 3)
    throw new JwtError("Malformed token: expected 3 parts", "ERR_MALFORMED");

  return {
    header: JSON.parse(base64urlDecodeString(parts[0])),
    payload: JSON.parse(base64urlDecodeString(parts[1]))
  };
}

/**
 * Generate a hybrid ML-DSA + Ed25519 keypair.
 * Store all secret keys securely. Distribute all public keys to verifiers.
 */
export async function generateHybridKeyPair(variant: MlDsaVariant = "ML-DSA-65"): Promise<HybridKeyPair> {
  const instance = await mlDsaFactory(variant);
  const mlDsaKeys = instance.generateKeyPair();
  const edKeys = await ed.keygenAsync();

  return {
    ed25519: {
      publicKey: base64urlEncode(edKeys.publicKey),
      secretKey: base64urlEncode(edKeys.secretKey)
    },
    mlDsa: {
      publicKey: base64urlEncode(mlDsaKeys.publicKey),
      secretKey: base64urlEncode(mlDsaKeys.secretKey)
    },
    variant
  };
}

/**
 * Generate an ML-DSA keypair.
 * Store secretKey securely. publicKey is safe to distribute to verifiers.
 */
export async function generateKeyPair(algorithm: MlDsaVariant = "ML-DSA-65"): Promise<KeyPair> {
  const instance = await mlDsaFactory(algorithm);
  const { publicKey, secretKey } = instance.generateKeyPair();

  return {
    publicKey: base64urlEncode(publicKey),
    secretKey: base64urlEncode(secretKey)
  };
}

/**
 * Sign a payload with both ML-DSA and Ed25519.
 * The signature blob is: ML-DSA sig || Ed25519 sig (64 bytes).
 * Both signatures are computed independently over the same signing input.
 * A verifier must hold both public keys and both must pass.
 *
 * @param payload - Claims to encode in the token
 * @param keyPair - Hybrid keypair from generateHybridKeyPair()
 * @param options - Signing options
 */
export async function hybridSign(payload: JwtPayload, keyPair: HybridKeyPair, options: HybridSignOptions = {}): Promise<string> {
  const { expiresIn, issuer, subject, variant = keyPair.variant } = options;
  const alg: HybridVariant = `${variant}+Ed25519`;
  const claims = buildClaims(payload, expiresIn, issuer, subject);
  const header: JwtHeader = { alg, typ: "JWT" };
  const headerB64 = base64urlEncodeString(JSON.stringify(header));
  const payloadB64 = base64urlEncodeString(JSON.stringify(claims));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingBytes = new TextEncoder().encode(signingInput);
  const instance = await mlDsaFactory(variant);
  const mlDsaSig = instance.sign(signingBytes, base64urlDecode(keyPair.mlDsa.secretKey));
  const edSig = await ed.signAsync(signingBytes, base64urlDecode(keyPair.ed25519.secretKey));

  /*** Encode: [uint32 BE mlDsaSig length][mlDsaSig][edSig] ***/
  const prefix = new Uint8Array(HYBRID_PREFIX_LENGTH);
  new DataView(prefix.buffer).setUint32(0, mlDsaSig.length, false);
  const combined = concatBytes(prefix, mlDsaSig, edSig);

  return `${signingInput}.${base64urlEncode(combined)}`;
}

/**
 * Verify a hybrid JWT. BOTH ML-DSA and Ed25519 signatures must pass.
 * If either fails, verification is rejected — this is intentional.
 *
 * @param token      - Compact hybrid JWT string
 * @param publicKeys - Both public keys from the issuing HybridKeyPair
 * @param options    - Verification options
 */
export async function hybridVerify(token: string, publicKeys: HybridPublicKeys, options: HybridVerifyOptions = {}): Promise<JwtPayload> {
  const { issuer, subject, variant = "ML-DSA-65" } = options;
  const parts = token.split(".");

  if (parts.length !== 3)
    throw new JwtError("Malformed token: expected 3 parts", "ERR_MALFORMED");

  const [headerB64, payloadB64, signatureB64] = parts;
  let header: JwtHeader;

  try {
    header = JSON.parse(base64urlDecodeString(headerB64));
  } catch {
    throw new JwtError("Malformed token: invalid header", "ERR_MALFORMED");
  }

  if (header.typ !== "JWT")
    throw new JwtError(`Invalid token type: ${header.typ}`, "ERR_TYPE");

  const expectedAlg: HybridVariant = `${variant}+Ed25519`;

  if (header.alg !== expectedAlg) {
    throw new JwtError(
      `Algorithm mismatch: token uses ${header.alg}, expected ${expectedAlg}`,
      "ERR_ALGORITHM"
    );
  }

  /*** Read the length-prefixed hybrid blob: [uint32 BE len][mlDsaSig][edSig] ***/
  const combinedBytes = base64urlDecode(signatureB64);

  if (combinedBytes.length < HYBRID_PREFIX_LENGTH + ED25519_SIG_LENGTH)
    throw new JwtError("Malformed hybrid signature: blob too short", "ERR_MALFORMED");

  const mlDsaSigLength = new DataView(combinedBytes.buffer).getUint32(0, false);
  const expectedLength = HYBRID_PREFIX_LENGTH + mlDsaSigLength + ED25519_SIG_LENGTH;

  if (combinedBytes.length !== expectedLength) {
    throw new JwtError(
      `Malformed hybrid signature: expected ${expectedLength} bytes, got ${combinedBytes.length}`,
      "ERR_MALFORMED"
    );
  }

  const mlDsaSigBytes = combinedBytes.slice(HYBRID_PREFIX_LENGTH, HYBRID_PREFIX_LENGTH + mlDsaSigLength);
  const edSigBytes = combinedBytes.slice(HYBRID_PREFIX_LENGTH + mlDsaSigLength);
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingBytes = new TextEncoder().encode(signingInput);
  const instance = await mlDsaFactory(variant);

  const mlDsaValid = instance.verify(
    signingBytes,
    mlDsaSigBytes,
    base64urlDecode(publicKeys.mlDsaPublicKey)
  );

  const edValid = await ed.verifyAsync(
    edSigBytes,
    signingBytes,
    base64urlDecode(publicKeys.ed25519PublicKey)
  );

  if (!mlDsaValid)
    throw new JwtError("ML-DSA signature verification failed", "ERR_SIGNATURE_MLDSA");

  if (!edValid)
    throw new JwtError("Ed25519 signature verification failed", "ERR_SIGNATURE_ED25519");

  const payload = parsePayload(payloadB64);
  validateClaims(payload, issuer, subject);

  return payload;
}

/**
 * Sign a payload and return a compact JWT string using ML-DSA only.
 *
 * @param payload   - Claims to encode in the token
 * @param secretKey - Base64url-encoded ML-DSA secret key
 * @param options   - Signing options
 */
export async function sign(payload: JwtPayload, secretKey: string, options: SignOptions = {}): Promise<string> {
  const { algorithm = "ML-DSA-65", expiresIn, issuer, subject } = options;
  const claims = buildClaims(payload, expiresIn, issuer, subject);
  const header: JwtHeader = { alg: algorithm, typ: "JWT" };
  const headerB64 = base64urlEncodeString(JSON.stringify(header));
  const payloadB64 = base64urlEncodeString(JSON.stringify(claims));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingBytes = new TextEncoder().encode(signingInput);
  const instance = await mlDsaFactory(algorithm);
  const signature = instance.sign(signingBytes, base64urlDecode(secretKey));

  return `${signingInput}.${base64urlEncode(signature)}`;
}

/**
 * Verify a compact JWT string and return the decoded payload.
 * Throws JwtError on any failure (invalid structure, bad signature, expiry).
 *
 * @param token     - Compact JWT string
 * @param publicKey - Base64url-encoded ML-DSA public key
 * @param options   - Verification options
 */
export async function verify(token: string, publicKey: string, options: VerifyOptions = {}): Promise<JwtPayload> {
  const { algorithm = "ML-DSA-65", issuer, subject } = options;
  const parts = token.split(".");

  if (parts.length !== 3)
    throw new JwtError("Malformed token: expected 3 parts", "ERR_MALFORMED");

  const [headerB64, payloadB64, signatureB64] = parts;
  let header: JwtHeader;

  try {
    header = JSON.parse(base64urlDecodeString(headerB64));
  } catch {
    throw new JwtError("Malformed token: invalid header", "ERR_MALFORMED");
  }

  if (header.typ !== "JWT")
    throw new JwtError(`Invalid token type: ${header.typ}`, "ERR_TYPE");

  if (header.alg !== algorithm) {
    throw new JwtError(
      `Algorithm mismatch: token uses ${header.alg}, expected ${algorithm}`,
      "ERR_ALGORITHM"
    );
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signingBytes = new TextEncoder().encode(signingInput);
  const instance = await mlDsaFactory(algorithm);

  const valid = instance.verify(
    signingBytes,
    base64urlDecode(signatureB64),
    base64urlDecode(publicKey)
  );

  if (!valid)
    throw new JwtError("Signature verification failed", "ERR_SIGNATURE");

  const payload = parsePayload(payloadB64);
  validateClaims(payload, issuer, subject);

  return payload;
}

/*** HELPER ------------------------------------------- ***/

/**
 * Decode a Base64url string (RFC 4648 §5, no padding) into raw bytes.
 * Re-pads and translates the URL-safe alphabet back to standard Base64
 * before delegating to {@link atob}.
 */
function base64urlDecode(str: string): Uint8Array {
  const padded = str
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(str.length + (4 - (str.length % 4)) % 4, "=");

  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Decode a Base64url string into a UTF-8 string. Convenience wrapper
 * around {@link base64urlDecode} used for JSON header/payload segments.
 */
function base64urlDecodeString(str: string): string {
  return new TextDecoder().decode(base64urlDecode(str));
}

/**
 * Encode raw bytes as a Base64url string (RFC 4648 §5, no padding).
 */
function base64urlEncode(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/**
 * Encode a UTF-8 string as Base64url. Convenience wrapper around
 * {@link base64urlEncode} used for JSON header/payload segments.
 */
function base64urlEncodeString(str: string): string {
  return base64urlEncode(new TextEncoder().encode(str));
}

/**
 * Merge user-supplied claims with standard registered claims.
 * Always injects `iat` (issued-at) using the current wall clock, and
 * conditionally adds `exp`, `iss`, and `sub` when the corresponding
 * options are provided. User-supplied values in `payload` are
 * overwritten by `iat` but preserved otherwise.
 */
function buildClaims(payload: JwtPayload, expiresIn?: number, issuer?: string, subject?: string): JwtPayload {
  const now = Math.floor(Date.now() / 1000);

  return {
    ...payload,
    iat: now,
    ...(expiresIn !== undefined ? { exp: now + expiresIn } : {}),
    ...(issuer !== undefined ? { iss: issuer } : {}),
    ...(subject !== undefined ? { sub: subject } : {})
  };
}

/**
 * Concatenate any number of `Uint8Array`s into a single buffer.
 * Used to assemble the hybrid signature blob.
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;

  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }

  return out;
}

/**
 * Return an initialised ML-DSA instance for the requested variant.
 * Each call constructs a fresh WebAssembly-backed instance from
 * `@oqs/liboqs-js`; callers are expected to obtain and discard these
 * per operation rather than cache them.
 */
async function mlDsaFactory(variant: MlDsaVariant): Promise<Awaited<ReturnType<typeof createMLDSA65>>> {
  switch (variant) {
    case "ML-DSA-44": {
      return await createMLDSA44();
    }

    case "ML-DSA-65": {
      return await createMLDSA65();
    }

    case "ML-DSA-87": {
      return await createMLDSA87();
    }
  }
}

/**
 * Decode and JSON-parse the payload segment of a JWT, raising a
 * {@link JwtError} with code `ERR_MALFORMED` on any failure.
 */
function parsePayload(payloadB64: string): JwtPayload {
  try {
    return JSON.parse(base64urlDecodeString(payloadB64));
  } catch {
    throw new JwtError("Malformed token: invalid payload", "ERR_MALFORMED");
  }
}

/**
 * Enforce registered-claim constraints after a signature has verified.
 * Checks `exp` against the current time and, when supplied, that
 * `iss` and `sub` match the expected values. Throws a {@link JwtError}
 * with an appropriate code on any mismatch.
 */
function validateClaims(payload: JwtPayload, issuer?: string, subject?: string): void {
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp !== undefined && payload.exp < now) {
    throw new JwtError(
      `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
      "ERR_EXPIRED"
    );
  }

  if (issuer !== undefined && payload.iss !== issuer) {
    throw new JwtError(
      `Issuer mismatch: expected "${issuer}", got "${payload.iss}"`,
      "ERR_ISSUER"
    );
  }

  if (subject !== undefined && payload.sub !== subject) {
    throw new JwtError(
      `Subject mismatch: expected "${subject}", got "${payload.sub}"`,
      "ERR_SUBJECT"
    );
  }
}
