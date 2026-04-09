/**
 * example.ts — Usage example for mod.ts
 * Run with: deno run example.ts
 */

/*** UTILITY ------------------------------------------ ***/

import {
  decode,
  generateHybridKeyPair,
  generateKeyPair,
  hybridSign,
  hybridVerify,
  JwtError,
  KEY_SIZES,
  sign,
  verify
} from "./mod.ts";

/*** 1. ML-DSA only ----------------------------------- ***/

console.log("\n/*** ML-DSA only -------------------------------------- ***/\n");

const { publicKey, secretKey } = await generateKeyPair("ML-DSA-65");
console.log("Public key length (chars):", publicKey.length, "\n");

const token = await sign(
  {
    role: "member",
    sub: "user_01jrwx8k9e4fv3z2"
  },
  secretKey,
  {
    algorithm: "ML-DSA-65",
    expiresIn: 3600,
    issuer: "kern.neue"
  }
);

console.log("Token length (chars):", token.length, "\n");

const { header, payload } = decode(token);

console.log("Header:", header, "\n");
console.log("Payload:", payload, "\n");

try {
  const claims = await verify(token, publicKey, {
    algorithm: "ML-DSA-65",
    issuer: "kern.neue"
  });

  console.log("✓ ML-DSA verification passed. sub:", claims.sub);
} catch (err) {
  if (err instanceof JwtError)
    console.error("✗", err.message, err.code);
}

/*** 2. Hybrid ML-DSA-65 + Ed25519 -------------------- ***/

console.log("\n/*** Hybrid ML-DSA-65 + Ed25519 ----------------------- ***/\n");

const hybridKeys = await generateHybridKeyPair("ML-DSA-65");

console.log("ML-DSA public key length (chars):", hybridKeys.mlDsa.publicKey.length, "\n");
console.log("Ed25519 public key length (chars):", hybridKeys.ed25519.publicKey.length, "\n");

const hybridToken = await hybridSign(
  {
    role: "admin",
    sub: "user_01jrwx8k9e4fv3z2"
  },
  hybridKeys,
  {
    expiresIn: 3600,
    issuer: "kern.neue"
  }
);

console.log("Hybrid token length (chars):", hybridToken.length, "\n");
console.log("Hybrid header:", decode(hybridToken).header, "\n");

try {
  const claims = await hybridVerify(
    hybridToken,
    {
      ed25519PublicKey: hybridKeys.ed25519.publicKey,
      mlDsaPublicKey: hybridKeys.mlDsa.publicKey
    },
    {
      issuer: "kern.neue",
      variant: "ML-DSA-65"
    }
  );

  console.log("✓ Hybrid verification passed. sub:", claims.sub);
} catch (err) {
  if (err instanceof JwtError)
    console.error("✗", err.message, err.code);
}

/*** 3. Tamper detection ------------------------------ ***/

console.log("\n/*** Tamper detection --------------------------------- ***/\n");

const tampered = hybridToken.slice(0, -10) + "AAAAAAAAAA";

try {
  await hybridVerify(tampered, {
    ed25519PublicKey: hybridKeys.ed25519.publicKey,
    mlDsaPublicKey: hybridKeys.mlDsa.publicKey
  }, { variant: "ML-DSA-65" });
} catch (err) {
  if (err instanceof JwtError)
    console.log("✓ Tampered token rejected:", err.message, `[${err.code}]`);
}

/*** 4. Wrong public key ------------------------------ ***/

console.log("\n/*** Wrong public key --------------------------------- ***/\n");

const otherKeys = await generateHybridKeyPair("ML-DSA-65");

try {
  await hybridVerify(
    hybridToken,
    {
      ed25519PublicKey: otherKeys.ed25519.publicKey,
      mlDsaPublicKey: otherKeys.mlDsa.publicKey
    },
    {
      variant: "ML-DSA-65"
    }
  );
} catch (err) {
  if (err instanceof JwtError)
    console.log("✓ Wrong key rejected:", err.message, `[${err.code}]`);
}

/*** 5. Key sizes (raw bytes) ------------------------- ***/

console.log("\n/*** Key sizes (raw bytes) ---------------------------- ***/\n");

for (const [variant, sizes] of Object.entries(KEY_SIZES)) {
  console.log(`${variant}`);
  console.log("  ML-DSA public key: ", sizes.mlDsaPublicKey, "bytes");
  console.log("  ML-DSA secret key: ", sizes.mlDsaSecretKey, "bytes");
  console.log("  Ed25519 public key:", sizes.ed25519PublicKey, "bytes");
  console.log("  Ed25519 secret key:", sizes.ed25519SecretKey, "bytes");
}
