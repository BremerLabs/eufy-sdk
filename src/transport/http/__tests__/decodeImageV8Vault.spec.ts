import { createCipheriv, createECDH, createHash, createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decodeImageV8WithVault } from "../decodeImageV8Vault.js";

// Build a v8 blob (ECIES-wrap of the AES key + GCM image), mirroring decodeImageV8.spec's synthesis.
function eufyKdf(shared: Buffer, outLen: number): Buffer {
  const hmac = (k: Buffer, d: Buffer) => createHmac("sha256", k).update(d).digest();
  const label = Buffer.from("ECIES");
  let out = Buffer.alloc(0);
  let t = label;
  while (out.length < outLen) {
    t = hmac(shared, t);
    out = Buffer.concat([out, hmac(shared, Buffer.concat([t, label]))]);
  }
  return out.subarray(0, outLen);
}
const pkcs7 = (b: Buffer, bl = 16) => Buffer.concat([b, Buffer.alloc(bl - (b.length % bl), bl - (b.length % bl))]);
function eciesWrap(payload: Buffer, pub: Buffer): Buffer {
  const eph = createECDH("prime256v1");
  eph.generateKeys();
  const iv = randomBytes(16);
  const kdf = eufyKdf(eph.computeSecret(pub), 48);
  const cipher = createCipheriv("aes-128-cbc", kdf.subarray(0, 16), iv);
  cipher.setAutoPadding(false);
  const ct = Buffer.concat([cipher.update(pkcs7(payload)), cipher.final()]);
  const mac = createHmac("sha256", kdf.subarray(16, 48))
    .update(Buffer.concat([iv, ct]))
    .digest();
  return Buffer.concat([eph.getPublicKey(undefined, "compressed"), iv, ct, mac]);
}
function buildV8(jpeg: Buffer, pub: Buffer): Buffer {
  const aesKey = randomBytes(32);
  const nonce = randomBytes(12);
  const gcm = createCipheriv("aes-256-gcm", aesKey, nonce);
  const ct = Buffer.concat([gcm.update(jpeg), gcm.final()]);
  return Buffer.concat([
    Buffer.from("v8_eufysecurity:", "latin1"),
    Buffer.from("T8030P000000000E", "latin1"),
    Buffer.from(":", "latin1"),
    Buffer.from([14]),
    eciesWrap(aesKey, pub),
    nonce,
    gcm.getAuthTag(),
    ct,
  ]);
}

const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from("vault jpeg".repeat(30))]);
const PW = "Test12456";

describe("decodeImageV8WithVault (experimental, self-verifying)", () => {
  it("fetches the wrapped key, finds the unwrap scheme via the public-key check, and decodes", async () => {
    // Vault keypair, and the server storing the private key wrapped under aes-256-cbc / pad0-32 / zero-iv.
    const vault = createECDH("prime256v1");
    vault.generateKeys();
    const priv = vault.getPrivateKey(); // 32 bytes
    const pub = vault.getPublicKey(); // uncompressed
    const wrapKey = Buffer.from(PW.padEnd(32, "0").slice(0, 32), "utf8");
    const enc = createCipheriv("aes-256-cbc", wrapKey, Buffer.alloc(16));
    const wrapped = Buffer.concat([enc.update(pkcs7(Buffer.from(priv))), enc.final()]);

    const blob = buildV8(JPEG, pub);
    const post = async (path: string, body: Record<string, unknown>) => {
      expect(path).toBe("/v3/app/cloud/get_safebox_etoe_key");
      expect(body.pincode_id).toBe(14);
      expect(body.password).toBe(createHash("sha256").update(Buffer.from(PW, "utf8")).digest("hex")); // hashed, not raw
      return { private_key: wrapped.toString("base64"), public_key: pub.toString("hex") } as never;
    };

    const out = await decodeImageV8WithVault(blob, { post, userId: "u1", vaultPassword: PW });
    expect(out.phase).toBeUndefined();
    expect(out.scheme).toContain("aes-256-cbc/pad0-32");
    expect(out.jpeg?.equals(JPEG)).toBe(true);
  });

  it("reports no-scheme when the wrap is non-standard (no false positive)", async () => {
    const vault = createECDH("prime256v1");
    vault.generateKeys();
    const pub = vault.getPublicKey();
    const post = async () =>
      ({ private_key: randomBytes(48).toString("base64"), public_key: pub.toString("hex") }) as never;
    const out = await decodeImageV8WithVault(buildV8(JPEG, pub), { post, userId: "u1", vaultPassword: PW });
    expect(out.phase).toBe("no-scheme");
    expect(out.jpeg).toBeUndefined();
  });

  it("surfaces a fetch failure", async () => {
    const post = async () => {
      throw new Error("100062: Failed to request");
    };
    const vault = createECDH("prime256v1");
    vault.generateKeys();
    const out = await decodeImageV8WithVault(buildV8(JPEG, vault.getPublicKey()), {
      post,
      userId: "u1",
      vaultPassword: PW,
    });
    expect(out.phase).toBe("fetch");
  });
});
