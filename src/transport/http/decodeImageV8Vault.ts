/**
 * EXPERIMENTAL — vault-password path for v8 images. NOT for merge as-is.
 *
 * {@link decodeImageV8} decodes a v8 blob given the account's vault private key. On a password-escrowed
 * account the app gets that key by `get_safebox_etoe_key` (authorised by `sha256(vaultPassword)`) and
 * unwrapping the returned, password-wrapped private key with `AESUtils.h` — whose exact scheme we have
 * NOT recovered. So this module is a **self-verifying probe**: it fetches the wrapped key and tries the
 * documented unwrap schemes, accepting one ONLY if the result regenerates the account's public key
 * (`priv·G == public_key`) — a hard gate that cannot false-positive. It is meant to run once on a real
 * password-escrowed account to learn which scheme the app uses; the confirmed scheme then replaces this
 * whole candidate loop in a proper decoder. It requires the owner's own vault password.
 */
import { createDecipheriv, createECDH, createHash } from "node:crypto";
import { decodeImageV8, isV8Image } from "./decodeImageV8.js";

/** A minimal view of the signed security-app POST the probe needs, so it stays decoupled from the client. */
export interface V8VaultDeps {
  /** `MegaHttpClient.securityAppPost` — a signed POST to the eufylife security-app host. */
  post: <T = unknown>(path: string, body: Record<string, unknown>) => Promise<T>;
  /** The account (owner) user id. */
  userId: string;
  /** The owner's Local-Advanced-Encryption vault password. */
  vaultPassword: string;
}

export interface V8VaultOutcome {
  jpeg?: Buffer;
  /** The unwrap scheme that verified against the public key, e.g. `aes-256-cbc/pad0-32/iv-zero/pkcs7`. */
  scheme?: string;
  /** Where it stopped when it could not produce an image. */
  phase?: "not-v8" | "fetch" | "no-scheme" | "decode";
  detail?: string;
}

const PIN_OFFSET = 33;
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
const md5 = (b: Buffer) => createHash("md5").update(b).digest();
const asBytes = (s: string) =>
  /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0 ? Buffer.from(s, "hex") : Buffer.from(s, "base64");

/** Candidate key derivations the eufy app's crypto utils are known to use (`EncUtil.a` pad-to-32, sha256, md5). */
function candidateKeys(pw: string): Record<string, Buffer> {
  const b = Buffer.from(pw, "utf8");
  return {
    "pad0-32": Buffer.from(pw.padEnd(32, "0").slice(0, 32), "utf8"),
    sha256: sha256(b),
    md5: md5(b),
    "sha256hex-32": Buffer.from(sha256(b).toString("hex").slice(0, 32), "utf8"),
  };
}

/** True (returning the 32-byte scalar) if `priv` is the P-256 key behind `pubHexes`. */
function matchesPublicKey(priv: Buffer, pubHexes: Set<string>): string | undefined {
  for (const p of [priv.subarray(0, 32), priv.subarray(-32)]) {
    if (p.length !== 32) continue;
    try {
      const e = createECDH("prime256v1");
      e.setPrivateKey(p);
      const u = e.getPublicKey("hex", "uncompressed");
      const c = e.getPublicKey("hex", "compressed");
      if (pubHexes.has(u) || pubHexes.has(c) || pubHexes.has(u.slice(2)) || pubHexes.has(u.slice(2, 66))) {
        return p.toString("hex");
      }
    } catch {
      /* not a valid scalar */
    }
  }
  return undefined;
}

/** Try the documented unwrap schemes; return the vault private key + the scheme that verified, or undefined. */
function unwrapVaultKey(
  wrapped: Buffer,
  pubHexes: Set<string>,
  pw: string,
): { privHex: string; scheme: string } | undefined {
  const keys = candidateKeys(pw);
  const pad0 = keys["pad0-32"];
  const ivs: Record<string, Buffer> = {
    "iv-zero": Buffer.alloc(16),
    "iv-pad0": pad0.subarray(0, 16),
    "iv-head16": wrapped.subarray(0, 16),
  };
  for (const mode of ["aes-256-cbc", "aes-256-ecb", "aes-128-cbc", "aes-128-ecb"] as const) {
    const need = mode.includes("256") ? 32 : 16;
    for (const [kn, key] of Object.entries(keys)) {
      if (key.length < need) continue;
      const k = key.subarray(0, need);
      const ivEntries: Array<[string, Buffer | null]> = mode.includes("ecb") ? [["none", null]] : Object.entries(ivs);
      for (const [ivn, iv] of ivEntries) {
        const body = ivn === "iv-head16" ? wrapped.subarray(16) : wrapped;
        for (const pad of [true, false]) {
          try {
            const d = createDecipheriv(mode, k, iv);
            d.setAutoPadding(pad);
            const out = Buffer.concat([d.update(body), d.final()]);
            const privHex =
              matchesPublicKey(out, pubHexes) ??
              (/^[0-9a-f]+$/i.test(out.toString("utf8").trim())
                ? matchesPublicKey(Buffer.from(out.toString("utf8").trim(), "hex"), pubHexes)
                : undefined);
            if (privHex) return { privHex, scheme: `${mode}/${kn}/${ivn}/${pad ? "pkcs7" : "nopad"}` };
          } catch {
            /* wrong combination */
          }
        }
      }
    }
  }
  return undefined;
}

/**
 * EXPERIMENTAL. Fetch the owner's vault key by password and decode a v8 blob, learning the unwrap scheme.
 * Returns the JPEG + the verified scheme on success, or the phase it stopped at.
 */
export async function decodeImageV8WithVault(blob: Buffer, deps: V8VaultDeps): Promise<V8VaultOutcome> {
  if (!isV8Image(blob)) return { phase: "not-v8" };
  const pincodeId = blob[PIN_OFFSET];
  const pwHash = sha256(Buffer.from(deps.vaultPassword, "utf8")).toString("hex");
  let res: { private_key?: string; public_key?: string };
  try {
    res = await deps.post("/v3/app/cloud/get_safebox_etoe_key", {
      user_id: deps.userId,
      pincode_id: pincodeId,
      password: pwHash,
    });
  } catch (e) {
    return { phase: "fetch", detail: e instanceof Error ? e.message : String(e) };
  }
  if (!res?.private_key || !res?.public_key) return { phase: "fetch", detail: "no key in response" };

  const pub = asBytes(res.public_key);
  const pubHexes = new Set([
    pub.toString("hex"),
    pub.subarray(-32).toString("hex"),
    pub.length >= 64 ? pub.subarray(-64, -32).toString("hex") : "",
  ]);
  const got = unwrapVaultKey(asBytes(res.private_key), pubHexes, deps.vaultPassword);
  if (!got) return { phase: "no-scheme", detail: "no documented unwrap matched the public key" };

  const jpeg = decodeImageV8(blob, got.privHex);
  if (!jpeg) return { phase: "decode", scheme: got.scheme, detail: "key verified but the image did not decode" };
  return { jpeg, scheme: got.scheme };
}
