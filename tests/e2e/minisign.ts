// Throwaway Minisign key for the E2E update tests. It lives in target/
// (gitignored) and is never a release key.
//
// `node tests/e2e/minisign.ts` prints the public key; `npm run e2e` bakes it
// into the debug agent through CENTRALD_UPDATE_PUBKEY.
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const KEY_FILE = path.resolve(
  import.meta.dirname,
  "../../target/e2e-update-key.json",
);

export interface UpdateKey {
  publicKey: string;
  keyId: Buffer;
  secret: KeyObject;
}

function generate(): string {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(
    publicKey.export({ format: "jwk" }).x ?? "",
    "base64url",
  );
  const keyId = randomBytes(8);
  return JSON.stringify({
    keyId: keyId.toString("hex"),
    publicKey: Buffer.concat([Buffer.from("Ed"), keyId, raw]).toString(
      "base64",
    ),
    secret: privateKey.export({ format: "pem", type: "pkcs8" }),
  });
}

/** Loads the key at `file`, creating it first when `create` is set. */
export function updateKey(file = KEY_FILE, create = false): UpdateKey {
  if (!existsSync(file)) {
    if (!create) {
      throw new Error(`${file} is missing. Run \`npm run e2e\`.`);
    }
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, generate(), { mode: 0o600 });
  }
  const data = JSON.parse(readFileSync(file, "utf8"));
  return {
    publicKey: data.publicKey,
    keyId: Buffer.from(data.keyId, "hex"),
    secret: createPrivateKey(data.secret),
  };
}

/** A prehashed (`ED`) Minisign signature, as `minisign -S` writes it. */
export function minisign(
  data: Buffer,
  trustedComment: string,
  key: UpdateKey,
): string {
  const prehash = createHash("blake2b512").update(data).digest();
  const signature = sign(null, prehash, key.secret);
  const global = sign(
    null,
    Buffer.concat([signature, Buffer.from(trustedComment)]),
    key.secret,
  );
  return [
    "untrusted comment: CentralD E2E signature",
    Buffer.concat([Buffer.from("ED"), key.keyId, signature]).toString("base64"),
    `trusted comment: ${trustedComment}`,
    global.toString("base64"),
    "",
  ].join("\n");
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.stdout.write(updateKey(KEY_FILE, true).publicKey);
}
