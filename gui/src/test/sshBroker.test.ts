import { describe, it, expect } from "vitest";
import {
  isStaticSshCredential,
  findStaticSshSecrets,
  STATIC_CREDENTIAL_SCAN_LIMIT,
} from "../lib/sshBroker";

describe("isStaticSshCredential (mirrors the server guard)", () => {
  it("flags a non-blank private_key or password", () => {
    expect(isStaticSshCredential({ private_key: "x" })).toBe(true);
    expect(isStaticSshCredential({ password: "p" })).toBe(true);
  });
  it("ignores blanks, passphrases and generic blobs", () => {
    expect(isStaticSshCredential({ password: "  " })).toBe(false);
    expect(isStaticSshCredential({ passphrase: "p" })).toBe(false);
    expect(isStaticSshCredential({ token: "t" })).toBe(false);
    expect(isStaticSshCredential({ password: 5 })).toBe(false);
  });
});

describe("findStaticSshSecrets", () => {
  it("returns only names, skipping unreadable and non-credential secrets", async () => {
    const data: Record<string, Record<string, unknown>> = {
      a: { password: "p" },
      b: { token: "t" },
      d: { private_key: "k" },
    };
    const out = await findStaticSshSecrets(["a", "b", "c", "d"], async (k) => {
      if (!(k in data)) throw new Error("denied");
      return data[k];
    });
    expect(out).toEqual(["a", "d"]);
  });
  it("caps how many secrets it reads", async () => {
    let reads = 0;
    const keys = Array.from({ length: STATIC_CREDENTIAL_SCAN_LIMIT + 20 }, (_, i) => `k${i}`);
    await findStaticSshSecrets(keys, async () => {
      reads++;
      return {};
    });
    expect(reads).toBe(STATIC_CREDENTIAL_SCAN_LIMIT);
  });
});
