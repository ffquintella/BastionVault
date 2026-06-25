import { describe, it, expect } from "vitest";
import {
  extractError,
  isMountNotFound,
  isNodeUnavailable,
  isPermissionDenied,
  isVaultSealed,
} from "../lib/error";

describe("extractError", () => {
  it("reads the .message field of a Tauri CommandError object", () => {
    expect(extractError({ message: "HTTP 403: Permission denied" })).toBe(
      "HTTP 403: Permission denied",
    );
  });

  it("reads Error instances", () => {
    expect(extractError(new Error("boom"))).toBe("boom");
  });

  it("stringifies anything else", () => {
    expect(extractError("plain")).toBe("plain");
  });
});

describe("isPermissionDenied", () => {
  it("matches an HTTP 403 from the backend", () => {
    expect(isPermissionDenied({ message: "HTTP 403: Permission denied" })).toBe(
      true,
    );
  });

  it("matches a permission-denied message without a status code", () => {
    expect(isPermissionDenied(new Error("permission denied"))).toBe(true);
  });

  it("does not match unrelated errors", () => {
    expect(isPermissionDenied(new Error("HTTP 500: internal error"))).toBe(
      false,
    );
    expect(isPermissionDenied({ message: "404 mount not found" })).toBe(false);
  });
});

describe("isVaultSealed", () => {
  it("matches a remote sealed-node error", () => {
    expect(
      isVaultSealed({
        message:
          "node `https://vault.example.com:4200` is unavailable: BastionVault is sealed.",
      }),
    ).toBe(true);
  });

  it("matches a plain sealed message", () => {
    expect(isVaultSealed(new Error("vault is sealed"))).toBe(true);
  });

  it("does not match the opposite 'unsealed' wording", () => {
    expect(isVaultSealed(new Error("vault is already unsealed"))).toBe(false);
  });

  it("does not match unrelated errors", () => {
    expect(isVaultSealed(new Error("HTTP 403: Permission denied"))).toBe(false);
  });
});

describe("error classifiers stay distinct", () => {
  it("a 403 is not a mount-not-found", () => {
    const e = { message: "HTTP 403: Permission denied" };
    expect(isPermissionDenied(e)).toBe(true);
    expect(isMountNotFound(e)).toBe(false);
    expect(isNodeUnavailable(e)).toBe(false);
  });
});
