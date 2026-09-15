import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// The validator calls the Tauri bridge through `lib/api` / `lib/rustion`.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import {
  CONNECT_VALIDATION_TTL_MS,
  clearConnectAccessCache,
  connectAccessCacheSizeForTests,
  invalidateConnectAccess,
  revalidateConnectAccess,
  staticVerdict,
  validateConnectAccess,
  type ConnectCandidate,
} from "../lib/connectValidation";

const SSH_SECRET = {
  protocol: "ssh",
  credential_source: { kind: "secret" },
} as const;

function candidate(over: Partial<ConnectCandidate> = {}): ConnectCandidate {
  return {
    name: "web01",
    type: "server",
    connectEnabled: true,
    hints: [{ ...SSH_SECRET }],
    assetGroupIds: [],
    ...over,
  };
}

/** `capabilities_self` answering "can read the secrets" for every path. */
function mockReadable() {
  mockInvoke.mockImplementation((cmd: string, args: any) => {
    if (cmd === "capabilities_self") {
      const paths: string[] = args.paths;
      return Promise.resolve({
        paths: Object.fromEntries(paths.map((p) => [p, ["read"]])),
      });
    }
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

/** `capabilities_self` answering "connect-only" plus a transport verdict. */
function mockConnectOnly(transport: string, bastions: string[] = []) {
  mockInvoke.mockImplementation((cmd: string, args: any) => {
    if (cmd === "capabilities_self") {
      const paths: string[] = args.paths;
      return Promise.resolve({
        paths: Object.fromEntries(paths.map((p) => [p, ["connect"]])),
      });
    }
    if (cmd === "rustion_policy_effective") {
      return Promise.resolve({ transport, bastions });
    }
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

describe("connect-access validator", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    clearConnectAccessCache();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  describe("staticVerdict", () => {
    it("refuses a non-server resource without a round trip", () => {
      expect(staticVerdict(candidate({ type: "database" }))?.allowed).toBe(false);
    });

    it("refuses a resource whose type has Connect disabled", () => {
      expect(staticVerdict(candidate({ connectEnabled: false }))?.allowed).toBe(
        false,
      );
    });

    it("refuses a resource with an empty profile list", () => {
      const v = staticVerdict(candidate({ hints: [] }));
      expect(v?.allowed).toBe(false);
      expect(v?.indeterminate).toBe(false);
      expect(v?.reason).toMatch(/No connection profile/);
    });

    it("leaves a card that carries no hints indeterminate, not denied", () => {
      const v = staticVerdict(candidate({ hints: undefined }));
      expect(v?.allowed).toBe(true);
      expect(v?.indeterminate).toBe(true);
    });

    it("defers to the server for a server resource with profiles", () => {
      expect(staticVerdict(candidate())).toBeNull();
    });
  });

  it("allows a credential-readable caller with a launchable profile", async () => {
    mockReadable();
    const res = await validateConnectAccess([candidate()], "e1@");
    expect(res.web01.allowed).toBe(true);
    expect(res.web01.connectOnly).toBe(false);
    expect(res.web01.indeterminate).toBe(false);
    // No transport resolution needed on this path.
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "rustion_policy_effective",
      expect.anything(),
    );
  });

  it("denies a connect-only caller whose profiles are all direct", async () => {
    mockConnectOnly("direct");
    const res = await validateConnectAccess([candidate()], "e1@");
    expect(res.web01.allowed).toBe(false);
    expect(res.web01.connectOnly).toBe(true);
    expect(res.web01.indeterminate).toBe(false);
    expect(res.web01.reason).toMatch(/bastion/);
  });

  it("allows a connect-only caller when the transport tier brokers the session", async () => {
    // The case that used to be refused off the card hints alone: the profile
    // isn't tagged `kind: "rustion"`, but the resource is pinned to
    // rustion-required, so the credential resolves server-side.
    mockConnectOnly("rustion-required");
    const res = await validateConnectAccess([candidate()], "e1@");
    expect(res.web01.allowed).toBe(true);
  });

  it("stays permissive and indeterminate when the capabilities probe fails", async () => {
    mockInvoke.mockImplementation(() => Promise.reject(new Error("boom")));
    const res = await validateConnectAccess([candidate()], "e1@");
    expect(res.web01.allowed).toBe(true);
    expect(res.web01.indeterminate).toBe(true);
  });

  it("stays permissive when the transport resolver refuses a connect-only caller", async () => {
    mockInvoke.mockImplementation((cmd: string, args: any) => {
      if (cmd === "capabilities_self") {
        const paths: string[] = args.paths;
        return Promise.resolve({
          paths: Object.fromEntries(paths.map((p) => [p, ["connect"]])),
        });
      }
      return Promise.reject(new Error("permission denied"));
    });
    const res = await validateConnectAccess([candidate()], "e1@");
    expect(res.web01.allowed).toBe(true);
    expect(res.web01.indeterminate).toBe(true);
  });

  it("probes every candidate in one capabilities call", async () => {
    mockReadable();
    const names = ["a", "b", "c"];
    await validateConnectAccess(
      names.map((n) => candidate({ name: n })),
      "e1@",
    );
    const capsCalls = mockInvoke.mock.calls.filter(
      (c) => c[0] === "capabilities_self",
    );
    expect(capsCalls).toHaveLength(1);
    expect(capsCalls[0][1].paths).toEqual([
      "resources/secrets/a/",
      "resources/secrets/b/",
      "resources/secrets/c/",
    ]);
  });

  it("serves a second pass from the cache", async () => {
    mockReadable();
    await validateConnectAccess([candidate()], "e1@");
    await validateConnectAccess([candidate()], "e1@");
    expect(
      mockInvoke.mock.calls.filter((c) => c[0] === "capabilities_self"),
    ).toHaveLength(1);
    expect(connectAccessCacheSizeForTests()).toBe(1);
  });

  it("re-probes once the TTL lapses", async () => {
    vi.useFakeTimers();
    mockReadable();
    await validateConnectAccess([candidate()], "e1@");
    vi.advanceTimersByTime(CONNECT_VALIDATION_TTL_MS + 1);
    await validateConnectAccess([candidate()], "e1@");
    expect(
      mockInvoke.mock.calls.filter((c) => c[0] === "capabilities_self"),
    ).toHaveLength(2);
  });

  it("does not reuse a verdict across authorization scopes", async () => {
    mockReadable();
    await validateConnectAccess([candidate()], "e1@");
    await validateConnectAccess([candidate()], "e2@");
    expect(
      mockInvoke.mock.calls.filter((c) => c[0] === "capabilities_self"),
    ).toHaveLength(2);
  });

  it("re-probes when the resource's profile set changes", async () => {
    mockReadable();
    await validateConnectAccess([candidate()], "e1@");
    await validateConnectAccess(
      [
        candidate({
          hints: [{ protocol: "rdp", credential_source: { kind: "secret" } }],
        }),
      ],
      "e1@",
    );
    expect(
      mockInvoke.mock.calls.filter((c) => c[0] === "capabilities_self"),
    ).toHaveLength(2);
  });

  it("drops the cache and notifies subscribers on a forced revalidation", async () => {
    mockReadable();
    await validateConnectAccess([candidate()], "e1@");
    const seen = vi.fn();
    const { subscribeConnectAccess, connectAccessEpoch } = await import(
      "../lib/connectValidation"
    );
    const before = connectAccessEpoch();
    const off = subscribeConnectAccess(seen);
    revalidateConnectAccess();
    expect(seen).toHaveBeenCalledTimes(1);
    expect(connectAccessEpoch()).toBe(before + 1);
    expect(connectAccessCacheSizeForTests()).toBe(0);
    off();

    await validateConnectAccess([candidate()], "e1@");
    expect(
      mockInvoke.mock.calls.filter((c) => c[0] === "capabilities_self"),
    ).toHaveLength(2);
  });

  it("invalidates one resource without touching the rest", async () => {
    mockReadable();
    await validateConnectAccess(
      [candidate({ name: "a" }), candidate({ name: "b" })],
      "e1@",
    );
    expect(connectAccessCacheSizeForTests()).toBe(2);
    invalidateConnectAccess("a");
    expect(connectAccessCacheSizeForTests()).toBe(1);
  });
});
