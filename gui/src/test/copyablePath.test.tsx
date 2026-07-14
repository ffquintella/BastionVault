import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CopyablePath } from "../components/ui/CopyablePath";
import { ToastProvider } from "../components/ui/Toast";

function renderPath(path: string) {
  return render(
    <ToastProvider>
      <CopyablePath path={path} />
    </ToastProvider>,
  );
}

describe("CopyablePath", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });

  it("renders the full path text", () => {
    renderPath("dti/esi/secret/data/github/rustion");
    expect(
      screen.getByText("dti/esi/secret/data/github/rustion"),
    ).toBeInTheDocument();
  });

  it("writes the exact path to the clipboard on copy", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(navigator.clipboard, "writeText");
    renderPath("dti/esi/resources/resources/db-01");
    await user.click(screen.getByRole("button", { name: /copy/i }));
    expect(spy).toHaveBeenCalledWith("dti/esi/resources/resources/db-01");
  });

  it("shows a Copied confirmation after copying", async () => {
    const user = userEvent.setup();
    renderPath("files/files/abc123");
    await user.click(screen.getByRole("button", { name: /copy/i }));
    expect(
      await screen.findByRole("button", { name: /copied/i }),
    ).toBeInTheDocument();
  });

  it("supports a custom label", () => {
    render(
      <ToastProvider>
        <CopyablePath path="secret/data/x" label="ACL path" />
      </ToastProvider>,
    );
    expect(screen.getByText("ACL path")).toBeInTheDocument();
  });
});

// The three pages each assemble the namespace-qualified ACL path inline.
// This mirrors that logic to lock the policy-ready forms: KV-v2 gets the
// `data/` infix, KV-v1 does not, resources/files use their fixed mount
// prefixes, and the active namespace (if any) is prepended.
function nsPrefix(ns: string, acl: string): string {
  const trimmed = ns.replace(/^\/+|\/+$/g, "");
  return trimmed ? `${trimmed}/${acl}` : acl;
}

function secretAclPath(
  mountBase: string,
  currentPath: string,
  key: string,
  mountType: string,
): string {
  const mount = mountBase.replace(/\/+$/, "");
  const logical = (currentPath + key).replace(/^\/+/, "");
  const rel = logical.startsWith(mount + "/")
    ? logical.slice(mount.length + 1)
    : logical === mount
      ? ""
      : logical;
  const infix = mountType === "kv-v2" ? "data/" : "";
  return `${mount}/${infix}${rel}`;
}

describe("namespace-qualified ACL path forms", () => {
  it("KV-v2 secret inserts the data/ infix", () => {
    const acl = secretAclPath("secret/", "secret/github/", "rustion", "kv-v2");
    expect(nsPrefix("dti/esi", acl)).toBe("dti/esi/secret/data/github/rustion");
  });

  it("KV-v1 secret has no infix", () => {
    const acl = secretAclPath("secret/", "secret/github/", "rustion", "kv");
    expect(nsPrefix("dti/esi", acl)).toBe("dti/esi/secret/github/rustion");
  });

  it("root namespace ('') produces an unprefixed path", () => {
    const acl = secretAclPath("secret/", "secret/", "api-key", "kv-v2");
    expect(nsPrefix("", acl)).toBe("secret/data/api-key");
  });

  it("resource path uses the resources/resources/ mount prefix", () => {
    expect(nsPrefix("dti/esi", "resources/resources/db-01")).toBe(
      "dti/esi/resources/resources/db-01",
    );
  });

  it("file path uses the files/files/ mount prefix", () => {
    expect(nsPrefix("", "files/files/abc123")).toBe("files/files/abc123");
  });
});
