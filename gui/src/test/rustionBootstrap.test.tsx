// Smoke test for the Bootstrap Master wizard in RustionBastionsTab.
//
// Asserts that clicking "Bootstrap master" on the empty-state panel,
// filling the modal, and submitting drives the right Tauri commands
// in the right order:
//   pki_list_mounts → pki_enable_mount → pki_list_issuers
//   → pki_generate_root (×2) → pki_write_role (×2)
//   → rustion_master_write → rustion_master_issue
//
// Two roots are generated (one Ed25519, one ML-DSA-65) because BV's PKI
// refuses mixed-class chains, so each leaf role pins its own same-class
// issuer.
//
// We don't pin on the exact arg shape of every call (the rustion master
// config snapshot has a lot of dead fields the wizard fills with empty
// values); we pin on the command names + role-name args because those
// are the load-bearing parts an operator would care about.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { RustionBastionsTab } from "../components/RustionBastionsTab";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function renderTab() {
  return render(
    <ToastProvider>
      <RustionBastionsTab />
    </ToastProvider>,
  );
}

describe("RustionBastionsTab — Bootstrap Master wizard", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    // Default: every command resolves cheaply so the empty state mounts.
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "rustion_target_list":
          return Promise.resolve([]);
        case "rustion_target_health_all":
          return Promise.resolve([]);
        case "rustion_master_read":
          return Promise.resolve({
            pki_mount: "",
            pki_role: "",
            pki_role_pqc: "",
            issuer_ref: "",
            algorithm: "",
            default_ttl_secs: 0,
            rotate_grace_secs: 0,
            current_serial: "",
            current_not_after: "",
            updated_at: "",
            configured: false,
          });
        case "rustion_master_pubkey_export":
          return Promise.resolve({
            algorithm: "",
            ed25519_pem: "",
            mldsa65_pem: "",
            fingerprint: "",
            current_serial: "",
            current_not_after: "",
            issued: false,
          });
        case "rustion_deployment_id_read":
          return Promise.resolve("");
        // Wizard step commands — overridden inside the test.
        case "pki_list_mounts":
          return Promise.resolve([]);
        case "pki_enable_mount":
          return Promise.resolve(null);
        case "pki_list_issuers":
          return Promise.resolve({ issuers: [] });
        case "pki_generate_root":
          return Promise.resolve({});
        case "pki_write_role":
          return Promise.resolve(null);
        case "rustion_master_write":
          return Promise.resolve({});
        case "rustion_master_issue":
          return Promise.resolve({
            serial: "17:42:0a",
            not_after: "2027-05-21T14:02:33Z",
            algorithm: "hybrid-ed25519-mldsa65",
          });
        default:
          return Promise.resolve(null);
      }
    });
  });

  it("drives every bootstrap step in order on submit", async () => {
    const user = userEvent.setup();
    renderTab();

    // Empty-state panel reveals the "Bootstrap master" button. The
    // initial loaders are async so we wait for it to surface.
    const bootstrapBtn = await screen.findByRole("button", {
      name: "Bootstrap master",
    });
    await user.click(bootstrapBtn);

    // Modal opens. The defaults fill the form; we just click Bootstrap.
    expect(await screen.findByText("Bootstrap Rustion master")).toBeInTheDocument();

    // Within the modal, the submit button is also labeled "Bootstrap".
    // Disambiguate by picking the last match (the modal Bootstrap), not
    // the page-level "Bootstrap master" button.
    const buttons = screen.getAllByRole("button");
    const matches = buttons.filter((b) => b.textContent === "Bootstrap");
    const submitBtn = matches[matches.length - 1];
    expect(submitBtn).toBeDefined();
    await user.click(submitBtn!);

    // Wait for the final "issue" call.
    await waitFor(
      () => {
        expect(
          mockInvoke.mock.calls.some(([c]) => c === "rustion_master_issue"),
        ).toBe(true);
      },
      { timeout: 4000 },
    );

    // Build the bootstrap-only call sequence (initial mounts already
    // fired during page load — we filter to the wizard's commands).
    const wizardCmds = new Set([
      "pki_list_mounts",
      "pki_enable_mount",
      "pki_list_issuers",
      "pki_generate_root",
      "pki_write_role",
      "rustion_master_write",
      "rustion_master_issue",
    ]);
    const orderedCalls = mockInvoke.mock.calls
      .map(([cmd]) => cmd as string)
      .filter((c) => wizardCmds.has(c));

    // Expected ordered sequence — two pki_generate_root calls (Ed25519 +
    // ML-DSA-65 roots) and two pki_write_role calls (one per role).
    expect(orderedCalls).toEqual([
      "pki_list_mounts",
      "pki_enable_mount",
      "pki_list_issuers",
      "pki_generate_root",
      "pki_generate_root",
      "pki_write_role",
      "pki_write_role",
      "rustion_master_write",
      "rustion_master_issue",
    ]);

    // The two role writes carry the right names + key types.
    const roleWrites = mockInvoke.mock.calls.filter(
      ([c]) => c === "pki_write_role",
    );
    expect(roleWrites[0][1]).toMatchObject({
      mount: "pki",
      name: "rustion-master-ed25519",
      config: { key_type: "ed25519" },
    });
    expect(roleWrites[1][1]).toMatchObject({
      mount: "pki",
      name: "rustion-master-mldsa65",
      config: { key_type: "ml-dsa-65" },
    });

    // The master config write carries both role names.
    const cfgWrite = mockInvoke.mock.calls.find(
      ([c]) => c === "rustion_master_write",
    );
    expect(cfgWrite?.[1]).toMatchObject({
      input: {
        pki_mount: "pki",
        pki_role: "rustion-master-ed25519",
        pki_role_pqc: "rustion-master-mldsa65",
      },
    });
  });

  it("stops the sequence and leaves the modal open on a step failure", async () => {
    // Force the root step to fail; assert nothing downstream runs.
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "rustion_target_list") return Promise.resolve([]);
      if (cmd === "rustion_target_health_all") return Promise.resolve([]);
      if (cmd === "rustion_master_read")
        return Promise.resolve({
          pki_mount: "",
          pki_role: "",
          pki_role_pqc: "",
          issuer_ref: "",
          algorithm: "",
          default_ttl_secs: 0,
          rotate_grace_secs: 0,
          current_serial: "",
          current_not_after: "",
          updated_at: "",
          configured: false,
        });
      if (cmd === "rustion_master_pubkey_export")
        return Promise.resolve({
          algorithm: "",
          ed25519_pem: "",
          mldsa65_pem: "",
          fingerprint: "",
          current_serial: "",
          current_not_after: "",
          issued: false,
        });
      if (cmd === "rustion_deployment_id_read") return Promise.resolve("");
      if (cmd === "pki_list_mounts") return Promise.resolve([]);
      if (cmd === "pki_enable_mount") return Promise.resolve(null);
      if (cmd === "pki_list_issuers")
        return Promise.resolve({ issuers: [] });
      if (cmd === "pki_generate_root")
        return Promise.reject(new Error("simulated root failure"));
      return Promise.resolve(null);
    });

    const user = userEvent.setup();
    renderTab();

    await user.click(
      await screen.findByRole("button", { name: "Bootstrap master" }),
    );
    expect(await screen.findByText("Bootstrap Rustion master")).toBeInTheDocument();

    const buttons = screen.getAllByRole("button");
    const matches = buttons.filter((b) => b.textContent === "Bootstrap");
    const submitBtn = matches[matches.length - 1];
    await user.click(submitBtn!);

    // Wait for the root step's failure to surface.
    await waitFor(() => {
      expect(screen.getByText(/simulated root failure/)).toBeInTheDocument();
    });

    // Downstream steps must NOT have fired.
    const wizardCalls = mockInvoke.mock.calls
      .map(([c]) => c as string)
      .filter((c) =>
        ["pki_write_role", "rustion_master_write", "rustion_master_issue"].includes(c),
      );
    expect(wizardCalls).toEqual([]);

    // Modal is still open — the title remains in the DOM.
    expect(screen.getByText("Bootstrap Rustion master")).toBeInTheDocument();
  });
});
