/**
 * Web Application Connect, Phase 4 (features/web-application-connect.md §8,
 * T96): TLS SPKI pin parsing mirrored from the host, save-time validation,
 * and the profile editor's pin list with its trust-on-first-use fingerprint
 * helper.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { WebProfileFields } from "../components/WebProfileFields";
import { MAX_TLS_PINS, canonicalTlsPins, normalizeTlsPin, validateTlsPins } from "../lib/webTlsPin";
import type { WebProfileSettings } from "../lib/types";

// The same vector as the host's `every_accepted_form_parses_to_the_same_pin`.
const BYTES = Array.from({ length: 32 }, (_, i) => (i * 37 + 5) & 0xff);
const HEX = BYTES.map((b) => b.toString(16).padStart(2, "0")).join("");
const COLONS = BYTES.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
const B64 = btoa(String.fromCharCode(...BYTES));
const CANONICAL = `sha256:${HEX}`;

describe("normalizeTlsPin — the host's accepted forms", () => {
  it("parses every accepted form to the canonical sha256:<hex>", () => {
    for (const form of [
      CANONICAL,
      `SHA256:${HEX.toUpperCase()}`,
      HEX,
      `  ${CANONICAL}\n`,
      `sha256:${COLONS}`,
      COLONS,
      `sha256/${B64}`,
      `sha256//${B64}`,
      `SHA256/${B64}`,
      B64,
    ]) {
      expect(normalizeTlsPin(form), form).toEqual({ pin: CANONICAL });
    }
  });

  it("refuses malformed pins", () => {
    const b64 = btoa(String.fromCharCode(...new Array(32).fill(7)));
    for (const bad of [
      "",
      "   ",
      "sha256:",
      "sha256/",
      "ab".repeat(31),
      "ab".repeat(33),
      `sha256:${HEX.slice(0, 62)}zz`,
      `sha1:${HEX}`,
      `sha256:${b64}`,
      `sha256/${b64.slice(0, 40)}`,
      `sha256/${btoa(String.fromCharCode(...new Array(20).fill(7)))}`,
      `sha256/${b64.replace("=", "")}`,
      "AB:CD",
      "ab:cd:".repeat(16),
      "not a pin",
    ]) {
      expect("error" in normalizeTlsPin(bad), JSON.stringify(bad)).toBe(true);
    }
    // Non-canonical trailing bits (the last character's two spare bits set):
    // the host's decoder refuses them, so do we.
    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const nonCanonical = B64.slice(0, 42) + ALPHABET[ALPHABET.indexOf(B64[42]) + 1] + "=";
    expect("error" in normalizeTlsPin(nonCanonical)).toBe(true);
    expect("error" in normalizeTlsPin(`sha256/${nonCanonical}`)).toBe(true);
  });

  it("validates a profile's list strictly and bounds it", () => {
    expect(validateTlsPins(undefined)).toBeNull();
    expect(validateTlsPins([])).toBeNull();
    expect(validateTlsPins([CANONICAL, `sha256/${B64}`])).toBeNull();
    expect(validateTlsPins("sha256:abc")).toMatch(/must be a list/);
    expect(validateTlsPins([CANONICAL, 5])).toMatch(/must be text/);
    expect(validateTlsPins([CANONICAL, "nope"])).toMatch(/not a SHA-256 public-key pin/);
    const many = Array.from({ length: MAX_TLS_PINS + 1 }, (_, i) => `sha256:${i.toString(16).padStart(64, "0")}`);
    expect(validateTlsPins(many)).toMatch(/At most 16/);
    expect(validateTlsPins(many.slice(0, MAX_TLS_PINS))).toBeNull();
    expect(canonicalTlsPins([CANONICAL, `sha256/${B64}`, "junk"])).toEqual([CANONICAL]);
  });
});

const START = "https://fw01.example.com/login";
const LEAF_PIN = `sha256:${"1a".repeat(32)}`;
const CA_PIN = `sha256:${"2b".repeat(32)}`;
const FINGERPRINT = {
  origin: "https://fw01.example.com",
  chain: [
    {
      depth: 0,
      pin: LEAF_PIN,
      pin_base64: "GhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGho=",
      subject: "CN=FortiGate",
      issuer: "CN=Appliance CA",
      not_before: 1_700_000_000,
      not_after: 1_800_000_000,
      self_issued: false,
      ca: false,
    },
    {
      depth: 1,
      pin: CA_PIN,
      pin_base64: "KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKys=",
      subject: "CN=Appliance CA",
      issuer: "CN=Appliance CA",
      not_before: 1_600_000_000,
      not_after: 2_000_000_000,
      self_issued: true,
      ca: true,
    },
  ],
};

function Harness({ initial, onWeb }: { initial?: Partial<WebProfileSettings>; onWeb?: (w: WebProfileSettings) => void }) {
  const [web, setWeb] = useState<WebProfileSettings>({
    start_url: START,
    allowed_origins: [],
    login_mode: "open",
    ...initial,
  });
  return (
    <MemoryRouter>
      <WebProfileFields
        web={web}
        onChange={(w) => {
          setWeb(w);
          onWeb?.(w);
        }}
      />
    </MemoryRouter>
  );
}

beforeEach(() => {
  mockInvoke.mockReset();
});

function lastWeb(fn: ReturnType<typeof vi.fn>): WebProfileSettings {
  const calls = fn.mock.calls;
  return calls[calls.length - 1][0] as WebProfileSettings;
}

describe("profile editor — TLS certificate pins", () => {
  it("edits the pin list and shows an unreadable pin as an error", async () => {
    const user = userEvent.setup();
    const onWeb = vi.fn();
    render(<Harness onWeb={onWeb} />);
    const box = screen.getByLabelText("TLS certificate pins (one per line)");
    await user.type(box, "nope");
    expect(screen.getByText(/not a SHA-256 public-key pin/)).toBeInTheDocument();
    await user.clear(box);
    expect(lastWeb(onWeb).tls_pin_sha256).toBeUndefined();
    await user.type(box, CANONICAL);
    expect(lastWeb(onWeb).tls_pin_sha256).toEqual([CANONICAL]);
    expect(screen.queryByText(/not a SHA-256 public-key pin/)).toBeNull();
    // Says what a pin does and does not do.
    expect(screen.getByText(/There is no .accept any certificate. option/)).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("only fetches a fingerprint for an https start URL", () => {
    render(<Harness initial={{ start_url: "http://fw01.example.com/", allow_insecure_http: true }} />);
    expect(screen.getByRole("button", { name: /Fetch certificate fingerprint \(trust on first use\)/ })).toBeDisabled();
    expect(screen.getByText("Needs an https start URL.")).toBeInTheDocument();
  });

  it("fetches the presented chain, labels it trust-on-first-use and pins only after confirmation", async () => {
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "web_tls_fingerprint" ? Promise.resolve(FINGERPRINT) : Promise.reject(new Error(`unexpected ${cmd}`)),
    );
    const user = userEvent.setup();
    const onWeb = vi.fn();
    render(<Harness onWeb={onWeb} />);
    await user.click(screen.getByRole("button", { name: /Fetch certificate fingerprint \(trust on first use\)/ }));

    const region = await screen.findByRole("region", { name: "Presented certificates" });
    // Only the URL goes to the host — nothing credential-shaped.
    expect(mockInvoke).toHaveBeenCalledWith("web_tls_fingerprint", { request: { url: START } });
    expect(region).toHaveTextContent(/Trust on first use/);
    expect(region).toHaveTextContent(/Anything on the network path could have answered instead/);
    expect(within(region).getByTestId("presented-pin-0")).toHaveTextContent(LEAF_PIN);
    expect(within(region).getByTestId("presented-pin-1")).toHaveTextContent(CA_PIN);
    expect(region).toHaveTextContent("Issuing CA (chain position 1)");
    expect(region).toHaveTextContent(/survives certificate renewal/);

    const pinLeaf = within(region).getByRole("button", { name: "Pin this certificate's key" });
    const pinCa = within(region).getByRole("button", { name: "Pin this CA's key" });
    expect(pinLeaf).toBeDisabled();
    expect(pinCa).toBeDisabled();
    await user.click(within(region).getByRole("checkbox"));
    expect(pinLeaf).toBeEnabled();
    await user.click(pinLeaf);
    expect(lastWeb(onWeb).tls_pin_sha256).toEqual([LEAF_PIN]);
    expect(within(region).getByRole("button", { name: "Pinned" })).toBeDisabled();
    expect(screen.getByLabelText("TLS certificate pins (one per line)")).toHaveValue(LEAF_PIN);

    await user.click(within(region).getByRole("button", { name: "Pin this CA's key" }));
    expect(lastWeb(onWeb).tls_pin_sha256).toEqual([LEAF_PIN, CA_PIN]);
  });

  it("asks for confirmation again after a new fetch, and shows a pin already in the list as pinned", async () => {
    mockInvoke.mockResolvedValue(FINGERPRINT);
    const user = userEvent.setup();
    render(<Harness initial={{ tls_pin_sha256: [`sha256/${btoa(String.fromCharCode(...new Array(32).fill(0x1a)))}`] }} />);
    const fetchButton = screen.getByRole("button", { name: /Fetch certificate fingerprint/ });
    await user.click(fetchButton);
    let region = await screen.findByRole("region", { name: "Presented certificates" });
    // The base64 form of the leaf pin is already in the list.
    expect(within(region).getByRole("button", { name: "Pinned" })).toBeDisabled();
    await user.click(within(region).getByRole("checkbox"));
    expect(within(region).getByRole("checkbox")).toBeChecked();
    await user.click(fetchButton);
    region = await screen.findByRole("region", { name: "Presented certificates" });
    expect(within(region).getByRole("checkbox")).not.toBeChecked();
  });

  it("shows the host's error when the probe fails", async () => {
    mockInvoke.mockRejectedValue("TLS handshake with fw01.example.com:443 failed: no cipher suites in common");
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: /Fetch certificate fingerprint/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/no cipher suites in common/);
    expect(screen.queryByRole("region", { name: "Presented certificates" })).toBeNull();
  });
});
