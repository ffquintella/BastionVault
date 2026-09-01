import { describe, expect, it } from "vitest";
import { shortSpiffeId } from "../routes/AuditPage";

describe("shortSpiffeId", () => {
  it("drops the scheme and abbreviates the trailing selector", () => {
    expect(
      shortSpiffeId(
        "ferrogate-spiffe://ferrogate-hml/host/5376139b-0117-8e2d-8049-1ab7b32e7d9a",
      ),
    ).toBe("ferrogate-hml/host/5376139b…e7d9a");
  });

  it("collapses extra middle segments to an ellipsis", () => {
    expect(
      shortSpiffeId("spiffe://td.example/ns/prod/sa/agent-0000000000001111"),
    ).toBe("td.example/…/agent-00…01111");
  });

  it("leaves short ids intact", () => {
    expect(shortSpiffeId("spiffe://td/host/n1")).toBe("td/host/n1");
  });

  it("is a no-op on an empty or scheme-less value", () => {
    expect(shortSpiffeId("")).toBe("");
    expect(shortSpiffeId("plain-name")).toBe("plain-name");
  });
});
