import { describe, it, expect } from "vitest";

import {
  brokersThroughBastion,
  type RustionEffectivePolicy,
} from "../lib/rustion";

function verdict(
  over: Partial<RustionEffectivePolicy> = {},
): RustionEffectivePolicy {
  return {
    transport: "",
    transportSource: "",
    bastions: [],
    bastionGroup: "",
    bastionsSource: "",
    recording: "",
    recordingSource: "",
    lockedBy: [],
    lockViolation: null,
    ...over,
  };
}

// This predicate is what tells the GUI whether a session on a resource is
// resolved server-side (brokered through a bastion) or on the operator's
// machine. It must agree with `prefer_rustion` in
// gui/src-tauri/src/commands/connect.rs, which makes the actual routing call —
// if the two disagree, the GUI either offers a Connect the server refuses or
// refuses one the server would have brokered.
describe("brokersThroughBastion", () => {
  it("brokers on rustion-required, with or without a resolved bastion list", () => {
    expect(brokersThroughBastion(verdict({ transport: "rustion-required" }))).toBe(
      true,
    );
    expect(
      brokersThroughBastion(
        verdict({ transport: "rustion-required", bastions: ["rt_a"] }),
      ),
    ).toBe(true);
  });

  it("brokers on rustion-preferred only when a bastion actually resolved", () => {
    expect(
      brokersThroughBastion(verdict({ transport: "rustion-preferred" })),
    ).toBe(false);
    expect(
      brokersThroughBastion(
        verdict({ transport: "rustion-preferred", bastions: ["rt_a"] }),
      ),
    ).toBe(true);
  });

  it("does not broker on direct or an unset transport", () => {
    expect(brokersThroughBastion(verdict({ transport: "direct" }))).toBe(false);
    expect(brokersThroughBastion(verdict())).toBe(false);
    // A bastion list without a rustion transport is not a routing decision.
    expect(
      brokersThroughBastion(verdict({ transport: "direct", bastions: ["rt_a"] })),
    ).toBe(false);
  });

  it("treats an unresolved verdict as not brokered", () => {
    // null is "unknown" — loading, or the resolver refused. Claiming brokered
    // here would offer a connect-only caller a dial that resolves the
    // credential locally.
    expect(brokersThroughBastion(null)).toBe(false);
  });
});
