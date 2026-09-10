/**
 * The request gate is what keeps the official client from tripping the
 * server's IP abuse guard. These tests pin the two properties that matter:
 * a burst is spread out rather than delivered at once, and a 429 parks the
 * queue instead of letting every queued call earn its own.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { invoke, gateForTests, gateStateForTests } from "../lib/invoke";

const mockInvoke = vi.mocked(tauriInvoke);

describe("request gate", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
    // Disabled by default under vitest; each test opts in explicitly.
    gateForTests({ enabled: false });
  });

  it("passes calls straight through when disabled", async () => {
    await Promise.all([invoke("a"), invoke("b"), invoke("c")]);
    expect(mockInvoke).toHaveBeenCalledTimes(3);
  });

  it("admits only the burst allowance immediately, then queues the rest", async () => {
    vi.useFakeTimers();
    try {
      gateForTests({ enabled: true, ratePerSec: 10, burst: 3 });
      // Ten simultaneous calls: the shape a `Promise.all(list.map(read))`
      // fan-out produces, and the shape that used to earn a 300 s ban.
      const all = Promise.all(Array.from({ length: 10 }, (_, i) => invoke(`cmd${i}`)));
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(gateStateForTests().queued).toBe(7);

      // 500 ms at 10/s refills 5 more tokens.
      await vi.advanceTimersByTimeAsync(500);
      expect(mockInvoke).toHaveBeenCalledTimes(8);

      await vi.advanceTimersByTimeAsync(1000);
      await all;
      expect(mockInvoke).toHaveBeenCalledTimes(10);
    } finally {
      vi.useRealTimers();
      gateForTests({ enabled: false });
    }
  });

  it("parks the queue for the server's Retry-After after a 429", async () => {
    vi.useFakeTimers();
    try {
      gateForTests({ enabled: true, ratePerSec: 10, burst: 10 });
      mockInvoke.mockRejectedValueOnce({
        message:
          "HTTP 429: request temporarily blocked by DoS protection: " +
          "request rate exceeded: >200 req/10s (retry after 12s)",
      });
      await expect(invoke("boom")).rejects.toBeTruthy();

      const pausedFor = gateStateForTests().pausedUntil - Date.now();
      expect(pausedFor).toBeGreaterThan(11_000);
      expect(pausedFor).toBeLessThanOrEqual(12_000);

      // A follow-up call waits out the pause instead of hitting the server.
      const next = invoke("after");
      await vi.advanceTimersByTimeAsync(1_000);
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(12_000);
      await next;
      expect(mockInvoke).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
      gateForTests({ enabled: false });
    }
  });

  it("caps the pause so a long ban cannot freeze the UI indefinitely", async () => {
    gateForTests({ enabled: true, ratePerSec: 10, burst: 10 });
    mockInvoke.mockRejectedValueOnce({
      message: "HTTP 429: blocked (retry after 300s)",
    });
    await expect(invoke("boom")).rejects.toBeTruthy();
    expect(gateStateForTests().pausedUntil - Date.now()).toBeLessThanOrEqual(30_000);
    gateForTests({ enabled: false });
  });

  it("leaves non-429 failures alone", async () => {
    gateForTests({ enabled: true, ratePerSec: 10, burst: 10 });
    mockInvoke.mockRejectedValueOnce({ message: "HTTP 403: permission denied" });
    await expect(invoke("nope")).rejects.toBeTruthy();
    expect(gateStateForTests().pausedUntil).toBe(0);
    gateForTests({ enabled: false });
  });
});
