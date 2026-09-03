// Chunked recording fetch — the size-independent replay path.
//
// The single-shot blob read put the whole artifact in one response and
// failed once it crossed the client's read limit (a 17.8 MB recording
// base64-expands past the 10 MB default). `fetchRecordingBytes` walks
// `blob/chunk/<n>` instead; these tests pin the loop's contract:
// allocate once from the first chunk, place every chunk at its own
// offset, and refuse to hand back a partial artifact.

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { fetchRecordingBytes } from "../lib/rustion";

/** Base64 of an arbitrary byte slice, without Buffer. */
function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** Serve `artifact` as `chunkSize`-sized chunks, the way the engine's
 *  `blob/chunk/<n>` route does. */
function serveChunks(artifact: Uint8Array, chunkSize: number) {
  const chunkCount = artifact.length === 0 ? 1 : Math.ceil(artifact.length / chunkSize);
  // No `expect` inside the fake: an assertion that throws from a mock
  // implementation is reported as a spurious extra call, which buries
  // the real failure. The command name is asserted from `mock.calls`.
  return (_cmd: string, args: { recordingId: string; chunkIndex: number }) => {
    const i = args.chunkIndex;
    if (i >= chunkCount) throw new Error(`chunk ${i} is past the end`);
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, artifact.length);
    return Promise.resolve({
      recordingId: args.recordingId,
      format: "rdp-rec",
      sha256: "deadbeef",
      sizeBytes: artifact.length,
      chunkIndex: i,
      chunkCount,
      chunkSize,
      offset: start,
      chunkLen: end - start,
      eof: i + 1 >= chunkCount,
      bytesB64: b64(artifact.subarray(start, end)),
    });
  };
}

describe("fetchRecordingBytes", () => {
  // Block body on purpose: `() => mockInvoke.mockReset()` returns the
  // mock, and Vitest treats a function returned from `beforeEach` as a
  // cleanup hook — it would call `invoke()` with no arguments after
  // every test, straight into the fake server below.
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("assembles an artifact that spans many chunks, byte for byte", async () => {
    const artifact = new Uint8Array(1000);
    for (let i = 0; i < artifact.length; i++) artifact[i] = i % 251;
    mockInvoke.mockImplementation(serveChunks(artifact, 128) as never);

    const got = await fetchRecordingBytes("rec_a");
    expect(mockInvoke.mock.calls[0]).toEqual([
      "rustion_recording_blob_chunk",
      { recordingId: "rec_a", chunkIndex: 0 },
    ]);
    expect(got.bytes.length).toBe(1000);
    expect(Array.from(got.bytes)).toEqual(Array.from(artifact));
    expect(got.format).toBe("rdp-rec");
    expect(got.sha256).toBe("deadbeef");
    // ceil(1000/128) = 8 chunk reads, no extra probe.
    expect(mockInvoke).toHaveBeenCalledTimes(8);
  });

  it("reports progress once per chunk, ending at the total", async () => {
    const artifact = new Uint8Array(300).fill(9);
    mockInvoke.mockImplementation(serveChunks(artifact, 100) as never);

    const seen: Array<[number, number]> = [];
    await fetchRecordingBytes("rec_b", {
      onProgress: (received, total) => seen.push([received, total]),
    });
    expect(seen).toEqual([
      [100, 300],
      [200, 300],
      [300, 300],
    ]);
  });

  it("handles an artifact that fits in one chunk", async () => {
    const artifact = new Uint8Array([1, 2, 3]);
    mockInvoke.mockImplementation(serveChunks(artifact, 4096) as never);
    const got = await fetchRecordingBytes("rec_c");
    expect(Array.from(got.bytes)).toEqual([1, 2, 3]);
    expect(mockInvoke).toHaveBeenCalledTimes(1);
  });

  it("handles an empty artifact as one empty chunk", async () => {
    mockInvoke.mockImplementation(serveChunks(new Uint8Array(0), 4096) as never);
    const got = await fetchRecordingBytes("rec_empty");
    expect(got.bytes.length).toBe(0);
  });

  it("throws rather than returning a short artifact", async () => {
    // A server that under-reports its chunk count: the loop would
    // otherwise hand the player a half-filled buffer, which surfaces
    // as an unplayable/corrupt recording with no stated cause.
    const artifact = new Uint8Array(300).fill(1);
    mockInvoke.mockImplementation(((
      _cmd: string,
      args: { recordingId: string; chunkIndex: number },
    ) => {
      const start = args.chunkIndex * 100;
      return Promise.resolve({
        recordingId: args.recordingId,
        format: "rdp-rec",
        sha256: "aa",
        sizeBytes: 300,
        chunkIndex: args.chunkIndex,
        chunkCount: 2, // lies: 300 bytes need 3
        chunkSize: 100,
        offset: start,
        chunkLen: 100,
        eof: args.chunkIndex >= 1,
        bytesB64: b64(artifact.subarray(start, start + 100)),
      });
    }) as never);

    await expect(fetchRecordingBytes("rec_short")).rejects.toThrow(
      /expected 300 bytes, assembled 200/,
    );
  });

  it("throws rather than writing a chunk past the reported size", async () => {
    mockInvoke.mockImplementation((() =>
      Promise.resolve({
        recordingId: "rec_over",
        format: "rdp-rec",
        sha256: "aa",
        sizeBytes: 10,
        chunkIndex: 0,
        chunkCount: 1,
        chunkSize: 100,
        offset: 5,
        chunkLen: 100,
        eof: true,
        bytesB64: b64(new Uint8Array(100).fill(2)),
      })) as never);

    await expect(fetchRecordingBytes("rec_over")).rejects.toThrow(
      /runs past the reported size/,
    );
  });

  it("falls back to the single-response read on a server with no chunk route", async () => {
    // Version skew: a newer GUI against a server that predates the
    // chunk route. Replay must keep working there, not die on a 500.
    const artifact = new Uint8Array([4, 5, 6, 7]);
    mockInvoke.mockImplementation(((cmd: string) => {
      if (cmd === "rustion_recording_blob_chunk") {
        return Promise.reject({
          message: "HTTP 500: Logical backend path not supported.",
        });
      }
      return Promise.resolve({
        recordingId: "rec_old",
        format: "asciicast",
        sha256: "cafe",
        bytesB64: b64(artifact),
        sizeBytes: artifact.length,
      });
    }) as never);

    const got = await fetchRecordingBytes("rec_old");
    expect(Array.from(got.bytes)).toEqual([4, 5, 6, 7]);
    expect(got.format).toBe("asciicast");
    expect(got.sha256).toBe("cafe");
    expect(mockInvoke.mock.calls.map((c) => c[0])).toEqual([
      "rustion_recording_blob_chunk",
      "rustion_recording_blob",
    ]);
  });

  it("does not fall back for an unrelated chunk-read failure", async () => {
    // Only a missing *route* justifies the older path. A 403, a 416 or
    // a bastion failure must surface as itself.
    mockInvoke.mockImplementation((() =>
      Promise.reject({ message: "HTTP 403: permission denied" })) as never);
    await expect(fetchRecordingBytes("rec_denied")).rejects.toMatchObject({
      message: "HTTP 403: permission denied",
    });
    expect(mockInvoke).toHaveBeenCalledTimes(1);
  });

  it("stops fetching when aborted between chunks", async () => {
    const artifact = new Uint8Array(1000).fill(3);
    mockInvoke.mockImplementation(serveChunks(artifact, 100) as never);
    const abort = new AbortController();
    abort.abort();
    await expect(
      fetchRecordingBytes("rec_abort", { signal: abort.signal }),
    ).rejects.toThrow();
    // Chunk 0 is already in flight when the signal is checked; what
    // matters is that the remaining nine are not requested.
    expect(mockInvoke).toHaveBeenCalledTimes(1);
  });
});
