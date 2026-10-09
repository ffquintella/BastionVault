import type { PluginManifest } from "./api";

const MAGIC = [0x42, 0x56, 0x50, 0x4c] as const; // BVPL
const LEGACY_HEADER_LEN = 12;

export interface ParsedPluginBundle {
  manifest: PluginManifest;
  binary: Uint8Array;
  surface: Uint8Array | null;
}

function checkedEnd(start: number, length: number, total: number, label: string) {
  const end = start + length;
  if (!Number.isSafeInteger(end) || end > total) {
    throw new Error(`bundle truncated: ${label} length exceeds file size`);
  }
  return end;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Parse and authenticate the content-addressed parts of a `.bvplugin`.
 * Returns `null` for a raw plugin binary. The host still performs the same
 * checks during registration; doing them here gives the operator an immediate
 * and deterministic refusal before any catalog write is attempted.
 */
export async function parsePluginBundle(
  bytes: Uint8Array,
): Promise<ParsedPluginBundle | null> {
  if (
    bytes.length < LEGACY_HEADER_LEN ||
    !MAGIC.every((byte, index) => bytes[index] === byte)
  ) {
    return null;
  }
  if (bytes[5] !== 0 || bytes[6] !== 0 || bytes[7] !== 0) {
    throw new Error("reserved bundle header bytes are non-zero");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = bytes[4];
  const manifestLength = view.getUint32(8, true);
  let manifestStart: number;
  let surface: Uint8Array | null = null;
  let binaryStart: number;
  let binaryEnd = bytes.length;

  if (version === 1) {
    manifestStart = LEGACY_HEADER_LEN;
    binaryStart = checkedEnd(
      manifestStart,
      manifestLength,
      bytes.length,
      "manifest",
    );
  } else if (version === 2) {
    manifestStart = LEGACY_HEADER_LEN;
    const manifestEnd = checkedEnd(
      manifestStart,
      manifestLength,
      bytes.length,
      "manifest",
    );
    const binaryLengthEnd = checkedEnd(manifestEnd, 4, bytes.length, "binary");
    const binaryLength = view.getUint32(manifestEnd, true);
    binaryStart = binaryLengthEnd;
    binaryEnd = checkedEnd(binaryStart, binaryLength, bytes.length, "binary");
    const surfaceLengthEnd = checkedEnd(
      binaryEnd,
      4,
      bytes.length,
      "surface",
    );
    const surfaceLength = view.getUint32(binaryEnd, true);
    const surfaceEnd = checkedEnd(
      surfaceLengthEnd,
      surfaceLength,
      bytes.length,
      "surface",
    );
    if (surfaceEnd !== bytes.length) {
      throw new Error("unsupported trailing sections in surface bundle");
    }
    surface = bytes.subarray(surfaceLengthEnd, surfaceEnd);
  } else {
    throw new Error(
      `unsupported bundle format version: ${version} (this build supports v1 and v2)`,
    );
  }

  const manifestBytes = bytes.subarray(manifestStart, manifestStart + manifestLength);
  const manifestText = new TextDecoder("utf-8", { fatal: true }).decode(
    manifestBytes,
  );
  const manifest = JSON.parse(manifestText) as PluginManifest;
  const binary = bytes.subarray(binaryStart, binaryEnd);

  const binaryHash = await sha256Hex(binary);
  if (manifest.sha256 !== binaryHash) {
    throw new Error(
      `manifest sha256 (${manifest.sha256?.slice(0, 16) ?? "missing"}…) does not match the embedded binary (${binaryHash.slice(0, 16)}…)`,
    );
  }
  if (manifest.size !== binary.length) {
    throw new Error(
      `manifest size (${manifest.size}) does not match the embedded binary (${binary.length})`,
    );
  }

  if (manifest.surface && !surface) {
    throw new Error("manifest declares a surface but this bundle does not embed it");
  }
  if (!manifest.surface && surface) {
    throw new Error("bundle embeds a surface that the manifest does not declare");
  }
  if (manifest.surface && surface) {
    const surfaceHash = await sha256Hex(surface);
    if (manifest.surface.sha256 !== surfaceHash) {
      throw new Error(
        `manifest surface sha256 (${manifest.surface.sha256.slice(0, 16)}…) does not match the embedded surface (${surfaceHash.slice(0, 16)}…)`,
      );
    }
    if (manifest.surface.size !== surface.length) {
      throw new Error(
        `manifest surface size (${manifest.surface.size}) does not match the embedded surface (${surface.length})`,
      );
    }
    let parsedSurface: unknown;
    try {
      parsedSurface = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(surface),
      );
    } catch (error) {
      throw new Error(`embedded surface is not valid JSON: ${(error as Error).message}`);
    }
    if (
      typeof parsedSurface !== "object" ||
      parsedSurface === null ||
      !("schema_version" in parsedSurface) ||
      parsedSurface.schema_version !== manifest.surface.schema_version
    ) {
      throw new Error(
        "embedded surface schema_version does not match the manifest reference",
      );
    }
  }

  return { manifest, binary, surface };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
