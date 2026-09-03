// Minimal ambient declaration for the three `node:zlib` entry points
// the `.rdp-rec` fixtures use.
//
// Vitest runs on Node, but this project has no `@types/node` and does
// not need one: the fixtures want a zlib implementation that is *not*
// the `fflate` inflate under test, so that a passing test means real
// RFC 1950 interop rather than a round trip through one codec. Three
// signatures is cheaper than a types package.
declare module "node:zlib" {
  /// RFC 1950 zlib stream (deflate with a zlib wrapper).
  export function deflateSync(data: Uint8Array): Uint8Array;
  /// RFC 1952 gzip stream — must be rejected by `encoding = 1`.
  export function gzipSync(data: Uint8Array): Uint8Array;
  /// RFC 1951 raw deflate, no wrapper — must be rejected too.
  export function deflateRawSync(data: Uint8Array): Uint8Array;
}
