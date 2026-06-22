/**
 * Client-side HCL ⇄ block-model tooling for the graphical policy builder.
 *
 * This module is the *non-authoritative* half of the hybrid evaluation
 * engine described in `features/policy-builder-validator.md`. It gives the
 * builder instant, offline feedback while typing:
 *
 *   - {@link parsePolicyHcl}  — tokenize policy HCL into a block model.
 *   - {@link serializePolicyModel} — render a block model back to HCL.
 *   - {@link lintPolicyModel} — capability / glob / TTL lint.
 *   - {@link previewCapability} — a lightweight allow/deny preview that
 *     mirrors the backend's exact > prefix > segment precedence.
 *
 * The authoritative verdict always comes from the backend dry-run
 * (`policyTest` in `api.ts`); the preview here is explicitly labelled
 * non-authoritative in the UI and must never gate a save on its own.
 *
 * The parser handles the subset of HCL that ACL policies use: a top-level
 * `name`, an optional `metadata { ... }` block, and `path "..." { ... }`
 * blocks. It is intentionally small and dependency-free — no Monaco /
 * CodeMirror, no HCL library.
 */

/** The ten ACL capabilities recognized by the backend `Capability` enum. */
export const CAPABILITIES = [
  "deny",
  "create",
  "read",
  "update",
  "delete",
  "list",
  "patch",
  "sudo",
  "connect",
  "root",
] as const;

export type Capability = (typeof CAPABILITIES)[number];

const CAPABILITY_SET = new Set<string>(CAPABILITIES);

/** One `path "..." { ... }` rule. */
export interface PolicyBlock {
  path: string;
  capabilities: string[];
  minWrappingTtl?: string;
  maxWrappingTtl?: string;
  requiredParameters?: string[];
  allowedParameters?: Record<string, string[]>;
  deniedParameters?: Record<string, string[]>;
  groups?: string[];
  scopes?: string[];
}

/** Parsed representation of a whole policy document. */
export interface PolicyModel {
  name?: string;
  metadata?: Record<string, string>;
  blocks: PolicyBlock[];
}

export interface ParseError {
  message: string;
  /** 1-based line number when known. */
  line?: number;
}

export interface ParseResult {
  ok: boolean;
  model: PolicyModel;
  errors: ParseError[];
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type TokKind =
  | "ident"
  | "string"
  | "number"
  | "bool"
  | "lbrace"
  | "rbrace"
  | "lbracket"
  | "rbracket"
  | "equals"
  | "comma"
  | "eof";

interface Token {
  kind: TokKind;
  value: string;
  line: number;
}

class Tokenizer {
  private i = 0;
  private line = 1;
  constructor(private readonly src: string) {}

  private peekChar(): string {
    return this.src[this.i] ?? "";
  }

  private advance(): string {
    const c = this.src[this.i++];
    if (c === "\n") this.line++;
    return c ?? "";
  }

  private skipTrivia(): void {
    for (;;) {
      const c = this.peekChar();
      if (c === " " || c === "\t" || c === "\r" || c === "\n") {
        this.advance();
        continue;
      }
      // Line comments: `#...` and `//...`
      if (c === "#" || (c === "/" && this.src[this.i + 1] === "/")) {
        while (this.i < this.src.length && this.peekChar() !== "\n") this.advance();
        continue;
      }
      // Block comments: `/* ... */`
      if (c === "/" && this.src[this.i + 1] === "*") {
        this.advance();
        this.advance();
        while (this.i < this.src.length && !(this.peekChar() === "*" && this.src[this.i + 1] === "/")) {
          this.advance();
        }
        this.advance();
        this.advance();
        continue;
      }
      return;
    }
  }

  next(): Token {
    this.skipTrivia();
    const line = this.line;
    if (this.i >= this.src.length) return { kind: "eof", value: "", line };

    const c = this.peekChar();
    switch (c) {
      case "{":
        this.advance();
        return { kind: "lbrace", value: c, line };
      case "}":
        this.advance();
        return { kind: "rbrace", value: c, line };
      case "[":
        this.advance();
        return { kind: "lbracket", value: c, line };
      case "]":
        this.advance();
        return { kind: "rbracket", value: c, line };
      case "=":
        this.advance();
        return { kind: "equals", value: c, line };
      case ",":
        this.advance();
        return { kind: "comma", value: c, line };
      case '"':
        return this.readString(line);
    }

    if (c >= "0" && c <= "9") return this.readNumber(line);

    // Bare identifier (attribute keys, `true`/`false`).
    if (/[A-Za-z_]/.test(c)) {
      let s = "";
      while (this.i < this.src.length && /[A-Za-z0-9_.-]/.test(this.peekChar())) s += this.advance();
      if (s === "true" || s === "false") return { kind: "bool", value: s, line };
      return { kind: "ident", value: s, line };
    }

    throw new HclSyntaxError(`unexpected character '${c}'`, line);
  }

  private readString(line: number): Token {
    this.advance(); // opening quote
    let s = "";
    for (;;) {
      if (this.i >= this.src.length) throw new HclSyntaxError("unterminated string", line);
      const c = this.advance();
      if (c === '"') break;
      if (c === "\\") {
        const e = this.advance();
        switch (e) {
          case "n":
            s += "\n";
            break;
          case "t":
            s += "\t";
            break;
          case '"':
            s += '"';
            break;
          case "\\":
            s += "\\";
            break;
          default:
            s += e;
        }
        continue;
      }
      s += c;
    }
    return { kind: "string", value: s, line };
  }

  private readNumber(line: number): Token {
    let s = "";
    while (this.i < this.src.length && /[0-9.]/.test(this.peekChar())) s += this.advance();
    return { kind: "number", value: s, line };
  }
}

class HclSyntaxError extends Error {
  constructor(
    message: string,
    public readonly line?: number,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser {
  private tok: Tokenizer;
  private lookahead: Token;
  constructor(src: string) {
    this.tok = new Tokenizer(src);
    this.lookahead = this.tok.next();
  }

  private peek(): Token {
    return this.lookahead;
  }

  private take(): Token {
    const t = this.lookahead;
    this.lookahead = this.tok.next();
    return t;
  }

  private expect(kind: TokKind): Token {
    const t = this.peek();
    if (t.kind !== kind) {
      throw new HclSyntaxError(`expected ${kind} but found '${t.value || t.kind}'`, t.line);
    }
    return this.take();
  }

  parse(): PolicyModel {
    const model: PolicyModel = { blocks: [] };
    for (;;) {
      const t = this.peek();
      if (t.kind === "eof") break;
      if (t.kind !== "ident") {
        throw new HclSyntaxError(`expected an attribute or block, found '${t.value || t.kind}'`, t.line);
      }
      // Block (`ident "label"? {`) vs attribute (`ident = value`).
      const ident = this.take();
      const nxt = this.peek();
      if (nxt.kind === "equals") {
        this.take();
        const value = this.parseValue();
        if (ident.value === "name" && typeof value === "string") model.name = value;
        // Other top-level scalar attributes are ignored (forward-compatible).
        continue;
      }
      if (ident.value === "path") {
        const label = this.expect("string").value;
        const body = this.parseBody();
        model.blocks.push(blockFromBody(label, body));
        continue;
      }
      if (ident.value === "metadata") {
        const body = this.parseBody();
        model.metadata = {};
        for (const [k, v] of Object.entries(body)) {
          model.metadata[k] = scalarToString(v);
        }
        continue;
      }
      // Unknown block: consume its body so parsing can continue.
      if (nxt.kind === "string") this.take();
      if (this.peek().kind === "lbrace") this.parseBody();
    }
    return model;
  }

  /** Parse a `{ key = value ... }` body into a plain object. */
  private parseBody(): Record<string, HclValue> {
    this.expect("lbrace");
    const obj: Record<string, HclValue> = {};
    for (;;) {
      const t = this.peek();
      if (t.kind === "rbrace") {
        this.take();
        break;
      }
      if (t.kind === "eof") throw new HclSyntaxError("unterminated block", t.line);
      // key (ident or string) = value
      const keyTok = this.take();
      if (keyTok.kind !== "ident" && keyTok.kind !== "string") {
        throw new HclSyntaxError(`expected attribute name, found '${keyTok.value || keyTok.kind}'`, keyTok.line);
      }
      this.expect("equals");
      obj[keyTok.value] = this.parseValue();
    }
    return obj;
  }

  private parseValue(): HclValue {
    const t = this.peek();
    switch (t.kind) {
      case "string":
        this.take();
        return t.value;
      case "number":
        this.take();
        return Number(t.value);
      case "bool":
        this.take();
        return t.value === "true";
      case "lbracket":
        return this.parseArray();
      case "lbrace":
        return this.parseBody();
      default:
        throw new HclSyntaxError(`expected a value, found '${t.value || t.kind}'`, t.line);
    }
  }

  private parseArray(): HclValue[] {
    this.expect("lbracket");
    const arr: HclValue[] = [];
    for (;;) {
      const t = this.peek();
      if (t.kind === "rbracket") {
        this.take();
        break;
      }
      arr.push(this.parseValue());
      if (this.peek().kind === "comma") this.take();
    }
    return arr;
  }
}

type HclScalar = string | number | boolean;
interface HclArray extends Array<HclValue> {}
interface HclObject {
  [key: string]: HclValue;
}
type HclValue = HclScalar | HclArray | HclObject;

function scalarToString(v: HclValue): string {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "";
}

function asStringArray(v: HclValue | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) return [];
  return v.map(scalarToString);
}

function asParamMap(v: HclValue | undefined): Record<string, string[]> | undefined {
  if (v === undefined || typeof v !== "object" || Array.isArray(v)) return undefined;
  const out: Record<string, string[]> = {};
  for (const [k, val] of Object.entries(v)) {
    out[k] = Array.isArray(val) ? val.map(scalarToString) : [];
  }
  return out;
}

function ttlToString(v: HclValue | undefined): string | undefined {
  if (v === undefined) return undefined;
  if (typeof v === "number") return String(v);
  return scalarToString(v);
}

function blockFromBody(path: string, body: Record<string, HclValue>): PolicyBlock {
  const block: PolicyBlock = {
    path,
    capabilities: asStringArray(body["capabilities"]) ?? [],
  };
  const minTtl = ttlToString(body["min_wrapping_ttl"]);
  const maxTtl = ttlToString(body["max_wrapping_ttl"]);
  if (minTtl !== undefined && minTtl !== "" && minTtl !== "0") block.minWrappingTtl = minTtl;
  if (maxTtl !== undefined && maxTtl !== "" && maxTtl !== "0") block.maxWrappingTtl = maxTtl;
  const req = asStringArray(body["required_parameters"]);
  if (req && req.length) block.requiredParameters = req;
  const allowed = asParamMap(body["allowed_parameters"]);
  if (allowed && Object.keys(allowed).length) block.allowedParameters = allowed;
  const denied = asParamMap(body["denied_parameters"]);
  if (denied && Object.keys(denied).length) block.deniedParameters = denied;
  const groups = asStringArray(body["groups"]);
  if (groups && groups.length) block.groups = groups;
  const scopes = asStringArray(body["scopes"]);
  if (scopes && scopes.length) block.scopes = scopes;
  return block;
}

/**
 * Parse policy HCL into a block model. Never throws — a syntax error is
 * returned as `{ ok: false, errors }` so the caller can render it inline.
 */
export function parsePolicyHcl(hcl: string): ParseResult {
  try {
    const model = new Parser(hcl).parse();
    // The backend rejects the `+*` wildcard combo; surface it here too so
    // the client lint blocks save before a round-trip to the server.
    for (const b of model.blocks) {
      if (b.path.includes("+*")) {
        return {
          ok: false,
          model,
          errors: [{ message: `path "${b.path}": invalid use of wildcards ('+*' is forbidden)` }],
        };
      }
    }
    return { ok: true, model, errors: [] };
  } catch (e) {
    if (e instanceof HclSyntaxError) {
      return { ok: false, model: { blocks: [] }, errors: [{ message: e.message, line: e.line }] };
    }
    return { ok: false, model: { blocks: [] }, errors: [{ message: String(e) }] };
  }
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

function quote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function serializeStringArray(values: string[]): string {
  return `[${values.map(quote).join(", ")}]`;
}

function serializeParamMap(indent: string, map: Record<string, string[]>): string {
  const inner = indent + "  ";
  const lines = Object.entries(map).map(([k, vals]) => `${inner}${quote(k)} = ${serializeStringArray(vals)}`);
  return `{\n${lines.join("\n")}\n${indent}}`;
}

/**
 * Render a block model back to canonical HCL. The output re-parses to an
 * equivalent model (round-trip stable); it is not byte-for-byte identical
 * to arbitrary input (comments and formatting are not preserved).
 */
export function serializePolicyModel(model: PolicyModel): string {
  const out: string[] = [];
  if (model.name) out.push(`name = ${quote(model.name)}`);
  if (model.metadata && Object.keys(model.metadata).length) {
    out.push("metadata {");
    for (const [k, v] of Object.entries(model.metadata)) out.push(`  ${k} = ${quote(v)}`);
    out.push("}");
  }
  for (const b of model.blocks) {
    const lines: string[] = [`path ${quote(b.path)} {`];
    lines.push(`  capabilities = ${serializeStringArray(b.capabilities)}`);
    if (b.minWrappingTtl) lines.push(`  min_wrapping_ttl = ${quote(b.minWrappingTtl)}`);
    if (b.maxWrappingTtl) lines.push(`  max_wrapping_ttl = ${quote(b.maxWrappingTtl)}`);
    if (b.requiredParameters?.length) {
      lines.push(`  required_parameters = ${serializeStringArray(b.requiredParameters)}`);
    }
    if (b.allowedParameters && Object.keys(b.allowedParameters).length) {
      lines.push(`  allowed_parameters = ${serializeParamMap("  ", b.allowedParameters)}`);
    }
    if (b.deniedParameters && Object.keys(b.deniedParameters).length) {
      lines.push(`  denied_parameters = ${serializeParamMap("  ", b.deniedParameters)}`);
    }
    if (b.groups?.length) lines.push(`  groups = ${serializeStringArray(b.groups)}`);
    if (b.scopes?.length) lines.push(`  scopes = ${serializeStringArray(b.scopes)}`);
    lines.push("}");
    out.push(lines.join("\n"));
  }
  return out.join("\n\n") + (out.length ? "\n" : "");
}

// ---------------------------------------------------------------------------
// Lint
// ---------------------------------------------------------------------------

export type LintSeverity = "error" | "warning";

export interface LintFinding {
  severity: LintSeverity;
  message: string;
  /** The offending rule's path, when the finding is rule-scoped. */
  path?: string;
}

const TTL_RE = /^\d+(\.\d+)?\s*(ns|us|µs|ms|s|m|h|d)?$/;

/**
 * Lint a parsed policy for the documented error and warning classes.
 * Errors should block save; warnings are advisory. Authoritative parse
 * errors come from {@link parsePolicyHcl} / the backend — this operates on
 * an already-parsed model.
 */
export function lintPolicyModel(model: PolicyModel): LintFinding[] {
  const findings: LintFinding[] = [];
  for (const b of model.blocks) {
    const caps = b.capabilities ?? [];

    if (b.path.includes("+*")) {
      findings.push({ severity: "error", message: `'+*' is a forbidden wildcard combination`, path: b.path });
    }

    for (const c of caps) {
      if (!CAPABILITY_SET.has(c)) {
        findings.push({ severity: "error", message: `unknown capability "${c}"`, path: b.path });
      }
    }

    if (caps.length === 0) {
      findings.push({
        severity: "warning",
        message: "rule has no capabilities — it grants nothing",
        path: b.path,
      });
    }

    const hasDeny = caps.includes("deny");
    if (hasDeny && caps.length > 1) {
      findings.push({
        severity: "warning",
        message: "deny overrides all other capabilities on this rule; the rest are ignored",
        path: b.path,
      });
    }

    if (!hasDeny && (b.path === "*" || b.path === "") && caps.length > 0) {
      findings.push({
        severity: "warning",
        message: "this rule grants access to every path — review carefully",
        path: b.path,
      });
    }

    for (const [label, ttl] of [
      ["min_wrapping_ttl", b.minWrappingTtl],
      ["max_wrapping_ttl", b.maxWrappingTtl],
    ] as const) {
      if (ttl && !TTL_RE.test(ttl.trim())) {
        findings.push({ severity: "error", message: `invalid ${label} format: "${ttl}"`, path: b.path });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Non-authoritative preview matcher
// ---------------------------------------------------------------------------

export type MatchKind = "exact" | "prefix" | "segment_wildcard" | "none";

export interface PreviewVerdict {
  allowed: boolean;
  matchedPath: string | null;
  matchKind: MatchKind;
  deniedByDeny: boolean;
  /** Always true — this verdict is a client-side preview, not authoritative. */
  preview: true;
}

interface ClassifiedRule {
  block: PolicyBlock;
  kind: MatchKind;
  /** path with a trailing `*` stripped (prefix rules). */
  base: string;
}

function classify(block: PolicyBlock): ClassifiedRule {
  const p = stripLeadingSlash(block.path);
  const hasSegment = p === "+" || p.includes("/+") || p.startsWith("+/");
  if (hasSegment) return { block, kind: "segment_wildcard", base: p };
  if (p.endsWith("*")) return { block, kind: "prefix", base: p.slice(0, -1) };
  return { block, kind: "exact", base: p };
}

function stripLeadingSlash(s: string): string {
  return s.startsWith("/") ? s.slice(1) : s;
}

function segmentMatch(rulePath: string, reqPath: string): boolean {
  const isPrefix = rulePath.endsWith("*");
  const rule = (isPrefix ? rulePath.slice(0, -1) : rulePath).split("/");
  const req = reqPath.split("/");
  if (!isPrefix && rule.length !== req.length) return false;
  if (isPrefix && req.length < rule.length) return false;
  for (let i = 0; i < rule.length; i++) {
    const rp = rule[i];
    if (rp === "+") continue;
    if (isPrefix && i === rule.length - 1) {
      if (!req[i].startsWith(rp)) return false;
    } else if (rp !== req[i]) {
      return false;
    }
  }
  return true;
}

/**
 * A lightweight, **non-authoritative** preview of whether the model grants
 * `capability` on `path`. Mirrors the backend's exact > prefix > segment
 * precedence so the builder can show an instant verdict while typing, but
 * the real answer always comes from the backend dry-run. Group- and
 * scope-gated rules are ignored here (they need request context the client
 * does not have).
 */
export function previewCapability(model: PolicyModel, path: string, capability: string): PreviewVerdict {
  const target = stripLeadingSlash(path);
  const rules = model.blocks.map(classify);

  const pick = (r: ClassifiedRule): boolean => {
    if (r.kind === "exact") return r.base === target || r.base === target.replace(/\/$/, "");
    if (r.kind === "prefix") return target.startsWith(r.base);
    return segmentMatch(r.block.path, target);
  };

  // Exact wins outright.
  const exact = rules.find((r) => r.kind === "exact" && pick(r));
  // Otherwise the longest-literal prefix/segment match wins (approximates
  // the backend's WcPathDescr ordering).
  let best: ClassifiedRule | undefined = exact;
  if (!best) {
    let bestLen = -1;
    for (const r of rules) {
      if (r.kind === "exact" || !pick(r)) continue;
      const literalLen = r.base.replace(/\+/g, "").length;
      if (literalLen > bestLen) {
        bestLen = literalLen;
        best = r;
      }
    }
  }

  if (!best) {
    return { allowed: false, matchedPath: null, matchKind: "none", deniedByDeny: false, preview: true };
  }

  const caps = best.block.capabilities ?? [];
  const deniedByDeny = caps.includes("deny");
  const isRoot = caps.includes("root");
  const allowed = !deniedByDeny && (isRoot || caps.includes(capability));
  return {
    allowed,
    matchedPath: best.block.path,
    matchKind: best.kind,
    deniedByDeny,
    preview: true,
  };
}
