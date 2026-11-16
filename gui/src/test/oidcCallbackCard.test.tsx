import { describe, expect, it } from "vitest";
import { parsePorts } from "../components/OidcCallbackCard";

describe("parsePorts", () => {
  it("accepts 1 to 3 distinct unprivileged ports", () => {
    expect(parsePorts("8473")).toEqual([8473]);
    expect(parsePorts("8473, 8474 8475")).toEqual([8473, 8474, 8475]);
  });
  it("rejects empty, too many, non-numeric, privileged and duplicate", () => {
    expect(() => parsePorts("")).toThrow();
    expect(() => parsePorts("1025,1026,1027,1028")).toThrow(/At most/);
    expect(() => parsePorts("abc")).toThrow(/not a port/);
    expect(() => parsePorts("443")).toThrow(/1024/);
    expect(() => parsePorts("70000")).toThrow(/1024/);
    expect(() => parsePorts("8473,8473")).toThrow(/twice/);
  });
});
