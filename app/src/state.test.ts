import { describe, expect, it } from "vitest";
import { blankConnection, hostLabel, pinnedIdentityAfterEdit, protocolLabel } from "./state";
import { parsePort, validateEditor } from "./views/editor-logic";

describe("connections", () => {
  it("starts new connections with the documented defaults", () => {
    expect(blankConnection("rdp")).toMatchObject({ id: "", port: 3389, nla: true, ssh_tunnel: true, ssh_port: 22, pinned_identity: null });
    expect(blankConnection("vnc").port).toBe(5900);
  });

  it("labels protocols and hosts", () => {
    expect(protocolLabel("rdp")).toBe("Windows");
    expect(protocolLabel("vnc")).toBe("Mac");
    expect(hostLabel({ ...blankConnection("rdp"), host: "pc" })).toBe("pc");
    expect(hostLabel({ ...blankConnection("rdp"), host: "pc", port: 3390 })).toBe("pc:3390");
  });

  it("keeps the pinned identity only while the target is the same machine", () => {
    const before = { ...blankConnection("vnc"), id: "1", host: "Mac.local", pinned_identity: "abc" };
    expect(pinnedIdentityAfterEdit(before, { ...before, name: "Renamed", username: "other" })).toBe("abc");
    expect(pinnedIdentityAfterEdit(before, { ...before, host: "mac.local " })).toBe("abc");
    expect(pinnedIdentityAfterEdit(before, { ...before, host: "other.local" })).toBeNull();
    expect(pinnedIdentityAfterEdit(before, { ...before, port: 5901 })).toBeNull();
    expect(pinnedIdentityAfterEdit(before, { ...before, ssh_tunnel: false })).toBeNull();
    expect(pinnedIdentityAfterEdit(before, { ...before, ssh_port: 2222 })).toBeNull();
    expect(pinnedIdentityAfterEdit(before, { ...before, protocol: "rdp" })).toBeNull();
    expect(pinnedIdentityAfterEdit(null, before)).toBeNull();
  });
});

describe("editor validation", () => {
  const good = { name: "PC", protocol: "rdp" as const, host: "pc.local", port: "3389", username: "sam", sshTunnel: true, sshPort: "22" };

  it("accepts a complete form", () => {
    expect(validateEditor(good)).toEqual({});
  });

  it("requires name, host, port and username", () => {
    const errors = validateEditor({ ...good, name: " ", host: "", port: "", username: "" });
    expect(Object.keys(errors).sort()).toEqual(["host", "name", "port", "username"]);
  });

  it("rejects hosts with spaces or slashes and bad ports", () => {
    expect(validateEditor({ ...good, host: "my pc" }).host).toBeDefined();
    expect(validateEditor({ ...good, host: "rdp://pc" }).host).toBeDefined();
    expect(validateEditor({ ...good, port: "0" }).port).toBeDefined();
    expect(validateEditor({ ...good, port: "70000" }).port).toBeDefined();
    expect(validateEditor({ ...good, port: "33.89" }).port).toBeDefined();
  });

  it("checks the SSH port only for a Mac with the tunnel on", () => {
    expect(validateEditor({ ...good, sshPort: "" })).toEqual({});
    expect(validateEditor({ ...good, protocol: "vnc", sshPort: "" }).sshPort).toBeDefined();
    expect(validateEditor({ ...good, protocol: "vnc", sshTunnel: false, sshPort: "" })).toEqual({});
  });

  it("parses ports", () => {
    expect(parsePort(" 5900 ")).toBe(5900);
    expect(parsePort("65535")).toBe(65535);
    expect(parsePort("65536")).toBeNull();
    expect(parsePort("abc")).toBeNull();
  });
});
