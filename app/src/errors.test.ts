import { describe, expect, it } from "vitest";
import { describeError, messageOf, toSessionError } from "./errors";
import type { ErrorKind } from "./ipc";

const windows = { host: "office-pc", protocol: "rdp" as const, ssh_tunnel: true, name: "Office" };
const mac = { host: "studio-mac", protocol: "vnc" as const, ssh_tunnel: true, name: "Studio" };

describe("describeError", () => {
  it("names the host when it cannot be reached and gives protocol-specific hints", () => {
    const pc = describeError({ kind: "unreachable", detail: "" }, windows);
    expect(pc.headline).toBe("Can't reach office-pc");
    expect(pc.hints.join(" ")).toContain("Remote Desktop");
    const tunnelled = describeError({ kind: "unreachable", detail: "" }, mac);
    expect(tunnelled.hints.join(" ")).toContain("Screen Sharing and Remote Login");
    const direct = describeError({ kind: "unreachable", detail: "" }, { ...mac, ssh_tunnel: false });
    expect(direct.hints.join(" ")).toContain("Screen Sharing");
    expect(direct.hints.join(" ")).not.toContain("Remote Login");
  });

  it("says Remote Login is off when the SSH tunnel cannot be opened, and offers both ways on", () => {
    const text = describeError({ kind: "tunnel_unavailable", detail: "os error 10061" }, mac);
    expect(text.headline).toBe("Remote Login is off on studio-mac");
    const hints = text.hints.join(" ");
    expect(hints).toContain("System Settings > General > Sharing > Remote Login");
    expect(hints).toContain("Reconnect");
    expect(hints).toContain("Connect without SSH");
    expect(hints).toContain("unencrypted");
  });

  it("explains a refused sign-in", () => {
    expect(describeError({ kind: "auth_failed", detail: "" }, windows).headline).toBe("Wrong username or password");
  });

  it("explains a changed identity", () => {
    const text = describeError({ kind: "security", detail: "" }, mac);
    expect(text.headline).toBe("The identity of studio-mac has changed");
  });

  it("has a headline and at least one hint for every kind", () => {
    const kinds: ErrorKind[] = [
      "unreachable",
      "tunnel_unavailable",
      "auth_failed",
      "unsupported",
      "security",
      "protocol",
      "disconnected",
      "other",
      "password_required",
    ];
    for (const kind of kinds) {
      for (const target of [windows, mac]) {
        const text = describeError({ kind, detail: "x" }, target);
        expect(text.headline.length).toBeGreaterThan(0);
        expect(text.hints.length).toBeGreaterThan(0);
      }
    }
  });

  it("falls back to the generic text for a kind it does not know", () => {
    const text = describeError({ kind: "brand_new" as ErrorKind, detail: "" }, windows);
    expect(text.headline).toBe("Something went wrong");
  });

  it("falls back to the name when there is no host", () => {
    expect(describeError({ kind: "unreachable", detail: "" }, { ...windows, host: "" }).headline).toBe("Can't reach Office");
  });
});

describe("toSessionError", () => {
  it("passes a SessionError through", () => {
    expect(toSessionError({ kind: "tunnel_unavailable", detail: "refused" })).toEqual({
      kind: "tunnel_unavailable",
      detail: "refused",
    });
    expect(toSessionError({ kind: "password_required", detail: "none saved" })).toEqual({
      kind: "password_required",
      detail: "none saved",
    });
  });

  it("wraps anything else as other", () => {
    expect(toSessionError("boom")).toEqual({ kind: "other", detail: "boom" });
    expect(toSessionError(new Error("bad"))).toEqual({ kind: "other", detail: "bad" });
    expect(toSessionError({ kind: "nonsense", detail: "d" }).kind).toBe("other");
    expect(toSessionError(undefined)).toEqual({ kind: "other", detail: "" });
    expect(toSessionError({ kind: "unreachable" })).toEqual({ kind: "unreachable", detail: "" });
  });

  it("messageOf gives readable text", () => {
    expect(messageOf("plain")).toBe("plain");
    expect(messageOf({ kind: "other", detail: "inner" })).toBe("inner");
    expect(messageOf(null)).toBe("Unknown error");
  });
});
