import { describe, expect, it } from "vitest";
import { DIRECT_MAC_SUMMARY, describeError, messageOf, passwordRequiredNote, toSessionError, vncSecurityProblem } from "./errors";
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
    expect(hints).toContain("still encrypted");
    expect(hints).toContain("verified sign-in");
    expect(hints).not.toContain("isn't encrypted");
  });

  it("explains each Mac encryption failure and points to the SSH tunnel", () => {
    const direct = { ...mac, ssh_tunnel: false };
    const notEncrypted = describeError(
      { kind: "security", detail: "the session could not be encrypted: the server announced RFB 3.8, not Apple Screen Sharing" },
      direct,
    );
    expect(notEncrypted.headline).toBe("Couldn't encrypt the session with studio-mac");
    expect(notEncrypted.hints.join(" ")).toContain("Remote Login");
    expect(notEncrypted.hints.join(" ")).toContain("Use SSH tunnel");

    const downgrade = describeError(
      {
        kind: "security",
        detail:
          "the session could not be encrypted: the Mac offers security types [1 (None)] ... Security types None (1) and VNC password (2) are refused while encryption is required: ...",
      },
      direct,
    );
    expect(downgrade.headline).toBe("studio-mac offered only an unencrypted connection");
    expect(downgrade.hints.join(" ")).toContain("tampering");

    const account = describeError(
      { kind: "security", detail: "a macOS username is set for this connection, but the server offers only [2]. Security types None (1) and VNC password (2) are refused when a username is set" },
      direct,
    );
    expect(account.headline).toBe("studio-mac offered only an unencrypted connection");

    const integrity = describeError(
      { kind: "security", detail: "the encrypted session failed during session: encrypted record 7 (64 bytes) failed its integrity check" },
      direct,
    );
    expect(integrity.headline).toBe("The encrypted connection to studio-mac was broken");
    expect(integrity.hints.join(" ")).toContain("tampering");
  });

  it("keeps the generic text for other security failures, and for Windows", () => {
    expect(vncSecurityProblem("SRP: the server sent invalid group parameters")).toBeNull();
    const pc = describeError({ kind: "security", detail: "the session could not be encrypted" }, windows);
    expect(pc.headline).toBe("Couldn't set up a secure connection to office-pc");
  });

  it("describes direct Mac connections as encrypted, with SSH still the best", () => {
    expect(DIRECT_MAC_SUMMARY).toContain("won't connect unencrypted");
    expect(DIRECT_MAC_SUMMARY).toContain("requires Apple's verified sign-in");
    expect(DIRECT_MAC_SUMMARY).toContain("allow older Macs");
    expect(DIRECT_MAC_SUMMARY).toContain("SSH (Remote Login)");
  });

  // rc_vnc::SRP_NOT_OFFERED and the text after it (crates/rc-vnc/src/proto.rs).
  const NO_SRP =
    "the Mac didn't offer SRP sign-in (Apple's verified sign-in); this can mean someone is interfering with the connection, or an older Mac. Apple's older sign-in (type 30) does not verify the Mac, and an impostor could learn the password through it, so it is refused. Use an SSH tunnel, or allow unverified sign-in for this connection if the network is trusted. Offered: [30 (Apple Remote Desktop)]";

  it("explains a Mac that didn't offer verified sign-in, with both ways out", () => {
    // The backend maps rc_vnc::is_srp_not_offered to its own kind; the detail is not parsed here.
    expect(vncSecurityProblem(NO_SRP)).toBeNull();
    expect(toSessionError({ kind: "no_verified_sign_in", detail: NO_SRP }).kind).toBe("no_verified_sign_in");
    const direct = { ...mac, ssh_tunnel: false };
    const text = describeError({ kind: "no_verified_sign_in", detail: NO_SRP }, direct);
    expect(text.headline).toBe("studio-mac didn't offer verified sign-in");
    const hints = text.hints.join(" ");
    expect(hints).toContain("interfering");
    expect(hints).toContain("older Mac");
    expect(hints).toContain("Use SSH tunnel");
    expect(hints).toContain("Allow older Macs without verified sign-in");
    expect(hints).toContain("capture your password");
    expect(hints).not.toContain("used verified sign-in before");
  });

  it("never suggests the older sign-in for a Mac that used verified sign-in before", () => {
    const seen = { ...mac, ssh_tunnel: false, srp_seen: true, allow_older_mac_sign_in: true };
    const hints = describeError({ kind: "no_verified_sign_in", detail: NO_SRP }, seen).hints.join(" ");
    expect(hints).toContain("This Mac used verified sign-in before");
    expect(hints).toContain("ignored");
    expect(hints).toContain("Use SSH tunnel");
    expect(hints).not.toContain("tick");
  });

  it("shows why a saved password was not used", () => {
    expect(passwordRequiredNote({ kind: "password_required", detail: "No password is saved for this connection." })).toBeNull();
    const removed = "The saved password was for a different address or account, so it was removed and not sent. Enter the password.";
    expect(passwordRequiredNote({ kind: "password_required", detail: removed })).toBe(removed);
    expect(passwordRequiredNote({ kind: "password_required", detail: "The saved password could not be read from the keychain (locked)." })).toContain("keychain");
  });

  it("explains a refused sign-in", () => {
    expect(describeError({ kind: "auth_failed", detail: "" }, windows).headline).toBe("Wrong username or password");
  });

  it("explains a changed identity", () => {
    const text = describeError({ kind: "identity_changed", detail: "" }, mac);
    expect(text.headline).toBe("The identity of studio-mac has changed");
  });

  it("does not call other TLS failures an identity change", () => {
    const text = describeError({ kind: "security", detail: "TLS handshake failed" }, windows);
    expect(text.headline).toBe("Couldn't set up a secure connection to office-pc");
    expect(text.hints.join(" ")).not.toContain("identity");
  });

  it("has a headline and at least one hint for every kind", () => {
    const kinds: ErrorKind[] = [
      "unreachable",
      "tunnel_unavailable",
      "auth_failed",
      "unsupported",
      "security",
      "identity_changed",
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

  it("keeps the fingerprints of an identity change, and only well-formed ones", () => {
    const identity = { identity_kind: "tls_certificate", expected_sha256: "aa", received_sha256: "bb" };
    expect(toSessionError({ kind: "identity_changed", detail: "d", identity })).toEqual({ kind: "identity_changed", detail: "d", identity });
    expect(toSessionError({ kind: "identity_changed", detail: "d", identity: { identity_kind: "x" } })).toEqual({
      kind: "identity_changed",
      detail: "d",
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
