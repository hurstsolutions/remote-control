import { describe, expect, it } from "vitest";
import { formatFingerprint, identityCheckSteps, identityKindOf, MAC_SSH_KEY_COMMAND, RDP_CERT_COMMAND } from "./fingerprint";

describe("formatFingerprint", () => {
  it("shows a certificate hash as colon-separated upper-case pairs", () => {
    expect(formatFingerprint("tls_certificate", "0a1b" + "ff".repeat(30))).toBe(["0A", "1B", ...Array(30).fill("FF")].join(":"));
  });

  it("shows an SSH host key hash the way ssh-keygen -l does", () => {
    // ssh-keygen prints SHA256: + unpadded base64 of the raw digest.
    expect(formatFingerprint("ssh_host_key", "00".repeat(32))).toBe("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(formatFingerprint("ssh_host_key", "fb".repeat(32))).toBe(`SHA256:${btoa("û".repeat(32)).replace(/=+$/, "")}`);
    expect(formatFingerprint("ssh_host_key", "FB".repeat(32))).toBe(formatFingerprint("ssh_host_key", "fb".repeat(32)));
  });

  it("leaves anything that is not hex alone", () => {
    expect(formatFingerprint("tls_certificate", "not hex")).toBe("not hex");
    expect(formatFingerprint("ssh_host_key", "abc")).toBe("abc");
  });
});

describe("identity guidance", () => {
  it("knows which identity a connection pins", () => {
    expect(identityKindOf({ protocol: "rdp", ssh_tunnel: true })).toBe("tls_certificate");
    expect(identityKindOf({ protocol: "vnc", ssh_tunnel: true })).toBe("ssh_host_key");
    expect(identityKindOf({ protocol: "vnc", ssh_tunnel: false })).toBeNull();
  });

  it("gives a command that prints the same format", () => {
    expect(identityCheckSteps("tls_certificate").map((s) => s.command)).toContain(RDP_CERT_COMMAND);
    expect(RDP_CERT_COMMAND).toContain("SHA256");
    expect(RDP_CERT_COMMAND).toContain("RawData");
    expect(identityCheckSteps("ssh_host_key").map((s) => s.command)).toContain(MAC_SSH_KEY_COMMAND);
  });
});
