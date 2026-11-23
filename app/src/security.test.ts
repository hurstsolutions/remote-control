import { describe, expect, it } from "vitest";
import { bestLayer, lockState, type SecurityLayer } from "./security";

const layer = (encrypted: boolean, server_verified: boolean, method: string): SecurityLayer => ({ encrypted, server_verified, method });

describe("lockState", () => {
  it("shows nothing before the backend reports any layer", () => {
    expect(lockState([])).toBeNull();
  });

  it("closed lock for an encrypted, verified session", () => {
    const lock = lockState([layer(true, true, "Apple Screen Sharing encryption, SRP sign-in")]);
    expect(lock?.level).toBe("verified");
    expect(lock?.label).toBe("Encrypted");
    expect(lock?.paragraphs.join(" ")).toContain("SRP");
  });

  it("caution for Apple's unverified sign-in, with the risk and the fix in plain words", () => {
    const lock = lockState([layer(true, false, "Apple Screen Sharing encryption")]);
    expect(lock?.level).toBe("unverified");
    expect(lock?.label).toBe("Encrypted");
    expect(lock?.tooltip).toContain("not verified");
    const text = lock?.paragraphs.join(" ") ?? "";
    expect(text).toContain("impersonate");
    expect(text).toContain("capture your password");
    expect(text).toContain("Remote Login");
  });

  it("treats a first-use pin as unverified but not as an impersonation risk", () => {
    for (const method of ["SSH tunnel", "TLS + NLA", "TLS"]) {
      const lock = lockState([layer(true, false, method)]);
      expect(lock?.level).toBe("unverified");
      expect(lock?.headline).toBe("Encrypted, first connection");
      expect(lock?.paragraphs.join(" ")).not.toContain("impersonate");
    }
    expect(lockState([layer(true, true, "TLS + NLA")])?.level).toBe("verified");
  });

  it("open lock when nothing encrypts the session", () => {
    const lock = lockState([layer(false, false, "VNC, unencrypted")]);
    expect(lock?.level).toBe("none");
    expect(lock?.label).toBe("Not encrypted");
  });

  it("uses the best layer: the SSH tunnel protects VNC inside it", () => {
    const tunnel = layer(true, true, "SSH tunnel");
    const vnc = layer(false, false, "VNC, unencrypted");
    expect(bestLayer([tunnel, vnc])).toBe(tunnel);
    expect(bestLayer([vnc, tunnel])).toBe(tunnel);
    expect(lockState([tunnel, vnc])?.method).toBe("SSH tunnel");
    expect(lockState([layer(true, false, "SSH tunnel"), vnc])?.level).toBe("unverified");
  });
});
