import { describe, expect, it } from "vitest";
import type { FoundHost } from "../ipc";
import { blankConnection } from "../state";
import {
  addableProtocols,
  allNames,
  estimateDuration,
  filterHosts,
  parseCidr,
  prefillConnection,
  progressText,
  savedMatches,
  sortHosts,
  suggestedName,
} from "./find-logic";

function host(ip: string, extra: Partial<FoundHost> = {}): FoundHost {
  return {
    ip,
    rdp: null,
    vnc: null,
    ssh: null,
    name: null,
    names: { rdp_certificate: null, mdns_name: null, mdns_host: null, netbios: null, dns: null },
    kind: "unknown",
    rdp_certificate_sha256: null,
    rfb_version: null,
    ssh_banner: null,
    model: null,
    ...extra,
  };
}

const windows = host("10.0.0.10", {
  rdp: 3389,
  kind: "windows",
  name: "DESKTOP-TEST01.corp.example",
  names: { rdp_certificate: "DESKTOP-TEST01.corp.example", mdns_name: null, mdns_host: null, netbios: "DESKTOP-TEST01", dns: null },
});
const mac = host("10.0.0.9", {
  vnc: 5900,
  ssh: 22,
  kind: "mac",
  name: "Studio Mac",
  names: { rdp_certificate: null, mdns_name: "Studio Mac", mdns_host: "Studio-Mac.local", netbios: null, dns: null },
  rfb_version: "003.889",
});
const nameless = host("10.0.0.200", { vnc: 5901 });

describe("parseCidr", () => {
  it("normalizes and counts", () => {
    const result = parseCidr(" 10.20.0.77/24 ");
    expect(result).toEqual({ ok: true, value: { cidr: "10.20.0.0/24", prefix: 24, hostCount: 254, isPrivate: true, isLarge: false } });
    expect(parseCidr("192.0.2.5")).toMatchObject({ ok: true, value: { cidr: "192.0.2.5/32", hostCount: 1, isPrivate: false } });
    expect(parseCidr("10.0.0.0/31")).toMatchObject({ ok: true, value: { hostCount: 2 } });
    expect(parseCidr("10.0.0.0/16")).toMatchObject({ ok: true, value: { hostCount: 65534, isLarge: true } });
    expect(parseCidr("172.31.0.0/16")).toMatchObject({ ok: true, value: { isPrivate: true } });
    expect(parseCidr("172.32.0.0/16")).toMatchObject({ ok: true, value: { isPrivate: false } });
    expect(parseCidr("100.64.1.0/24")).toMatchObject({ ok: true, value: { isPrivate: true } });
  });

  it("refuses what the backend refuses", () => {
    for (const bad of ["", "fd00::/64", "10.0.0/24", "10.0.0.256/24", "010.0.0.0/24", "10.0.0.0/33", "10.0.0.0/", "office"]) {
      expect(parseCidr(bad).ok, bad).toBe(false);
    }
    const tooBig = parseCidr("10.0.0.0/15");
    expect(tooBig.ok).toBe(false);
    if (!tooBig.ok) expect(tooBig.error).toContain("/16");
  });
});

describe("results", () => {
  it("sorts by address numerically and by name with nameless last", () => {
    const hosts = [windows, nameless, mac];
    expect(sortHosts(hosts, "ip", true).map((h) => h.ip)).toEqual(["10.0.0.9", "10.0.0.10", "10.0.0.200"]);
    expect(sortHosts(hosts, "ip", false).map((h) => h.ip)).toEqual(["10.0.0.200", "10.0.0.10", "10.0.0.9"]);
    expect(sortHosts(hosts, "name", true).map((h) => h.ip)).toEqual(["10.0.0.10", "10.0.0.9", "10.0.0.200"]);
    expect(sortHosts(hosts, "name", false).map((h) => h.ip)).toEqual(["10.0.0.9", "10.0.0.10", "10.0.0.200"]);
  });

  it("filters on address, any name and service", () => {
    const hosts = [windows, mac, nameless];
    expect(filterHosts(hosts, "")).toHaveLength(3);
    expect(filterHosts(hosts, "studio-mac.local")).toEqual([mac]);
    expect(filterHosts(hosts, "desktop")).toEqual([windows]);
    expect(filterHosts(hosts, "10.0.0.20")).toEqual([nameless]);
    expect(filterHosts(hosts, "remote desktop")).toEqual([windows]);
    expect(filterHosts(hosts, "SSH")).toEqual([mac]);
  });

  it("lists every name once", () => {
    expect(allNames(windows)).toEqual(["DESKTOP-TEST01.corp.example", "DESKTOP-TEST01"]);
    expect(allNames(nameless)).toEqual([]);
  });

  it("matches saved connections by address or name", () => {
    const byIp = { ...blankConnection("rdp"), name: "A", host: "10.0.0.10" };
    const byName = { ...blankConnection("vnc"), name: "B", host: "studio-mac.local." };
    const byShortName = { ...blankConnection("vnc"), name: "C", host: "Studio-Mac" };
    const other = { ...blankConnection("rdp"), name: "D", host: "10.0.0.100" };
    const all = [byIp, byName, byShortName, other];
    expect(savedMatches(windows, all)).toEqual([byIp]);
    expect(savedMatches(mac, all)).toEqual([byName, byShortName]);
    expect(savedMatches(nameless, all)).toEqual([]);
  });

  it("formats progress", () => {
    expect(progressText(1200, 65534, 1)).toBe("1,200 of 65,534 addresses checked, 1 computer found");
    expect(estimateDuration(254)).toBe("about 2 seconds");
    expect(estimateDuration(65534)).toBe("about 7 minutes");
  });
});

describe("prefill", () => {
  it("fills a Windows PC", () => {
    expect(addableProtocols(windows)).toEqual(["rdp"]);
    const c = prefillConnection(windows, "rdp");
    expect(c).toMatchObject({ id: "", protocol: "rdp", host: "10.0.0.10", port: 3389, name: "DESKTOP-TEST01", username: "", pinned_identity: null });
  });

  it("fills a Mac with the SSH tunnel on when Remote Login answered", () => {
    const c = prefillConnection(mac, "vnc");
    expect(c).toMatchObject({ protocol: "vnc", host: "10.0.0.9", port: 5900, name: "Studio Mac", ssh_tunnel: true, ssh_port: 22 });
    const noSsh = prefillConnection(nameless, "vnc");
    expect(noSsh).toMatchObject({ port: 5901, ssh_tunnel: false, name: "10.0.0.200" });
  });

  it("never pins anything from a scan", () => {
    const withCert = { ...windows, rdp_certificate_sha256: "ab".repeat(32) };
    expect(prefillConnection(withCert, "rdp").pinned_identity).toBeNull();
  });

  it("suggests short names", () => {
    expect(suggestedName(host("10.0.0.1", { name: "pc-1.example.internal", names: { ...windows.names, rdp_certificate: null, netbios: null, dns: "pc-1.example.internal" } }), "rdp")).toBe("pc-1");
    expect(suggestedName(host("10.0.0.2", { vnc: 5900, names: { ...mac.names, mdns_name: null } }), "vnc")).toBe("Studio-Mac");
  });
});
