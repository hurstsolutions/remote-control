import { describe, expect, it } from "vitest";
import type { FoundHost } from "../ipc";
import { blankConnection } from "../state";
import {
  addableProtocols,
  displayName,
  hostKind,
  isTailscaleResult,
  withoutTailscale,
  allNames,
  estimateDuration,
  filterHosts,
  hiddenToggleLabel,
  ipInCidr,
  isComputer,
  nameMatchWarning,
  nameSource,
  upsertHost,
  withoutSubnets,
  nameOnlyMatches,
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
    names: { rdp_certificate: null, mdns_name: null, mdns_host: null, netbios: null, smb: null, dns: null },
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
  names: { rdp_certificate: "DESKTOP-TEST01.corp.example", mdns_name: null, mdns_host: null, netbios: "DESKTOP-TEST01", smb: null, dns: null },
});
const mac = host("10.0.0.9", {
  vnc: 5900,
  ssh: 22,
  kind: "mac",
  name: "Studio Mac",
  names: { rdp_certificate: null, mdns_name: "Studio Mac", mdns_host: "Studio-Mac.local", netbios: null, smb: null, dns: null },
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

  it("counts a saved connection only by address; a name alone is a warning", () => {
    const byIp = { ...blankConnection("rdp"), name: "A", host: "10.0.0.10" };
    const byName = { ...blankConnection("vnc"), name: "B", host: "studio-mac.local." };
    const byShortName = { ...blankConnection("vnc"), name: "C", host: "Studio-Mac" };
    const other = { ...blankConnection("rdp"), name: "D", host: "10.0.0.100" };
    const all = [byIp, byName, byShortName, other];
    expect(savedMatches(windows, all)).toEqual([byIp]);
    expect(savedMatches(mac, all)).toEqual([]);
    expect(savedMatches(nameless, all)).toEqual([]);
    expect(nameOnlyMatches(mac, all).map((m) => m.connection)).toEqual([byName, byShortName]);
    expect(nameOnlyMatches(windows, all)).toEqual([]);
    expect(nameMatchWarning(nameOnlyMatches(mac, all)[0]!)).toBe('Name matches saved "B", but the address isn\'t confirmed');
  });

  it("warns when a machine announces the name of a saved one at another address", () => {
    const saved = { ...blankConnection("rdp"), name: "Payroll PC", host: "10.0.0.50" };
    const named = { ...blankConnection("rdp"), name: "Office", host: "desktop-test01" };
    const impostor = host("10.0.0.66", { rdp: 3389, name: "10.0.0.50", names: { ...windows.names, rdp_certificate: "10.0.0.50" } });
    expect(savedMatches(impostor, [saved])).toEqual([]);
    const [match] = nameOnlyMatches(impostor, [saved]);
    expect(match?.differentAddress).toBe(true);
    expect(nameMatchWarning(match!)).toBe('Name matches saved "Payroll PC" but at a different address');
    // A saved host name (not an address) matching an announced name: not confirmed either way.
    expect(nameOnlyMatches(windows, [named])[0]?.differentAddress).toBe(false);
  });

  it("formats progress", () => {
    expect(progressText(1200, 65534, 1)).toBe("1,200 of 65,534 addresses checked, 1 computer found");
    expect(estimateDuration(254)).toBe("about 2 seconds");
    expect(estimateDuration(65534)).toBe("about 7 minutes");
  });
});

describe("computers and other devices", () => {
  it("never hides a Mac with only Screen Sharing or a PC with only Remote Desktop", () => {
    const screenSharingOnly = host("10.0.0.31", { vnc: 5900, kind: "mac", rfb_version: "003.889" });
    const rdpOnly = host("10.0.0.32", { rdp: 3389, kind: "windows" });
    // Reported without lookups (past the description cap): kind unknown, but RDP is open.
    const bareRdp = host("10.0.0.33", { rdp: 3389 });
    // Screen Sharing whose greeting never arrived: could be a Mac.
    const unreadVnc = host("10.0.0.34", { vnc: 5900 });
    for (const h of [windows, mac, screenSharingOnly, rdpOnly, bareRdp, unreadVnc]) expect(isComputer(h), h.ip).toBe(true);
  });

  it("hides SSH-only devices and non-Apple VNC servers", () => {
    const accessPoint = host("10.0.0.2", { ssh: 22, ssh_banner: "SSH-2.0-dropbear_2022.83" });
    const linuxVnc = host("10.0.0.120", { vnc: 5900, rfb_version: "003.008" });
    expect(isComputer(accessPoint)).toBe(false);
    expect(isComputer(linuxVnc)).toBe(false);
    expect(isComputer(nameless)).toBe(true);
  });

  it("labels the toggle with the hidden count", () => {
    expect(hiddenToggleLabel(0)).toBe("Show all devices");
    expect(hiddenToggleLabel(3)).toBe("Show all devices (3 hidden)");
    expect(hiddenToggleLabel(1200)).toBe("Show all devices (1,200 hidden)");
  });
});

describe("name sources", () => {
  it("says where the best name came from", () => {
    expect(nameSource(windows)).toBe("Remote Desktop certificate");
    expect(nameSource(mac)).toBe("Bonjour");
    expect(nameSource(nameless)).toBeNull();
    const smbMac = host("10.0.0.31", {
      vnc: 5900,
      kind: "mac",
      name: "Reception-Mac.local",
      names: { ...mac.names, mdns_name: null, mdns_host: null, smb: "Reception-Mac.local", netbios: "RECEPTION-MAC" },
    });
    expect(nameSource(smbMac)).toBe("file sharing (SMB)");
    expect(allNames(smbMac)).toEqual(["Reception-Mac.local", "RECEPTION-MAC"]);
    expect(filterHosts([smbMac, windows], "reception")).toEqual([smbMac]);
    expect(suggestedName(smbMac, "vnc")).toBe("Reception-Mac");
    const dnsOnly = host("10.0.0.40", { rdp: 3389, name: "pc.example.internal", names: { ...windows.names, rdp_certificate: null, netbios: null, dns: "pc.example.internal" } });
    expect(nameSource(dnsOnly)).toBe("DNS");
  });
});

describe("rescanning one subnet", () => {
  it("knows which subnet an address is in", () => {
    expect(ipInCidr("10.0.0.9", "10.0.0.0/24")).toBe(true);
    expect(ipInCidr("10.0.1.9", "10.0.0.0/24")).toBe(false);
    expect(ipInCidr("10.0.1.9", "10.0.0.0/16")).toBe(true);
    expect(ipInCidr("10.0.0.9", "10.0.0.9/32")).toBe(true);
    expect(ipInCidr("10.0.0.9", "bad")).toBe(false);
    expect(ipInCidr("bad", "10.0.0.0/24")).toBe(false);
  });

  it("replaces only the rescanned subnet's results", () => {
    const other = host("10.0.1.5", { rdp: 3389, kind: "windows" });
    const kept = withoutSubnets([windows, mac, other, nameless], ["10.0.0.0/24"]);
    expect(kept).toEqual([other]);
    expect(withoutSubnets([windows, other], [])).toEqual([windows, other]);
    const renamed = { ...windows, name: "NEW-NAME" };
    expect(upsertHost([windows, other], renamed)).toEqual([renamed, other]);
    expect(upsertHost([other], windows)).toEqual([other, windows]);
  });
});

describe("prefill", () => {
  it("fills a Windows PC", () => {
    expect(addableProtocols(windows)).toEqual(["rdp"]);
    const c = prefillConnection(windows, "rdp");
    expect(c).toMatchObject({ id: "", protocol: "rdp", host: "10.0.0.10", port: 3389, name: "DESKTOP-TEST01", username: "", pinned_identity: null });
    expect(c.share_clipboard).toBe(false);
    expect(prefillConnection(mac, "vnc").share_clipboard).toBe(false);
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

  it("never copies a saved connection's name verbatim", () => {
    const saved = [{ ...blankConnection("rdp"), name: "desktop-test01", host: "10.0.0.50" }];
    expect(suggestedName(windows, "rdp", saved)).toBe("DESKTOP-TEST01 (10.0.0.10)");
    expect(prefillConnection(windows, "rdp", saved).name).toBe("DESKTOP-TEST01 (10.0.0.10)");
    const byHost = [{ ...blankConnection("vnc"), name: "Mac", host: "Studio Mac" }];
    expect(suggestedName(mac, "vnc", byHost)).toBe("Studio Mac (10.0.0.9)");
    expect(suggestedName(windows, "rdp", [])).toBe("DESKTOP-TEST01");
    const byFqdn = [{ ...blankConnection("rdp"), name: "Office", host: "desktop-test01.corp.example" }];
    expect(suggestedName(windows, "rdp", byFqdn)).toBe("DESKTOP-TEST01 (10.0.0.10)");
    expect(suggestedName(nameless, "vnc", [{ ...blankConnection("vnc"), name: "10.0.0.200", host: "10.0.0.200" }])).toBe("10.0.0.200");
  });

  it("suggests short names", () => {
    expect(suggestedName(host("10.0.0.1", { name: "pc-1.example.internal", names: { ...windows.names, rdp_certificate: null, netbios: null, dns: "pc-1.example.internal" } }), "rdp")).toBe("pc-1");
    expect(suggestedName(host("10.0.0.2", { vnc: 5900, names: { ...mac.names, mdns_name: null } }), "vnc")).toBe("Studio-Mac");
  });
});

describe("Tailscale results", () => {
  const tsPc = host("100.64.0.11", {
    rdp: 3389,
    tailscaleName: "gaming-pc",
    tailscaleDnsName: "gaming-pc.example.ts.net.",
    tailscaleOs: "windows",
  });
  const tsMac = host("100.64.0.12", {
    vnc: 5900,
    rfb_version: "003.008",
    tailscaleName: "studio‮mbp",
    tailscaleDnsName: "studio-mbp.example.ts.net.",
    tailscaleOs: "macOS",
  });
  const tsLinux = host("100.64.0.14", { ssh: 22, tailscaleName: "nas-01", tailscaleDnsName: "nas-01.example.ts.net.", tailscaleOs: "linux" });
  const named = host("100.64.0.15", { rdp: 3389, kind: "windows", name: "GAMING-2", names: { ...windows.names, rdp_certificate: "GAMING-2", netbios: null }, tailscaleName: "gaming-2", tailscaleOs: "windows" });

  it("falls back to the Tailscale name, cleaned, and says where it came from", () => {
    expect(displayName(tsPc)).toBe("gaming-pc");
    expect(nameSource(tsPc)).toBe("Tailscale");
    expect(displayName(tsMac)).toBe("studiombp");
    expect(displayName(named)).toBe("GAMING-2");
    expect(nameSource(named)).toBe("Remote Desktop certificate");
    expect(allNames(tsPc)).toEqual(["gaming-pc", "gaming-pc.example.ts.net"]);
    expect(nameSource(host("100.64.0.20", { tailscaleOs: "windows" }))).toBeNull();
  });

  it("classifies from the Tailscale OS when the probes couldn't", () => {
    expect(hostKind(tsPc)).toBe("windows");
    expect(hostKind(tsMac)).toBe("mac");
    expect(hostKind(tsLinux)).toBe("unknown");
    // A non-Apple VNC greeting would be hidden, but Tailscale says it is a Mac.
    expect(isComputer(tsMac)).toBe(true);
    expect(isComputer(tsLinux)).toBe(false);
    // The probes win when they know.
    expect(hostKind({ ...tsMac, kind: "windows" })).toBe("windows");
  });

  it("counts the IP or the MagicDNS name as Saved, never the Tailscale name", () => {
    const byDns = { ...blankConnection("rdp"), id: "1", name: "PC", host: "Gaming-PC.example.ts.net" };
    const byIp = { ...blankConnection("rdp"), id: "2", name: "PC ip", host: "100.64.0.11" };
    const byName = { ...blankConnection("rdp"), id: "3", name: "PC name", host: "gaming-pc" };
    expect(savedMatches(tsPc, [byDns, byIp, byName])).toEqual([byDns, byIp]);
    expect(nameOnlyMatches(tsPc, [byDns, byIp, byName]).map((m) => m.connection)).toEqual([byName]);
    expect(savedMatches(windows, [byDns])).toEqual([]);
  });

  it("replaces only the previous Tailscale results on a rescan", () => {
    const subnetHost = host("10.0.0.10", { rdp: 3389 });
    const unmarked = host("100.64.0.30", { rdp: 3389 });
    expect(isTailscaleResult(tsPc)).toBe(true);
    expect(isTailscaleResult(subnetHost)).toBe(false);
    let results = [subnetHost, tsPc, tsMac, unmarked];
    results = withoutTailscale(results, new Set(["100.64.0.30"]));
    expect(results.map((h) => h.ip)).toEqual(["10.0.0.10"]);
    results = upsertHost(results, tsLinux);
    expect(results.map((h) => h.ip)).toEqual(["10.0.0.10", "100.64.0.14"]);
    // A subnet rescan keeps Tailscale results outside the subnet.
    expect(withoutSubnets(results, ["10.0.0.0/24"]).map((h) => h.ip)).toEqual(["100.64.0.14"]);
  });

  it("filters, sorts and prefills by the Tailscale name", () => {
    expect(filterHosts([tsPc, tsMac, windows], "gaming").map((h) => h.ip)).toEqual(["100.64.0.11"]);
    expect(filterHosts([tsPc, tsMac], "example.ts.net")).toHaveLength(2);
    expect(sortHosts([tsMac, nameless, tsPc], "name", true).map((h) => h.ip)).toEqual(["100.64.0.11", "100.64.0.12", "10.0.0.200"]);
    const c = prefillConnection(tsPc, "rdp");
    expect(c).toMatchObject({ name: "gaming-pc", host: "100.64.0.11", share_clipboard: false });
  });
});
