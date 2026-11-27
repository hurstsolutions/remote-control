import { describe, expect, it } from "vitest";
import type { Connection, TailscaleDevice, TailscaleStatus } from "../ipc";
import { blankConnection } from "../state";
import {
  DOWNLOAD_URL,
  cleanDnsName,
  cleanIpv4,
  cleanText,
  deviceForConnection,
  deviceMatchesHost,
  displayTags,
  groupDevices,
  hostChoices,
  isHiddenChar,
  lastSeenText,
  osKind,
  osLabel,
  parseLastSeen,
  prefillFromDevice,
  presenceTooltip,
  relativeTime,
  savedForDevice,
  suggestedDeviceName,
  unavailableShort,
  unavailableText,
} from "./tailscale-logic";

function device(n: number, extra: Partial<TailscaleDevice> & Pick<TailscaleDevice, "name" | "os">): TailscaleDevice {
  return {
    id: `node-${n}`,
    dnsName: `${extra.name}.example.ts.net.`,
    ipv4: `100.64.0.${n}`,
    ipv6: `fd7a:115c:a1e0::${n}`,
    online: true,
    lastSeen: null,
    tags: [],
    isSelf: false,
    ...extra,
  };
}

function saved(host: string, name = "Saved", protocol: Connection["protocol"] = "rdp"): Connection {
  return { ...blankConnection(protocol), id: `c-${host}`, name, host };
}

const NOW = Date.UTC(2026, 10, 27, 12, 0, 0);
const self = device(10, { name: "this-laptop", os: "macOS", isSelf: true });
const pc = device(11, { name: "gaming-pc", os: "windows" });
const mbp = device(12, { name: "studio-mbp", os: "macOS" });
const air = device(13, { name: "travel-air", os: "macOS", online: false, lastSeen: new Date(NOW - 3 * 86_400_000).toISOString() });
const nas = device(14, { name: "nas-01", os: "linux", tags: ["tag:server"] });
const phone = device(15, { name: "sams-iphone", os: "iOS", online: false, lastSeen: "0001-01-01T00:00:00Z" });
const all = [self, pc, mbp, air, nas, phone];

function status(extra: Partial<TailscaleStatus>): TailscaleStatus {
  return { available: false, reason: null, detail: null, tailnet: null, magicDnsSuffix: null, selfName: null, devices: [], ...extra };
}

describe("cleanText", () => {
  it("drops bidi, hidden and control characters", () => {
    expect(cleanText("invoice‮txt.exe")).toBe("invoicetxt.exe");
    expect(cleanText("a​b⁦c⁩d﻿e­f")).toBe("abcdef");
    expect(cleanText("tab\there\nnew\u0085line\u007F")).toBe("tabherenewline");
    expect(cleanText("tag\u{E0041}\u{E0042}s")).toBe("tags");
    expect(cleanText("  café  ")).toBe("café");
    expect(cleanText(null)).toBe("");
    expect(cleanText("‮​")).toBe("");
  });

  it("mirrors the Rust hidden list's edges", () => {
    for (const c of [0x00ad, 0x200b, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069, 0xfeff, 0xe0001, 0xe007f, 0xfe0f, 0x061c]) {
      expect(isHiddenChar(c), c.toString(16)).toBe(true);
    }
    for (const c of ["a", " ", "é", "-", "."]) expect(isHiddenChar(c.codePointAt(0) ?? 0)).toBe(false);
  });

  it("cuts long names with an ellipsis, by characters", () => {
    const long = "x".repeat(100);
    const cut = cleanText(long, 20);
    expect(Array.from(cut)).toHaveLength(20);
    expect(cut.endsWith("…")).toBe(true);
    expect(cleanText("😀".repeat(30), 10)).toBe(`${"😀".repeat(9)}…`);
    expect(cleanText("short", 20)).toBe("short");
  });
});

describe("addresses", () => {
  it("accepts only plain MagicDNS names and dotted quads", () => {
    expect(cleanDnsName("Studio-MBP.example.ts.net.")).toBe("studio-mbp.example.ts.net");
    expect(cleanDnsName("bad name.example.ts.net")).toBe("");
    expect(cleanDnsName("evil‮.example.ts.net")).toBe("");
    expect(cleanDnsName("single")).toBe("");
    expect(cleanDnsName(null)).toBe("");
    expect(cleanIpv4("100.64.0.11")).toBe("100.64.0.11");
    expect(cleanIpv4("100.64.0.256")).toBe("");
    expect(cleanIpv4("fd7a:115c:a1e0::1")).toBe("");
  });

  it("keeps only names in the tailnet's MagicDNS domain or *.ts.net, never addresses", () => {
    // Shared-in devices: another tailnet's ts.net name.
    expect(cleanDnsName("friend-pc.other-tailnet.ts.net.")).toBe("friend-pc.other-tailnet.ts.net");
    expect(cleanDnsName("pc.example.com")).toBe("");
    expect(cleanDnsName("pc.example.com", "example.ts.net")).toBe("");
    expect(cleanDnsName("pc.example.ts.net.evil.com", "example.ts.net")).toBe("");
    expect(cleanDnsName("pc-ts.net")).toBe("");
    expect(cleanDnsName("ts.net")).toBe("");
    // A tailnet with its own (older) suffix, only when the status says so.
    expect(cleanDnsName("pc.example.beta.tailscale.net", "example.beta.tailscale.net")).toBe("pc.example.beta.tailscale.net");
    expect(cleanDnsName("pc.example.beta.tailscale.net")).toBe("");
    // Addresses are not names.
    expect(cleanDnsName("10.0.0.1")).toBe("");
    expect(cleanDnsName("100.64.0.1.", "example.ts.net")).toBe("");
    expect(cleanDnsName("pc.123", "123")).toBe("");
    expect(cleanDnsName("-pc.example.ts.net")).toBe("");
    expect(cleanDnsName("pc..example.ts.net")).toBe("");
  });

  it("keeps only IPv4 addresses in 100.64.0.0/10", () => {
    expect(cleanIpv4("100.64.0.0")).toBe("100.64.0.0");
    expect(cleanIpv4("100.127.255.255")).toBe("100.127.255.255");
    expect(cleanIpv4("100.128.0.1")).toBe("");
    expect(cleanIpv4("100.63.255.255")).toBe("");
    expect(cleanIpv4("10.0.0.1")).toBe("");
    expect(cleanIpv4("100.064.0.1")).toBe("");
  });

  it("ties a device to a saved host only by tailnet addresses", () => {
    const outside = device(20, { name: "outside", os: "windows", ipv4: "10.0.0.20", dnsName: "outside.example.com." });
    expect(deviceMatchesHost(outside, "10.0.0.20")).toBe(false);
    expect(deviceMatchesHost(outside, "outside.example.com")).toBe(false);
    expect(hostChoices(outside)).toEqual({ dnsName: "", ip: "" });
    const custom = device(21, { name: "pc", os: "windows", dnsName: "pc.corp.example." });
    expect(deviceMatchesHost(custom, "pc.corp.example")).toBe(false);
    expect(deviceMatchesHost(custom, "pc.corp.example", "corp.example")).toBe(true);
    expect(hostChoices(custom, "corp.example").dnsName).toBe("pc.corp.example");
  });
});

describe("OS", () => {
  it("maps Tailscale's OS labels", () => {
    expect(osKind("windows")).toBe("windows");
    expect(osKind("macOS")).toBe("mac");
    expect(osKind("iOS")).toBe("unknown");
    expect(osKind("linux")).toBe("unknown");
    expect(osKind("")).toBe("unknown");
    expect(osLabel("macOS")).toBe("macOS");
    expect(osLabel("windows")).toBe("Windows");
    expect(osLabel("android")).toBe("Android");
    expect(osLabel("plan9‮")).toBe("plan9");
    expect(osLabel("")).toBe("Other");
  });
});

describe("groupDevices", () => {
  it("shows only Windows and Macs by default, never this computer", () => {
    const groups = groupDevices(all, false);
    expect(groups.online.map((d) => d.name)).toEqual(["gaming-pc", "studio-mbp"]);
    expect(groups.offline.map((d) => d.name)).toEqual(["travel-air"]);
    expect(groups.hidden).toBe(2);
  });

  it("shows the rest when asked, still without this computer", () => {
    const groups = groupDevices(all, true);
    expect(groups.online.map((d) => d.name)).toEqual(["gaming-pc", "nas-01", "studio-mbp"]);
    expect(groups.offline.map((d) => d.name)).toEqual(["sams-iphone", "travel-air"]);
    expect(groups.hidden).toBe(0);
  });
});

describe("matching saved connections", () => {
  it("matches the IPv4 or the MagicDNS name, case-insensitively", () => {
    expect(deviceMatchesHost(pc, "100.64.0.11")).toBe(true);
    expect(deviceMatchesHost(pc, " Gaming-PC.example.ts.net. ")).toBe(true);
    expect(deviceMatchesHost(pc, "gaming-pc.example.ts.net")).toBe(true);
  });

  it("never matches on the name alone", () => {
    expect(deviceMatchesHost(pc, "gaming-pc")).toBe(false);
    expect(deviceMatchesHost(pc, "100.64.0.1")).toBe(false);
    expect(deviceMatchesHost(pc, "")).toBe(false);
    expect(deviceMatchesHost({ ...pc, ipv4: null, dnsName: null }, "")).toBe(false);
  });

  it("finds saved connections and the device of a connection", () => {
    const list = [saved("gaming-pc.example.ts.net", "PC"), saved("100.64.0.13", "Air"), saved("gaming-pc", "Name only"), saved("office-pc.local")];
    expect(savedForDevice(pc, list).map((c) => c.name)).toEqual(["PC"]);
    expect(savedForDevice(air, list).map((c) => c.name)).toEqual(["Air"]);
    expect(deviceForConnection(list[1] as Connection, all)?.name).toBe("travel-air");
    expect(deviceForConnection(list[2] as Connection, all)).toBeNull();
    expect(deviceForConnection(list[3] as Connection, all)).toBeNull();
  });
});

describe("times", () => {
  it("formats relative times", () => {
    expect(relativeTime(NOW - 20_000, NOW)).toBe("just now");
    expect(relativeTime(NOW - 60_000, NOW)).toBe("1 minute ago");
    expect(relativeTime(NOW - 5 * 60_000, NOW)).toBe("5 minutes ago");
    expect(relativeTime(NOW - 2 * 3_600_000, NOW)).toBe("2 hours ago");
    expect(relativeTime(NOW - 3 * 86_400_000, NOW)).toBe("3 days ago");
    expect(relativeTime(NOW - 90 * 86_400_000, NOW)).toBe("3 months ago");
    expect(relativeTime(NOW + 60_000, NOW)).toBe("just now");
  });

  it("treats Tailscale's year 1 and junk as unknown", () => {
    expect(parseLastSeen("0001-01-01T00:00:00Z")).toBeNull();
    expect(parseLastSeen("not a date")).toBeNull();
    expect(parseLastSeen(null)).toBeNull();
    expect(lastSeenText(air, NOW)).toBe("Last seen 3 days ago");
    expect(lastSeenText(phone, NOW)).toBeNull();
  });

  it("words the Home dot tooltip", () => {
    expect(presenceTooltip(pc, NOW)).toBe("Online on Tailscale");
    expect(presenceTooltip(air, NOW)).toBe("Offline on Tailscale, last seen 3 days ago");
    expect(presenceTooltip(phone, NOW)).toBe("Offline on Tailscale");
  });
});

describe("prefillFromDevice", () => {
  it("fills a Windows PC as Remote Desktop by MagicDNS name, clipboard off", () => {
    const c = prefillFromDevice(pc);
    expect(c).toMatchObject({ protocol: "rdp", host: "gaming-pc.example.ts.net", name: "gaming-pc", port: 3389, share_clipboard: false, username: "" });
  });

  it("fills a Mac as Screen Sharing", () => {
    expect(prefillFromDevice(mbp)).toMatchObject({ protocol: "vnc", host: "studio-mbp.example.ts.net", port: 5900, ssh_tunnel: true, share_clipboard: false });
  });

  it("falls back to the IP without a usable MagicDNS name", () => {
    expect(prefillFromDevice({ ...pc, dnsName: null }).host).toBe("100.64.0.11");
    expect(prefillFromDevice({ ...pc, dnsName: "bad name" }).host).toBe("100.64.0.11");
  });

  it("cleans the name and avoids look-alikes of saved connections", () => {
    expect(prefillFromDevice(device(16, { name: "invoice‮txt.exe-pc", os: "windows", dnsName: "invoice.example.ts.net." })).name).toBe("invoicetxt.exe-pc");
    expect(suggestedDeviceName(pc, [saved("10.0.0.5", "gaming-pc")])).toBe("gaming-pc (100.64.0.11)");
    expect(suggestedDeviceName(pc, [saved("gaming-pc.local", "Other")])).toBe("gaming-pc (100.64.0.11)");
    expect(suggestedDeviceName(pc, [saved("10.0.0.5", "Office")])).toBe("gaming-pc");
    expect(suggestedDeviceName({ ...pc, name: "‮" })).toBe("gaming-pc");
  });

  it("offers both hosts", () => {
    expect(hostChoices(pc)).toEqual({ dnsName: "gaming-pc.example.ts.net", ip: "100.64.0.11" });
    expect(hostChoices({ ...pc, ipv4: null })).toEqual({ dnsName: "gaming-pc.example.ts.net", ip: "" });
  });
});

describe("tags", () => {
  it("are cleaned and capped, for display only", () => {
    expect(displayTags({ ...nas, tags: ["tag:server‮", "", "tag:a", "tag:b", "tag:c", "tag:d", "tag:e"] })).toEqual(["tag:server", "tag:a", "tag:b", "tag:c", "tag:d"]);
  });
});

describe("unavailable", () => {
  it("has a message and a next step for each reason", () => {
    expect(unavailableText(status({ available: true }))).toBeNull();
    const notInstalled = unavailableText(status({ reason: "not_installed" }));
    expect(notInstalled?.next).toContain("Install Tailscale and sign in");
    expect(notInstalled?.link).toBe(DOWNLOAD_URL);
    expect(unavailableText(status({ reason: "not_running" }))?.next).toContain("Start Tailscale");
    expect(unavailableText(status({ reason: "logged_out" }))?.next).toContain("Sign in to Tailscale");
    expect(unavailableText(status({ reason: "error", detail: "socket refused‮" }))?.next).toBe("socket refused");
    expect(unavailableText(status({ reason: "error", detail: null }))?.next).toContain("error");
  });

  it("has a short reason for Find computers", () => {
    expect(unavailableShort(status({ reason: "not_installed" }))).toContain("install Tailscale");
    expect(unavailableShort(status({ reason: "not_running" }))).toContain("start Tailscale");
    expect(unavailableShort(status({ reason: "logged_out" }))).toContain("sign in");
    expect(unavailableShort(status({ reason: "error", detail: "boom" }))).toBe("boom");
  });
});
