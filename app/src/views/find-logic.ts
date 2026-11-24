// Logic for "Find computers". Pure: no DOM. The backend (crates/rc-discover) has the final say
// on subnets; this mirrors its rules for instant feedback.
import type { Connection, FoundHost, Protocol } from "../ipc";
import { DEFAULT_SSH_PORT, blankConnection } from "../state";

export const MIN_PREFIX = 16;
export const WARN_PREFIX = 22;
export const MAX_SCAN_ADDRESSES = 65536;
/** The backend's rate cap (probes per second) and probes per address, for time estimates. */
const PROBES_PER_SECOND = 500;
const PROBES_PER_ADDRESS = 3;

export interface ParsedCidr {
  /** Normalized, e.g. "10.0.0.0/24". */
  cidr: string;
  prefix: number;
  /** Addresses that will be probed (network and broadcast skipped up to /30). */
  hostCount: number;
  isPrivate: boolean;
  /** More than 1,024 addresses. */
  isLarge: boolean;
}

export type CidrResult = { ok: true; value: ParsedCidr } | { ok: false; error: string };

function parseIpv4(text: string): number | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

function formatIpv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

const PRIVATE: Array<[number, number]> = [
  [0x0a000000, 8],
  [0xac100000, 12],
  [0xc0a80000, 16],
  [0x64400000, 10],
  [0xa9fe0000, 16],
  [0x7f000000, 8],
];

export function parseCidr(input: string): CidrResult {
  const text = input.trim();
  if (text === "") return { ok: false, error: "Enter a subnet such as 10.0.0.0/24." };
  if (text.includes(":")) return { ok: false, error: "IPv6 subnets are not supported yet. Enter an IPv4 subnet such as 10.0.0.0/24." };
  const slash = text.indexOf("/");
  const addressText = (slash < 0 ? text : text.slice(0, slash)).trim();
  let prefix = 32;
  if (slash >= 0) {
    const prefixText = text.slice(slash + 1).trim();
    if (!/^\d{1,2}$/.test(prefixText) || Number(prefixText) > 32) {
      return { ok: false, error: "The prefix length after / must be a number from 0 to 32." };
    }
    prefix = Number(prefixText);
  }
  const address = parseIpv4(addressText);
  if (address === null) {
    return { ok: false, error: "Enter the subnet as an IPv4 address and prefix length, such as 10.0.0.0/24." };
  }
  if (prefix < MIN_PREFIX) {
    return {
      ok: false,
      error: `A /${prefix} is too large to scan: the limit is /${MIN_PREFIX} (65,536 addresses). Split it into smaller subnets.`,
    };
  }
  const network = (address & maskOf(prefix)) >>> 0;
  const size = 2 ** (32 - prefix);
  const isPrivate = PRIVATE.some(([net, len]) => len <= prefix && ((network & maskOf(len)) >>> 0) === net);
  return {
    ok: true,
    value: {
      cidr: `${formatIpv4(network)}/${prefix}`,
      prefix,
      hostCount: prefix <= 30 ? size - 2 : size,
      isPrivate,
      isLarge: prefix < WARN_PREFIX,
    },
  };
}

/** "about 2 minutes" for a scan of `addresses`, at the backend's rate cap. */
export function estimateDuration(addresses: number): string {
  const seconds = Math.ceil((addresses * PROBES_PER_ADDRESS) / PROBES_PER_SECOND);
  if (seconds < 60) return `about ${Math.max(seconds, 1)} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.round(seconds / 60);
  return `about ${minutes} minute${minutes === 1 ? "" : "s"}`;
}

export function ipSortKey(ip: string): number {
  return parseIpv4(ip) ?? Number.MAX_SAFE_INTEGER;
}

export type SortKey = "ip" | "name";

export function sortHosts(hosts: FoundHost[], key: SortKey, ascending: boolean): FoundHost[] {
  const sign = ascending ? 1 : -1;
  return [...hosts].sort((a, b) => {
    if (key === "name") {
      // Machines without a name go last either way.
      if (a.name === null || b.name === null) {
        if (a.name !== b.name) return a.name === null ? 1 : -1;
      } else {
        const byName = a.name.localeCompare(b.name, undefined, { sensitivity: "base", numeric: true });
        if (byName !== 0) return sign * byName;
      }
    }
    return sign * (ipSortKey(a.ip) - ipSortKey(b.ip));
  });
}

/** Every name a host is known by, best first, without duplicates. */
export function allNames(host: FoundHost): string[] {
  const names = [host.name, host.names.rdp_certificate, host.names.mdns_name, host.names.mdns_host, host.names.netbios, host.names.dns];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const name of names) {
    if (!name) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out;
}

export function serviceLabels(host: FoundHost): string[] {
  const labels: string[] = [];
  if (host.rdp !== null) labels.push("Remote Desktop");
  if (host.vnc !== null) labels.push(host.rfb_version === "003.889" ? "Screen Sharing (Mac)" : "Screen Sharing / VNC");
  if (host.ssh !== null) labels.push("SSH");
  return labels;
}

/** Case-insensitive match on the IP, any name, a service or the model. */
export function filterHosts(hosts: FoundHost[], text: string): FoundHost[] {
  const needle = text.trim().toLowerCase();
  if (!needle) return hosts;
  return hosts.filter((host) =>
    [host.ip, ...allNames(host), ...serviceLabels(host), host.model ?? ""].some((value) => value.toLowerCase().includes(needle)),
  );
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Saved connections that point at this machine's address. Only the address counts: the names a
 * scan finds are whatever the machine (or anyone on the network) chose to announce.
 */
export function savedMatches(host: FoundHost, connections: Connection[]): Connection[] {
  return connections.filter((c) => normalizeHost(c.host) === host.ip);
}

export interface NameMatch {
  connection: Connection;
  /** The saved connection uses an IP address, and it is not this one. */
  differentAddress: boolean;
}

/** Saved connections whose host matches one of this machine's names, but not its address. */
export function nameOnlyMatches(host: FoundHost, connections: Connection[]): NameMatch[] {
  const keys = new Set(allNames(host).map(normalizeHost));
  // "studio-mac.local" also matches a saved "studio-mac".
  for (const name of allNames(host)) {
    const short = normalizeHost(name).split(".")[0];
    if (short && name.includes(".")) keys.add(short);
  }
  return connections
    .filter((c) => normalizeHost(c.host) !== host.ip && keys.has(normalizeHost(c.host)))
    .map((connection) => ({ connection, differentAddress: parseIpv4(normalizeHost(connection.host)) !== null }));
}

/** The warning for a name-only match: the name may be announced by any machine. */
export function nameMatchWarning(match: NameMatch): string {
  return match.differentAddress
    ? `Name matches saved "${match.connection.name}" but at a different address`
    : `Name matches saved "${match.connection.name}", but the address isn't confirmed`;
}

/** The protocols the app can connect to this machine with. */
export function addableProtocols(host: FoundHost): Protocol[] {
  const out: Protocol[] = [];
  if (host.rdp !== null) out.push("rdp");
  if (host.vnc !== null) out.push("vnc");
  return out;
}

/**
 * A friendly connection name: the computer name without domain, or the IP. A name that a saved
 * connection already has gets the address added, so an announced name can never produce a
 * look-alike of a saved connection.
 */
export function suggestedName(host: FoundHost, protocol: Protocol, saved: Connection[] = []): string {
  const name = announcedName(host, protocol);
  if (name === host.ip) return name;
  const key = name.trim().toLowerCase();
  const taken = saved.some((c) => {
    const host = normalizeHost(c.host);
    return c.name.trim().toLowerCase() === key || host === key || (parseIpv4(host) === null && host.split(".")[0] === key);
  });
  return taken ? `${name} (${host.ip})` : name;
}

function announcedName(host: FoundHost, protocol: Protocol): string {
  const preferred =
    protocol === "vnc"
      ? (host.names.mdns_name ?? host.names.mdns_host ?? host.name)
      : (host.names.rdp_certificate ?? host.names.netbios ?? host.name);
  if (!preferred) return host.ip;
  // A FQDN becomes its first label; friendly names (which may contain dots) are kept.
  if (preferred === host.names.mdns_name) return preferred;
  return /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(preferred) ? (preferred.split(".")[0] ?? preferred) : preferred;
}

/**
 * A new connection pre-filled from a found machine. The user still enters the username. Nothing
 * is known about the machine yet, so clipboard sharing starts off.
 */
export function prefillConnection(host: FoundHost, protocol: Protocol, saved: Connection[] = []): Connection {
  const connection = blankConnection(protocol);
  connection.name = suggestedName(host, protocol, saved);
  connection.host = host.ip;
  connection.share_clipboard = false;
  if (protocol === "rdp") {
    connection.port = host.rdp ?? connection.port;
  } else {
    connection.port = host.vnc ?? connection.port;
    connection.ssh_tunnel = host.ssh !== null;
    connection.ssh_port = host.ssh ?? DEFAULT_SSH_PORT;
  }
  return connection;
}

export function progressText(done: number, total: number, found: number): string {
  const machines = found === 1 ? "1 computer found" : `${found} computers found`;
  return `${done.toLocaleString("en-US")} of ${total.toLocaleString("en-US")} addresses checked, ${machines}`;
}
