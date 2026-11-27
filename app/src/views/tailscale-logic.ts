// Logic for the Tailscale tab, the Tailscale source in "Find computers" and the online dots on
// Home. Pure: no DOM. Every device string comes from another member of the tailnet (they chose
// the name and the OS label), so it is cleaned before display and shown as text only. Tags are
// shown for information and never trusted for anything.
import type { Connection, HostKind, Protocol, TailscaleDevice, TailscaleStatus } from "../ipc";
import { blankConnection } from "../state";

/** Longest device name shown before it is cut (the full cleaned name goes in the tooltip). */
export const MAX_NAME_CHARS = 48;
export const MAX_DNS_CHARS = 80;
export const MAX_DETAIL_CHARS = 300;
/** Auto-refresh interval of the Tailscale tab and of the dots on Home. */
export const REFRESH_MS = 30_000;
export const DOWNLOAD_URL = "https://tailscale.com/download";

/** Hidden characters, in step with rc_discover::is_hidden_char. */
const HIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x2800, 0x2800],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xffa0, 0xffa0],
  [0xe0100, 0xe01ef],
  [0x0600, 0x0605],
  [0x061c, 0x061c],
  [0x06dd, 0x06dd],
  [0x070f, 0x070f],
  [0x0890, 0x0891],
  [0x08e2, 0x08e2],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffc],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0001, 0xe0001],
  [0xe0020, 0xe007f],
];

export function isHiddenChar(codePoint: number): boolean {
  return HIDDEN_RANGES.some(([low, high]) => codePoint >= low && codePoint <= high);
}

/** Control (Unicode Cc, as Rust's char::is_control) or hidden: dropped before display. */
export function isUnsafeChar(codePoint: number): boolean {
  return codePoint < 0x20 || (codePoint >= 0x7f && codePoint <= 0x9f) || isHiddenChar(codePoint);
}

/**
 * A string from the tailnet made fit to show: no control, hidden or bidi characters, trimmed, and
 * cut to `max` characters with an ellipsis. Null or nothing left gives "".
 */
export function cleanText(text: string | null | undefined, max = MAX_NAME_CHARS): string {
  if (!text) return "";
  const kept = Array.from(text).filter((c) => !isUnsafeChar(c.codePointAt(0) ?? 0));
  const joined = kept.join("").trim();
  const chars = Array.from(joined);
  return chars.length > max ? `${chars.slice(0, Math.max(max - 1, 1)).join("").trimEnd()}…` : joined;
}

/** A MagicDNS name without its trailing dot, lowercased; "" when absent or not a plain DNS name. */
export function cleanDnsName(dnsName: string | null | undefined): string {
  const text = (dnsName ?? "").trim().replace(/\.$/, "").toLowerCase();
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(text) && text.length <= 253 ? text : "";
}

/** Only a dotted-quad IPv4 address is used as one (and shown as one). */
export function cleanIpv4(ip: string | null | undefined): string {
  const text = (ip ?? "").trim();
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(text) ? text : "";
}

/** Windows or Mac from Tailscale's OS label ("windows", "macOS"); everything else is unknown. */
export function osKind(os: string | null | undefined): HostKind {
  const key = (os ?? "").trim().toLowerCase();
  if (key === "windows") return "windows";
  if (key === "macos" || key === "darwin") return "mac";
  return "unknown";
}

const OS_LABELS: Record<string, string> = {
  windows: "Windows",
  macos: "macOS",
  darwin: "macOS",
  linux: "Linux",
  ios: "iOS",
  ipados: "iPadOS",
  android: "Android",
  tvos: "tvOS",
  freebsd: "FreeBSD",
  openbsd: "OpenBSD",
  illumos: "illumos",
};

export function osLabel(os: string | null | undefined): string {
  const key = (os ?? "").trim().toLowerCase();
  return OS_LABELS[key] ?? (cleanText(os, 16) || "Other");
}

/** Windows PCs and Macs: shown by default and offered as connections. */
export function isComputerDevice(device: TailscaleDevice): boolean {
  return osKind(device.os) !== "unknown";
}

export interface DeviceGroups {
  online: TailscaleDevice[];
  offline: TailscaleDevice[];
  /** Devices left out because they are not Windows PCs or Macs (0 when showing all). */
  hidden: number;
}

function sortKey(device: TailscaleDevice): string {
  return cleanText(device.name, 1000).toLowerCase();
}

/** The devices to list, grouped and sorted by name. This computer is always left out. */
export function groupDevices(devices: TailscaleDevice[], showAll: boolean): DeviceGroups {
  const others = devices.filter((d) => !d.isSelf);
  const shown = showAll ? others : others.filter(isComputerDevice);
  const sorted = [...shown].sort((a, b) => sortKey(a).localeCompare(sortKey(b), undefined, { numeric: true }));
  return {
    online: sorted.filter((d) => d.online),
    offline: sorted.filter((d) => !d.online),
    hidden: others.length - shown.length,
  };
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

/** Whether a saved host is this device's Tailscale IPv4 or MagicDNS name. Names alone never count. */
export function deviceMatchesHost(device: TailscaleDevice, host: string): boolean {
  const key = normalizeHost(host);
  if (key === "") return false;
  const ip = cleanIpv4(device.ipv4);
  const dns = cleanDnsName(device.dnsName);
  return (ip !== "" && key === ip) || (dns !== "" && key === dns);
}

/** Saved connections that point at this device by address (IPv4 or MagicDNS name). */
export function savedForDevice(device: TailscaleDevice, connections: Connection[]): Connection[] {
  return connections.filter((c) => deviceMatchesHost(device, c.host));
}

/** The tailnet device a saved connection points at, if any. */
export function deviceForConnection(connection: Connection, devices: TailscaleDevice[]): TailscaleDevice | null {
  return devices.find((d) => deviceMatchesHost(d, connection.host)) ?? null;
}

/** Tailscale's "never seen" is year 1; anything that old, or unparsable, is no date at all. */
export function parseLastSeen(lastSeen: string | null): number | null {
  if (!lastSeen) return null;
  const time = Date.parse(lastSeen);
  if (Number.isNaN(time) || time < Date.UTC(2000, 0, 1)) return null;
  return time;
}

/** "just now", "5 minutes ago", "3 days ago". */
export function relativeTime(time: number, now: number): string {
  const seconds = Math.max(0, Math.round((now - time) / 1000));
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"} ago`;
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return unit(minutes, "minute");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return unit(hours, "hour");
  const days = Math.floor(hours / 24);
  if (days < 60) return unit(days, "day");
  const months = Math.floor(days / 30);
  if (months < 24) return unit(months, "month");
  return unit(Math.floor(days / 365), "year");
}

/** "Last seen 3 days ago", or null when Tailscale doesn't know. */
export function lastSeenText(device: TailscaleDevice, now: number): string | null {
  const time = parseLastSeen(device.lastSeen);
  return time === null ? null : `Last seen ${relativeTime(time, now)}`;
}

/** The tooltip of a Home dot. */
export function presenceTooltip(device: TailscaleDevice, now: number): string {
  if (device.online) return "Online on Tailscale";
  const time = parseLastSeen(device.lastSeen);
  return time === null ? "Offline on Tailscale" : `Offline on Tailscale, last seen ${relativeTime(time, now)}`;
}

/** Tags for display only: cleaned, short, at most a few. */
export function displayTags(device: TailscaleDevice): string[] {
  return (device.tags ?? [])
    .map((t) => cleanText(t, 32))
    .filter((t) => t !== "")
    .slice(0, 5);
}

export function protocolForDevice(device: TailscaleDevice): Protocol {
  return osKind(device.os) === "mac" ? "vnc" : "rdp";
}

/** The two hosts a device can be saved with; either may be "". */
export interface HostChoices {
  dnsName: string;
  ip: string;
}

export function hostChoices(device: TailscaleDevice): HostChoices {
  return { dnsName: cleanDnsName(device.dnsName), ip: cleanIpv4(device.ipv4) };
}

/**
 * A connection name from the device name. Like "Find computers", a name a saved connection
 * already uses gets the address added, so another tailnet member can't make a look-alike.
 */
export function suggestedDeviceName(device: TailscaleDevice, saved: Connection[] = []): string {
  const choices = hostChoices(device);
  const fallback = choices.dnsName.split(".")[0] || choices.ip;
  const name = cleanText(device.name) || fallback;
  const key = name.toLowerCase();
  const taken = saved.some((c) => {
    const host = normalizeHost(c.host);
    return c.name.trim().toLowerCase() === key || host === key || host.split(".")[0] === key;
  });
  const address = choices.ip || choices.dnsName;
  return taken && address && name !== address ? `${name} (${address})` : name;
}

/**
 * A new connection pre-filled from a tailnet device: Windows means Remote Desktop, macOS means
 * Screen Sharing, the host is the MagicDNS name (the IP when there is none). The user enters the
 * username. Nothing is known about the machine yet, so clipboard sharing starts off.
 */
export function prefillFromDevice(device: TailscaleDevice, saved: Connection[] = []): Connection {
  const connection = blankConnection(protocolForDevice(device));
  const choices = hostChoices(device);
  connection.name = suggestedDeviceName(device, saved);
  connection.host = choices.dnsName || choices.ip;
  connection.share_clipboard = false;
  return connection;
}

export interface UnavailableText {
  headline: string;
  /** The next step, one line. */
  next: string;
  /** Shown as text to copy (the app has no way to open links). */
  link: string | null;
}

/** What to say when Tailscale can't be read, or null when it can. */
export function unavailableText(status: TailscaleStatus): UnavailableText | null {
  if (status.available) return null;
  switch (status.reason) {
    case "not_installed":
      return { headline: "Tailscale isn't installed on this computer", next: "Install Tailscale and sign in. Download it from:", link: DOWNLOAD_URL };
    case "not_running":
      return { headline: "Tailscale isn't running", next: "Start Tailscale, then refresh.", link: null };
    case "logged_out":
      return { headline: "Tailscale is signed out", next: "Sign in to Tailscale, then refresh.", link: null };
    default: {
      const detail = cleanText(status.detail, MAX_DETAIL_CHARS);
      return { headline: "Couldn't read Tailscale", next: detail || "Tailscale returned an error. Try again in a moment.", link: null };
    }
  }
}

/** A one-line reason for the Tailscale row in "Find computers". */
export function unavailableShort(status: TailscaleStatus): string {
  switch (status.reason) {
    case "not_installed":
      return "Not installed: install Tailscale and sign in.";
    case "not_running":
      return "Not running: start Tailscale.";
    case "logged_out":
      return "Signed out: sign in to Tailscale.";
    default:
      return cleanText(status.detail, 120) || "Couldn't read Tailscale.";
  }
}
