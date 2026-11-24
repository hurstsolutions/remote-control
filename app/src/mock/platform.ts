// An in-memory stand-in for the Rust side, used only when the page runs in a plain browser
// (vite dev) without Tauri. Never loaded inside the app.
import type {
  AppInfo,
  ChannelMessage,
  ConnectArgs,
  Connection,
  ErrorKind,
  SessionError,
  SessionEvent,
  FoundHost,
  ScanEvent,
  SessionInput,
  Subnet,
} from "../ipc";
import type { Api, Platform } from "../platform";
import { parseCidr } from "../views/find-logic";

const FAILING_ID = "mock-fails";
/** A Mac with Screen Sharing on but Remote Login off: fails with tunnel_unavailable until the tunnel is off. */
const NO_SSH_ID = "mock-mac-no-ssh";
const FAILURES: ErrorKind[] = ["unreachable", "auth_failed", "security", "identity_changed", "unsupported", "protocol", "disconnected", "other"];
/** A Windows PC whose certificate changed since it was pinned (it has a saved password, which trusting must not use). */
const NEW_CERT_ID = "mock-new-cert";
/** A Mac whose SSH host key changed since it was pinned. */
const NEW_KEY_ID = "mock-new-key";
/**
 * A Mac without SSH whose Screen Sharing doesn't offer Apple's verified (SRP) sign-in: refused
 * until "Allow older Macs without verified sign-in" is ticked, then encrypted but not verified.
 */
const OLDER_MAC_ID = "mock-older-mac";
/**
 * A Mac without SSH that signed in with SRP before and now doesn't offer it (what someone
 * interfering would cause): refused even though the older sign-in is allowed for it.
 */
const SRP_GONE_ID = "mock-srp-gone";
/** Macs that don't offer SRP (now). */
const NO_SRP_IDS = new Set([OLDER_MAC_ID, SRP_GONE_ID]);
/** rc_vnc::SRP_NOT_OFFERED and the text after it. */
const NO_SRP_DETAIL =
  "the Mac didn't offer SRP sign-in (Apple's verified sign-in); this can mean someone is interfering with the connection, or an older Mac. Apple's older sign-in (type 30) does not verify the Mac, and an impostor could learn the password through it, so it is refused. Use an SSH tunnel, or allow unverified sign-in for this connection if the network is trusted. Offered: [30 (Apple Remote Desktop)]";
/** Adding this subnet makes the mock scan answer on every address and stop with "too many". */
const EVERYWHERE_CIDR = "10.0.9.0/24";
/** A VNC server that cannot encrypt: fails without the SSH tunnel. */
const NO_ENCRYPTION_ID = "mock-no-encryption";
const OLD_IDENTITY = "aa".repeat(32);
/** What each sample presents now; anything else presents DEFAULT_IDENTITY. */
const PRESENTED: Record<string, string> = {
  [NEW_CERT_ID]: "b7e1" + "0c".repeat(28) + "9f42",
  [NEW_KEY_ID]: "5d" + "e3".repeat(30) + "71",
};
const DEFAULT_IDENTITY = "3f".repeat(32);
/** Typing this password with "save" ticked makes the mock keychain fail, to show the notice. */
const KEYCHAIN_FAILS = "keychain-fails";
const HEADER = 8;

const connections: Connection[] = [
  {
    id: "mock-windows",
    name: "Office PC (sample)",
    protocol: "rdp",
    host: "office-pc.local",
    port: 3389,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: "mock-mac",
    name: "Studio Mac (sample)",
    protocol: "vnc",
    host: "studio-mac.local",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: FAILING_ID,
    name: "Fails a different way each time (sample)",
    protocol: "rdp",
    host: "10.0.0.99",
    port: 3389,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: NO_SSH_ID,
    name: "Mac with Remote Login off (sample)",
    protocol: "vnc",
    host: "10.0.0.42",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: NEW_CERT_ID,
    name: "PC with a new certificate (sample)",
    protocol: "rdp",
    host: "10.0.0.42",
    port: 3389,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: OLD_IDENTITY,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: NEW_KEY_ID,
    name: "Mac with a new SSH key (sample)",
    protocol: "vnc",
    host: "10.0.0.43",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: 22,
    pinned_identity: OLD_IDENTITY,
    share_clipboard: false,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: OLDER_MAC_ID,
    name: "Older Mac without SSH (sample)",
    protocol: "vnc",
    host: "10.0.0.44",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: false,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
  {
    id: SRP_GONE_ID,
    name: "Mac that used verified sign-in before (sample)",
    protocol: "vnc",
    host: "10.0.0.46",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: false,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: true,
    srp_seen: true,
  },
  {
    id: NO_ENCRYPTION_ID,
    name: "VNC server that can't encrypt (sample)",
    protocol: "vnc",
    host: "10.0.0.45",
    port: 5900,
    username: "sam",
    domain: "",
    nla: true,
    ssh_tunnel: false,
    ssh_port: 22,
    pinned_identity: null,
    share_clipboard: true,
    allow_older_mac_sign_in: false,
    srp_seen: false,
  },
];
// The Mac samples, the failing sample and the changed-identity samples have a "saved" password;
// the Windows sample asks.
const savedPasswords = new Set<string>(["mock-mac", NO_SSH_ID, FAILING_ID, NEW_CERT_ID, NEW_KEY_ID, OLDER_MAC_ID, SRP_GONE_ID, NO_ENCRYPTION_ID]);
const sessions = new Map<string, MockSession>();
const log: string[] = [];
let nextId = 1;
let failureIndex = 0;
let clipboardText = "";

function note(line: string): void {
  log.push(`${new Date().toISOString()} ${line}`);
  if (log.length > 500) log.shift();
}

// ---- debug overlay --------------------------------------------------------------------------

let overlayLines: HTMLElement | null = null;
const recent: string[] = [];

function echo(line: string): void {
  if (!overlayLines) {
    const box = document.createElement("div");
    box.className = "mock-overlay";
    const title = document.createElement("div");
    title.className = "mock-overlay-title";
    title.textContent = "Mock backend - input received. F7 cursor, F8 remote copy, F9 drop connection";
    overlayLines = document.createElement("pre");
    box.append(title, overlayLines);
    document.body.append(box);
  }
  recent.push(line);
  if (recent.length > 8) recent.shift();
  overlayLines.textContent = recent.join("\n");
}

function describe(input: SessionInput): string {
  switch (input.type) {
    case "pointer_move":
      return `move ${input.x},${input.y}`;
    case "pointer_button":
      return `button ${input.button} ${input.down ? "down" : "up"} at ${input.x},${input.y}`;
    case "wheel":
      return `wheel dx ${input.dx.toFixed(2)} dy ${input.dy.toFixed(2)} at ${input.x},${input.y}`;
    case "key":
      return `key ${input.down ? "down" : "up"} ${input.code} (${input.key.length === 1 ? "char" : input.key})`;
    case "clipboard":
      return `clipboard (${input.text.length} characters)`;
    case "resize":
      return `resize ${input.width}x${input.height}`;
    default:
      return input.type;
  }
}

// ---- fake session ---------------------------------------------------------------------------

type Emit = (message: ChannelMessage) => void;

class MockSession {
  private width = 1280;
  private height = 800;
  private readonly timers: number[] = [];
  private interval = 0;
  private tick = 0;
  private blockX = 0;
  private cursorStep = 0;
  private closed = false;

  constructor(
    readonly id: string,
    private readonly connection: Connection,
    private readonly emit: Emit,
    /** Runs on sign-in, before "connected" is sent (where the real backend saves the pin). */
    private readonly onSignedIn: () => string | null = () => null,
    /** The "security" events sent before "connected". */
    private readonly security: SessionEvent[] = [],
  ) {}

  private event(event: SessionEvent): void {
    if (!this.closed) this.emit(event);
  }

  private later(ms: number, action: () => void): void {
    this.timers.push(window.setTimeout(action, ms));
  }

  /** Go through the status steps, then either connect or fail. */
  run(failure: ErrorKind | null): void {
    const host = this.connection.host;
    this.event({ type: "status", text: `Looking up ${host}...` });
    this.later(400, () => this.event({ type: "status", text: `Connecting to ${host}...` }));
    if (failure && failure !== "disconnected") {
      const error =
        failure === "identity_changed"
          ? identityChanged({ ...this.connection, pinned_identity: OLD_IDENTITY }, presentedIdentity(this.connection.id))
          : mockError(failure, host);
      this.later(1100, () => this.finish(error));
      return;
    }
    this.later(800, () => {
      if (this.connection.protocol === "rdp" || this.connection.ssh_tunnel) {
        this.event({ type: "identity", sha256: presentedIdentity(this.connection.id) });
      }
      for (const event of this.security) this.event(event);
      this.event({ type: "status", text: "Signing in..." });
    });
    this.later(1300, () => {
      const notice = this.onSignedIn();
      this.event({ type: "connected", width: this.width, height: this.height, name: `${this.connection.name} (mock)` });
      if (notice) this.event({ type: "notice", text: notice });
      this.emit(this.frame(0, 0, this.width, this.height));
      this.interval = window.setInterval(() => this.animate(), 50);
      if (failure === "disconnected") this.later(3000, () => this.finish(mockError("disconnected", host)));
    });
  }

  input(input: SessionInput): void {
    if (this.closed) return;
    echo(describe(input));
    if (input.type === "pointer_button" && input.down) {
      // Mark where the remote saw the click, to check the coordinate mapping by eye.
      const x = Math.max(0, Math.min(this.width - 12, input.x - 6));
      const y = Math.max(0, Math.min(this.height - 12, input.y - 6));
      this.emit(this.solid(x, y, 12, 12, input.button === "left" ? [220, 40, 40] : [40, 90, 220]));
    } else if (input.type === "resize" && this.connection.protocol === "rdp") {
      this.width = input.width;
      this.height = input.height;
      this.blockX = 0;
      this.event({ type: "resized", width: this.width, height: this.height });
      this.emit(this.frame(0, 0, this.width, this.height));
    } else if (input.type === "refresh") {
      this.emit(this.frame(0, 0, this.width, this.height));
    } else if (input.type === "close") {
      this.finish(null);
    } else if (input.type === "key" && input.down) {
      if (input.code === "F7") this.nextCursor();
      if (input.code === "F8") this.event({ type: "clipboard", text: `Copied on the mock remote at ${new Date().toLocaleTimeString()}` });
      if (input.code === "F9") this.finish(mockError("disconnected", this.connection.host));
    }
  }

  /** Fail after the first status steps with a ready-made error. */
  fail(error: SessionError): void {
    this.event({ type: "status", text: `Connecting to ${this.connection.host}...` });
    this.later(900, () => this.finish(error));
  }

  finish(error: SessionError | null): void {
    if (this.closed) return;
    this.event({ type: "closed", error });
    this.stop();
  }

  stop(): void {
    this.closed = true;
    for (const timer of this.timers) window.clearTimeout(timer);
    window.clearInterval(this.interval);
    sessions.delete(this.id);
  }

  private nextCursor(): void {
    this.cursorStep = (this.cursorStep + 1) % 3;
    if (this.cursorStep === 0) this.event({ type: "cursor", kind: "default" });
    else if (this.cursorStep === 1) this.event(crosshairCursor());
    else this.event({ type: "cursor", kind: "hidden" });
  }

  /** A block sliding across a band near the top, plus a blinking square. */
  private animate(): void {
    this.tick++;
    const size = 64;
    const bandY = 96;
    const previous = this.blockX;
    this.blockX = (this.blockX + 8) % Math.max(1, this.width - size);
    const erase = this.frame(previous, bandY, size, size);
    const draw = this.solid(this.blockX, bandY, size, size, [240, 170, 40]);
    if (this.tick % 2 === 0) {
      // Two frames in one message, as the real backend may send.
      this.emit(concat(erase, draw));
    } else {
      this.emit(erase);
      this.emit(draw);
    }
    if (this.tick % 10 === 0) {
      const on = (this.tick / 10) % 2 === 0;
      this.emit(this.solid(24, 24, 32, 32, on ? [60, 200, 120] : [30, 60, 45]));
    }
  }

  /** The background test pattern for a rectangle: a grid with a colour ramp. */
  private frame(x: number, y: number, w: number, h: number): ArrayBuffer {
    const buffer = header(x, y, w, h);
    const pixels = new Uint8Array(buffer, HEADER);
    let i = 0;
    for (let py = y; py < y + h; py++) {
      for (let px = x; px < x + w; px++) {
        const line = px % 100 === 0 || py % 100 === 0;
        const edge = px === 0 || py === 0 || px === this.width - 1 || py === this.height - 1;
        pixels[i++] = edge ? 255 : line ? 90 : 30 + Math.floor((px / this.width) * 60);
        pixels[i++] = edge ? 255 : line ? 90 : 36 + Math.floor((py / this.height) * 60);
        pixels[i++] = edge ? 255 : line ? 100 : 60;
        pixels[i++] = 255;
      }
    }
    return buffer;
  }

  private solid(x: number, y: number, w: number, h: number, rgb: [number, number, number]): ArrayBuffer {
    const buffer = header(x, y, w, h);
    const pixels = new Uint8Array(buffer, HEADER);
    for (let i = 0; i < pixels.length; i += 4) {
      pixels[i] = rgb[0];
      pixels[i + 1] = rgb[1];
      pixels[i + 2] = rgb[2];
      pixels[i + 3] = 255;
    }
    return buffer;
  }
}

function header(x: number, y: number, w: number, h: number): ArrayBuffer {
  const buffer = new ArrayBuffer(HEADER + w * h * 4);
  const view = new DataView(buffer);
  view.setUint16(0, x, true);
  view.setUint16(2, y, true);
  view.setUint16(4, w, true);
  view.setUint16(6, h, true);
  return buffer;
}

function concat(a: ArrayBuffer, b: ArrayBuffer): ArrayBuffer {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(new Uint8Array(a), 0);
  out.set(new Uint8Array(b), a.byteLength);
  return out.buffer;
}

function crosshairCursor(): SessionEvent {
  const size = 24;
  const rgba = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const onCross = Math.abs(x - 12) <= 1 || Math.abs(y - 12) <= 1;
      const core = x === 12 || y === 12;
      if (!onCross) continue;
      const i = (y * size + x) * 4;
      const shade = core ? 255 : 0;
      rgba[i] = shade;
      rgba[i + 1] = shade;
      rgba[i + 2] = shade;
      rgba[i + 3] = 255;
    }
  }
  let binary = "";
  for (const byte of rgba) binary += String.fromCharCode(byte);
  return { type: "cursor", kind: "bitmap", width: size, height: size, hot_x: 12, hot_y: 12, rgba_base64: btoa(binary) };
}

/**
 * What the backend reports for a session that signs in; `pinned` = a pin was checked. A session
 * that trusts a new identity is never reported as verified (lib.rs security_for_session).
 */
function mockSecurity(connection: Connection, pinned: boolean, trusting: boolean): SessionEvent[] {
  const verified = pinned && !trusting;
  if (connection.protocol === "rdp") {
    return [{ type: "security", encrypted: true, server_verified: verified, method: connection.nla ? "TLS + NLA" : "TLS" }];
  }
  if (connection.ssh_tunnel) {
    return [
      { type: "security", encrypted: true, server_verified: verified, method: "SSH tunnel" },
      { type: "security", encrypted: false, server_verified: false, method: "VNC, unencrypted" },
    ];
  }
  return NO_SRP_IDS.has(connection.id)
    ? [{ type: "security", encrypted: true, server_verified: false, method: "Apple Screen Sharing encryption" }]
    : [{ type: "security", encrypted: true, server_verified: true, method: "Apple Screen Sharing encryption, SRP sign-in" }];
}

function presentedIdentity(id: string): string {
  return PRESENTED[id] ?? DEFAULT_IDENTITY;
}

function sameTarget(a: Connection, b: Connection): boolean {
  return (
    a.protocol === b.protocol &&
    a.host.toLowerCase() === b.host.toLowerCase() &&
    a.port === b.port &&
    a.ssh_tunnel === b.ssh_tunnel &&
    (!a.ssh_tunnel || a.ssh_port === b.ssh_port)
  );
}

function identityChanged(connection: Connection, presented: string): SessionError {
  const ssh = connection.protocol === "vnc";
  const expected = connection.pinned_identity ?? "";
  return {
    kind: "identity_changed",
    detail: ssh
      ? `the Mac's SSH host key changed (expected ${expected}, got ${presented}). No password was sent.`
      : `the server's certificate changed (expected ${expected}, got ${presented}). No credentials were sent.`,
    identity: { identity_kind: ssh ? "ssh_host_key" : "tls_certificate", expected_sha256: expected, received_sha256: presented },
  };
}

function mockError(kind: ErrorKind, host: string): SessionError {
  const details: Record<ErrorKind, string> = {
    unreachable: `tcp connect to ${host}:3389 failed: connection timed out (os error 60)`,
    tunnel_unavailable: `SSH (Remote Login) connection to ${host}:22 failed: No connection could be made because the target machine actively refused it. (os error 10061)`,
    auth_failed: "CredSSP: the server rejected the credentials (STATUS_LOGON_FAILURE 0xC000006D)",
    security: `TLS handshake failed: invalid peer certificate: UnsupportedCertVersion (${host})`,
    identity_changed: `the server's certificate changed (expected ${OLD_IDENTITY}, got ${DEFAULT_IDENTITY}).`,
    unsupported: "server requires a security protocol this client does not offer (HYBRID_EX)",
    protocol: "decode error: unexpected PDU type 0x17 in state CapabilitiesExchange",
    disconnected: "connection reset by peer (os error 54)",
    other: "mock: an error with no particular kind",
    password_required: "no password supplied and none saved",
    no_verified_sign_in: NO_SRP_DETAIL,
  };
  return { kind, detail: details[kind] };
}

// ---- api ------------------------------------------------------------------------------------

const delay = <T>(value: T, ms = 60): Promise<T> => new Promise((resolve) => window.setTimeout(() => resolve(value), ms));

// ---- find computers -------------------------------------------------------------------------

let subnets: Subnet[] = [
  { id: "mock-subnet-office", cidr: "10.0.0.0/24", label: "Office VLAN (sample)", allow_public: false },
  { id: "mock-subnet-lab", cidr: "10.0.1.0/24", label: "Lab (sample)", allow_public: false },
];
let nextSubnet = 1;
let scanTimer = 0;
let activeScan: { id: string; cancel: () => void } | null = null;

function blankHost(ip: string): FoundHost {
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
  };
}

/** Fake machines at these host numbers of every scanned subnet. */
function fakeHost(base: string, offset: number): FoundHost | null {
  const prefix = base.split(".").slice(0, 3).join(".");
  const ip = `${prefix}.${offset}`;
  const host = blankHost(ip);
  switch (offset) {
    case 10:
      return { ...host, rdp: 3389, kind: "windows", name: "DESKTOP-SAMPLE1", names: { ...host.names, rdp_certificate: "DESKTOP-SAMPLE1", netbios: "DESKTOP-SAMPLE1" }, rdp_certificate_sha256: "3f".repeat(32) };
    case 23:
      return { ...host, vnc: 5900, ssh: 22, kind: "mac", name: "Design Mac (sample)", names: { ...host.names, mdns_name: "Design Mac (sample)", mdns_host: "design-mac.local" }, rfb_version: "003.889", ssh_banner: "SSH-2.0-OpenSSH_9.8", model: "Mac14,3" };
    case 42:
      // Matches the saved "Mac with Remote Login off" and "PC with a new certificate" samples.
      return { ...host, rdp: 3389, vnc: 5900, kind: "mac", name: "dual-boot.example.internal", names: { ...host.names, dns: "dual-boot.example.internal" }, rfb_version: "003.889" };
    case 57:
      return { ...host, ssh: 22, name: "build-server.example.internal", names: { ...host.names, dns: "build-server.example.internal" }, ssh_banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu" };
    case 88:
      // A hostile name: must show as plain text.
      return { ...host, rdp: 3389, kind: "windows", name: '<img src=x onerror="window.__xss=1">', names: { ...host.names, rdp_certificate: '<img src=x onerror="window.__xss=1">' }, rdp_certificate_sha256: "9a".repeat(32) };
    case 120:
      return { ...host, vnc: 5900, name: null, rfb_version: "003.008" };
    case 77:
      // Announces the name of the saved "Office PC" sample from another address: a warning, not "Saved".
      return { ...host, rdp: 3389, kind: "windows", name: "office-pc.local", names: { ...host.names, rdp_certificate: "office-pc.local" }, rdp_certificate_sha256: "4c".repeat(32) };
    default:
      return null;
  }
}

function mockSaveSubnets(list: Subnet[]): Subnet[] {
  const out: Subnet[] = [];
  for (const subnet of list) {
    const parsed = parseCidr(subnet.cidr);
    if (!parsed.ok) throw { kind: "other", detail: `${subnet.cidr}: ${parsed.error}` } satisfies SessionError;
    if (out.some((s) => s.cidr === parsed.value.cidr)) throw { kind: "other", detail: `${parsed.value.cidr} is in the list twice.` } satisfies SessionError;
    out.push({
      id: subnet.id || `mock-subnet-${nextSubnet++}`,
      cidr: parsed.value.cidr,
      label: subnet.label.trim().slice(0, 80),
      allow_public: subnet.allow_public && !parsed.value.isPrivate,
    });
  }
  return out;
}

function mockStartScan(ids: string[], onEvent: (event: ScanEvent) => void): string {
  if (activeScan) throw { kind: "other", detail: "A scan is already running. Cancel it or wait for it to finish." } satisfies SessionError;
  if (ids.length === 0) throw { kind: "other", detail: "Choose at least one subnet to scan." } satisfies SessionError;
  const chosen = ids.map((id) => subnets.find((s) => s.id === id));
  if (chosen.some((s) => !s)) throw { kind: "other", detail: "A chosen subnet is no longer in the list. Reload and try again." } satisfies SessionError;
  const plan = chosen as Subnet[];
  for (const s of plan) {
    const parsed = parseCidr(s.cidr);
    if (parsed.ok && !parsed.value.isPrivate && !s.allow_public) {
      throw { kind: "other", detail: `${s.cidr} is a public address range. Edit it and confirm it is your own network before scanning it.` } satisfies SessionError;
    }
  }
  const total = plan.reduce((sum, s) => {
    const parsed = parseCidr(s.cidr);
    return sum + (parsed.ok ? parsed.value.hostCount : 0);
  }, 0);
  const found: FoundHost[] = [];
  const everywhere = plan.some((s) => s.cidr === EVERYWHERE_CIDR);
  for (const s of plan) {
    if (s.cidr === EVERYWHERE_CIDR) {
      // Something answering for every address: the scan stops itself past the report limit.
      for (let offset = 1; offset < 255; offset++) found.push({ ...blankHost(`10.0.9.${offset}`), rdp: 3389, kind: "windows" });
      continue;
    }
    for (const offset of [10, 23, 42, 57, 77, 88, 120]) {
      const host = fakeHost(s.cidr, offset);
      if (host) found.push(host);
    }
  }
  /** Stand-in for ScanOptions::max_reported_hosts. */
  const reportLimit = 120;
  const id = `mock-scan-${nextId++}`;
  const steps = 20;
  let step = 0;
  let reported = 0;
  const finish = (cancelled: boolean, tooMany = false) => {
    window.clearInterval(scanTimer);
    activeScan = null;
    const done = cancelled || tooMany ? Math.round((total * step) / steps) : total;
    note(`scan ${id} ${tooMany ? "stopped: too many answers" : cancelled ? "cancelled" : "finished"}`);
    onEvent({ type: "progress", done, total, found: reported });
    onEvent({ type: "finished", cancelled, too_many: tooMany, done, total, found: reported });
  };
  scanTimer = window.setInterval(() => {
    step++;
    const due = Math.floor((found.length * step) / steps);
    while (reported < due) {
      if (everywhere && reported >= reportLimit) {
        finish(false, true);
        return;
      }
      const host = found[reported++];
      if (host) onEvent({ type: "host", host });
    }
    onEvent({ type: "progress", done: Math.round((total * step) / steps), total, found: reported });
    if (step >= steps) finish(false);
  }, 120);
  activeScan = { id, cancel: () => finish(true) };
  note(`scan ${id}: ${plan.map((s) => s.cidr).join(", ")}`);
  return id;
}

const mockApi: Api = {
  listConnections: () => delay(connections.map((c) => ({ ...c }))),
  saveConnection: (connection: Connection) => {
    // The same rules as save_connection in lib.rs: the pin and the password stay only with the
    // same machine (and the password only with the same account); the caller's pin is ignored.
    const saved = { ...connection, id: connection.id || `mock-${nextId++}` };
    const index = connections.findIndex((c) => c.id === saved.id);
    const existing = index >= 0 ? connections[index] : undefined;
    const target = existing !== undefined && sameTarget(existing, saved);
    const account = existing !== undefined && existing.username === saved.username && existing.domain.toLowerCase() === saved.domain.toLowerCase();
    saved.pinned_identity = existing && target ? existing.pinned_identity : null;
    saved.srp_seen = existing !== undefined && target && existing.srp_seen;
    let passwordCleared = false;
    if (connection.id !== "" && (!target || !account)) {
      passwordCleared = existing !== undefined && savedPasswords.has(saved.id);
      savedPasswords.delete(saved.id);
    }
    if (existing) connections[index] = saved;
    else connections.push(saved);
    note(`saved connection ${saved.id}${passwordCleared ? " (saved password cleared)" : ""}`);
    return delay({ connection: { ...saved }, password_cleared: passwordCleared });
  },
  deleteConnection: (id: string) => {
    const index = connections.findIndex((c) => c.id === id);
    if (index >= 0) connections.splice(index, 1);
    savedPasswords.delete(id);
    note(`deleted connection ${id}`);
    return delay(undefined);
  },
  hasSavedPassword: (id: string) => delay(savedPasswords.has(id)),
  forgetPassword: (id: string) => {
    savedPasswords.delete(id);
    return delay(undefined);
  },
  connect: async (args: ConnectArgs, onMessage: (message: ChannelMessage) => void) => {
    await delay(null, 150);
    const connection = connections.find((c) => c.id === args.id);
    if (!connection) throw { kind: "other", detail: `no connection with id ${args.id}` } satisfies SessionError;
    if (args.trust_new_identity && !args.new_identity) {
      throw { kind: "other", detail: "Trusting a new identity needs the fingerprint that was reviewed." } satisfies SessionError;
    }
    if (args.trust_new_identity && args.password === null) {
      // Like the backend: the saved password is never used to trust a new identity.
      note(`connect ${args.id}: trusting a new identity needs a typed password`);
      throw { kind: "password_required", detail: "Enter the password to connect to a computer with a new identity." } satisfies SessionError;
    }
    if (args.password === null && !savedPasswords.has(args.id)) {
      note(`connect ${args.id}: password required`);
      throw mockError("password_required", connection.host);
    }
    const presented = presentedIdentity(args.id);
    const expected = args.trust_new_identity ? args.new_identity : connection.pinned_identity;
    const pinsIdentity = connection.protocol === "rdp" || connection.ssh_tunnel;
    let failure: ErrorKind | null = null;
    let error: SessionError | null = null;
    if (pinsIdentity && expected !== null && expected !== presented && args.id !== FAILING_ID) {
      failure = "identity_changed";
      error = identityChanged(connection, presented);
    } else if (args.id === FAILING_ID && !args.trust_new_identity) {
      failure = FAILURES[failureIndex % FAILURES.length] ?? "other";
      failureIndex++;
    } else if (args.id === NO_SSH_ID && connection.ssh_tunnel) {
      failure = "tunnel_unavailable";
    } else if (NO_SRP_IDS.has(args.id) && !connection.ssh_tunnel && !(connection.allow_older_mac_sign_in && !connection.srp_seen)) {
      // As rc-vnc under EncryptionPolicy::Required without allow_unverified_sign_in.
      failure = "no_verified_sign_in";
      error = { kind: "no_verified_sign_in", detail: NO_SRP_DETAIL };
    } else if (args.id === NO_ENCRYPTION_ID && !connection.ssh_tunnel) {
      failure = "security";
      error = {
        kind: "security",
        detail:
          "the session could not be encrypted: the server announced RFB 3.8, not Apple Screen Sharing (RFB 003.889), and only Apple Screen Sharing can encrypt a VNC session. Refusing to connect without encryption.",
      };
    } else if (args.password === "wrong") {
      failure = "auth_failed";
    }
    const id = `mock-session-${nextId++}`;
    note(
      `connect ${args.id} as ${id}: ${args.width}x${args.height} at ${args.scale_factor}%, trust ${args.trust_new_identity}, outcome ${failure ?? "ok"}`,
    );
    const snapshot = { ...connection };
    const signedIn = (): string | null => {
      // As the backend: pin and password are saved only now, and only for an unchanged target.
      const current = connections.find((c) => c.id === snapshot.id);
      if (!current || !sameTarget(current, snapshot)) return null;
      if (pinsIdentity && (current.pinned_identity === null || args.trust_new_identity)) current.pinned_identity = presented;
      if (connection.protocol === "vnc" && !connection.ssh_tunnel && !NO_SRP_IDS.has(connection.id)) current.srp_seen = true;
      if (args.password !== null && args.save_password) {
        if (args.password === KEYCHAIN_FAILS) {
          return "Signed in, but the password could not be saved in the keychain, so you will be asked for it next time. (mock: no keychain)";
        }
        savedPasswords.add(args.id);
      }
      return null;
    };
    const session = new MockSession(id, connection, onMessage, signedIn, mockSecurity(connection, pinsIdentity && expected !== null, args.trust_new_identity));
    sessions.set(id, session);
    if (error) session.fail(error);
    else session.run(failure);
    return id;
  },
  sendInput: (sessionId: string, input: SessionInput) => {
    sessions.get(sessionId)?.input(input);
    return Promise.resolve();
  },
  disconnect: (sessionId: string) => {
    sessions.get(sessionId)?.stop();
    note(`disconnect ${sessionId}`);
    return Promise.resolve();
  },
  listSubnets: () => delay(subnets.map((s) => ({ ...s }))),
  saveSubnets: async (list: Subnet[]) => {
    await delay(null);
    subnets = mockSaveSubnets(list);
    return subnets.map((s) => ({ ...s }));
  },
  startScan: async (subnetIds: string[], onEvent: (event: ScanEvent) => void) => {
    await delay(null);
    return mockStartScan(subnetIds, onEvent);
  },
  cancelScan: (scanId: string) => {
    if (activeScan?.id === scanId) activeScan.cancel();
    return delay(undefined);
  },
  appInfo: () =>
    delay<AppInfo>({ version: "0.1.0-mock", os: "browser", arch: "mock", log_path: "/mock/RemoteControl.log" }),
  logText: () => delay(log.join("\n") || "(the mock log is empty)"),
  revealLog: () => {
    echo("reveal log (nothing to show in the browser)");
    return Promise.resolve();
  },
};

export function createMockPlatform(): Platform {
  note("mock backend started (no Tauri in this page)");
  return {
    api: mockApi,
    isMock: true,
    readClipboard: () => Promise.resolve(clipboardText),
    writeClipboard: async (text) => {
      clipboardText = text;
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // The browser refused (no focus or permission); the in-memory copy is enough here.
      }
    },
    setFullscreen: async (on) => {
      if (on) await document.documentElement.requestFullscreen();
      else if (document.fullscreenElement) await document.exitFullscreen();
    },
    isFullscreen: () => Promise.resolve(document.fullscreenElement !== null),
  };
}
