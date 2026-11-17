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
  SessionInput,
} from "../ipc";
import type { Api, Platform } from "../platform";

const FAILING_ID = "mock-fails";
const FAILURES: ErrorKind[] = ["unreachable", "auth_failed", "security", "unsupported", "protocol", "disconnected", "other"];
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
  },
];
// The Mac sample and the failing sample have a "saved" password; the Windows sample asks.
const savedPasswords = new Set<string>(["mock-mac", FAILING_ID]);
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
      this.later(1100, () => this.finish(mockError(failure, host)));
      return;
    }
    this.later(800, () => {
      this.event({ type: "identity", sha256: "3f".repeat(32) });
      this.event({ type: "status", text: "Signing in..." });
    });
    this.later(1300, () => {
      this.event({ type: "connected", width: this.width, height: this.height, name: `${this.connection.name} (mock)` });
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

function mockError(kind: ErrorKind, host: string): SessionError {
  const details: Record<ErrorKind, string> = {
    unreachable: `tcp connect to ${host}:3389 failed: connection timed out (os error 60)`,
    auth_failed: "CredSSP: the server rejected the credentials (STATUS_LOGON_FAILURE 0xC000006D)",
    security: `server identity changed for ${host}\n  pinned:    sha256:3f3f3f3f3f3f3f3f...\n  presented: sha256:a91c04be77d20e15...`,
    unsupported: "server requires a security protocol this client does not offer (HYBRID_EX)",
    protocol: "decode error: unexpected PDU type 0x17 in state CapabilitiesExchange",
    disconnected: "connection reset by peer (os error 54)",
    other: "mock: an error with no particular kind",
    password_required: "no password supplied and none saved",
  };
  return { kind, detail: details[kind] };
}

// ---- api ------------------------------------------------------------------------------------

const delay = <T>(value: T, ms = 60): Promise<T> => new Promise((resolve) => window.setTimeout(() => resolve(value), ms));

const mockApi: Api = {
  listConnections: () => delay(connections.map((c) => ({ ...c }))),
  saveConnection: (connection: Connection) => {
    const saved = { ...connection, id: connection.id || `mock-${nextId++}` };
    const index = connections.findIndex((c) => c.id === saved.id);
    if (index >= 0) connections[index] = saved;
    else connections.push(saved);
    note(`saved connection ${saved.id}`);
    return delay({ ...saved });
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
    if (args.password === null && !savedPasswords.has(args.id)) {
      note(`connect ${args.id}: password required`);
      throw mockError("password_required", connection.host);
    }
    let failure: ErrorKind | null = null;
    if (args.id === FAILING_ID && !args.trust_new_identity) {
      failure = FAILURES[failureIndex % FAILURES.length] ?? "other";
      failureIndex++;
    } else if (args.password === "wrong") {
      failure = "auth_failed";
    }
    if (failure === null && args.password !== null && args.save_password) savedPasswords.add(args.id);
    const id = `mock-session-${nextId++}`;
    note(`connect ${args.id} as ${id}: ${args.width}x${args.height} at ${args.scale_factor}%, outcome ${failure ?? "ok"}`);
    const session = new MockSession(id, connection, onMessage);
    sessions.set(id, session);
    session.run(failure);
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
