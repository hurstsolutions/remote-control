// The contract between the web UI and the Rust side (app/src-tauri). Keep both in step.
import { Channel, invoke } from "@tauri-apps/api/core";

export type Protocol = "rdp" | "vnc";

/** A saved connection. Passwords are never part of it: they live in the OS keychain. */
export interface Connection {
  /** Empty string when creating; the backend assigns one. */
  id: string;
  name: string;
  protocol: Protocol;
  host: string;
  /** 3389 for RDP, 5900 for VNC by default. */
  port: number;
  username: string;
  /** RDP only: Windows domain, or "" for a local / Microsoft account. */
  domain: string;
  /** RDP only: Network Level Authentication. Default true. */
  nla: boolean;
  /** VNC only: carry the session through SSH (the Mac's Remote Login). Default true. */
  ssh_tunnel: boolean;
  /** VNC only: SSH port. Default 22. */
  ssh_port: number;
  /** SHA-256 of the server identity pinned on first connect (TLS certificate or SSH host key). */
  pinned_identity: string | null;
}

export type ErrorKind =
  | "unreachable"
  /**
   * VNC through SSH only: the Mac's SSH port refused or did not answer (Remote Login is off).
   * Never used for a refused sign-in or a changed host key.
   */
  | "tunnel_unavailable"
  | "auth_failed"
  | "unsupported"
  | "security"
  | "protocol"
  | "disconnected"
  | "other"
  /** No password was supplied and none is saved: ask the user, then call connect again. */
  | "password_required";

export interface SessionError {
  kind: ErrorKind;
  detail: string;
}

/** JSON events delivered on the session channel. Frames arrive separately as ArrayBuffers. */
export type SessionEvent =
  | { type: "status"; text: string }
  | { type: "identity"; sha256: string }
  | { type: "connected"; width: number; height: number; name: string }
  | { type: "resized"; width: number; height: number }
  | { type: "cursor"; kind: "default" | "hidden" }
  | { type: "cursor"; kind: "bitmap"; width: number; height: number; hot_x: number; hot_y: number; rgba_base64: string }
  | { type: "clipboard"; text: string }
  | { type: "bell" }
  | { type: "closed"; error: SessionError | null };

/**
 * A binary channel message holds one or more frames, back to back. Each frame (little endian):
 *   bytes 0..2 x, 2..4 y, 4..6 w, 6..8 h (u16 each), then w*h*4 bytes of RGBA (alpha 255).
 */
export const FRAME_HEADER_BYTES = 8;

export type MouseButton = "left" | "middle" | "right" | "back" | "forward";

/** Input sent to the remote machine. Coordinates are remote framebuffer pixels. */
export type SessionInput =
  | { type: "pointer_move"; x: number; y: number }
  | { type: "pointer_button"; button: MouseButton; down: boolean; x: number; y: number }
  /** Wheel notches; positive dy = wheel up, positive dx = right. May be fractional. */
  | { type: "wheel"; dx: number; dy: number; x: number; y: number }
  /** code / key are KeyboardEvent.code / KeyboardEvent.key. */
  | { type: "key"; code: string; key: string; down: boolean }
  /** Release everything held; send on blur / tab switch. */
  | { type: "release_all" }
  | { type: "clipboard"; text: string }
  | { type: "resize"; width: number; height: number }
  | { type: "refresh" }
  | { type: "close" };

export interface ConnectArgs {
  id: string;
  /** null = use the password saved in the keychain. */
  password: string | null;
  /** Save `password` in the keychain when the sign-in succeeds. */
  save_password: boolean;
  /** Initial remote desktop size in physical pixels (RDP honours it; VNC ignores it). */
  width: number;
  height: number;
  /** Percent: 100 = 1x, 200 = Retina. */
  scale_factor: number;
  /** Forget the pinned identity and pin whatever the server presents now. */
  trust_new_identity: boolean;
}

export interface AppInfo {
  version: string;
  os: string;
  arch: string;
  log_path: string;
}

export type ChannelMessage = SessionEvent | ArrayBuffer;

export const api = {
  listConnections: () => invoke<Connection[]>("list_connections"),
  saveConnection: (connection: Connection) => invoke<Connection>("save_connection", { connection }),
  deleteConnection: (id: string) => invoke<void>("delete_connection", { id }),
  hasSavedPassword: (id: string) => invoke<boolean>("has_saved_password", { id }),
  forgetPassword: (id: string) => invoke<void>("forget_password", { id }),
  /**
   * Start a session. Resolves with a session id once the session task is running; everything
   * after that (including failures) arrives on the channel, ending with a "closed" event.
   * Rejects with a SessionError only for immediate problems such as kind "password_required".
   */
  connect: (args: ConnectArgs, onMessage: (message: ChannelMessage) => void) => {
    const events = new Channel<ChannelMessage>();
    events.onmessage = onMessage;
    return invoke<string>("connect", { args, events });
  },
  sendInput: (sessionId: string, input: SessionInput) => invoke<void>("send_input", { sessionId, input }),
  disconnect: (sessionId: string) => invoke<void>("disconnect", { sessionId }),
  appInfo: () => invoke<AppInfo>("app_info"),
  /** The last part of the log (credentials are never logged). */
  logText: () => invoke<string>("log_text"),
  /** Show the log file in Finder / Explorer / the file manager. */
  revealLog: () => invoke<void>("reveal_log"),
};
