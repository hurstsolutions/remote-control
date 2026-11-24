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
  /**
   * SHA-256 (lowercase hex) of the server identity pinned after the first successful sign-in
   * (TLS certificate or SSH host key). The backend ignores what the UI sends here.
   */
  pinned_identity: string | null;
  /** Pass clipboard text both ways during a session. Default true. */
  share_clipboard: boolean;
  /**
   * VNC without the SSH tunnel only: let a Mac that does not offer Apple's verified (SRP) sign-in
   * sign in the older way (encrypted, but the Mac is not verified). Default false.
   */
  allow_older_mac_sign_in: boolean;
  /**
   * This Mac has signed in with SRP before, so allow_older_mac_sign_in is ignored for it. Set by
   * the backend; it ignores what the UI sends and clears it when the address changes.
   */
  srp_seen: boolean;
}

/** What save_connection resolves with. */
export interface SavedConnection {
  connection: Connection;
  /** The saved password was removed because the address or the account changed. */
  password_cleared: boolean;
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
  /** A TLS or certificate problem other than a changed identity. No way to override it. */
  | "security"
  /**
   * Mac without the SSH tunnel: the Mac did not offer Apple's verified (SRP) sign-in, so the
   * older, unverified one was refused (someone interfering, or an older Mac). The password was
   * not sent. The connection's allow_older_mac_sign_in (ignored once srp_seen) lets it through.
   */
  | "no_verified_sign_in"
  /** The pinned identity no longer matches; `SessionError.identity` has both fingerprints. */
  | "identity_changed"
  | "protocol"
  | "disconnected"
  | "other"
  /** No password was supplied and none is saved: ask the user, then call connect again. */
  | "password_required";

export type IdentityKind = "tls_certificate" | "ssh_host_key";

export interface IdentityMismatch {
  identity_kind: IdentityKind;
  /** Lowercase hex SHA-256: the pinned identity. */
  expected_sha256: string;
  /** Lowercase hex SHA-256: what the server presented this time. */
  received_sha256: string;
}

export interface SessionError {
  kind: ErrorKind;
  detail: string;
  /** Only with kind "identity_changed". */
  identity?: IdentityMismatch;
}

/** JSON events delivered on the session channel. Frames arrive separately as ArrayBuffers. */
export type SessionEvent =
  | { type: "status"; text: string }
  | { type: "identity"; sha256: string }
  /**
   * How one layer of the connection is protected, before "connected". A session may send several
   * (a Mac through SSH: the tunnel, then VNC's own); the best layer protects the session.
   * `method` is a short label such as "TLS + NLA", "SSH tunnel" or "Apple Screen Sharing encryption".
   */
  | { type: "security"; encrypted: boolean; server_verified: boolean; method: string }
  | { type: "connected"; width: number; height: number; name: string }
  | { type: "resized"; width: number; height: number }
  | { type: "cursor"; kind: "default" | "hidden" }
  | { type: "cursor"; kind: "bitmap"; width: number; height: number; hot_x: number; hot_y: number; rgba_base64: string }
  | { type: "clipboard"; text: string }
  | { type: "bell" }
  /** Something the user should know that does not end the session (a password that could not be saved). */
  | { type: "notice"; text: string }
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
  /**
   * Replace the pinned identity with `new_identity` once the sign-in succeeds. Requires a typed
   * `password`: the saved one is never used (rejects with "password_required" otherwise).
   */
  trust_new_identity: boolean;
  /**
   * With trust_new_identity: the fingerprint the user reviewed (required; the backend refuses
   * to trust without it). Only that identity is accepted.
   */
  new_identity: string | null;
}

export interface AppInfo {
  version: string;
  os: string;
  arch: string;
  log_path: string;
}

export type ChannelMessage = SessionEvent | ArrayBuffer;

/** A saved subnet for "Find computers". The backend validates and normalizes it on save. */
export interface Subnet {
  /** Empty string when new; the backend assigns one. */
  id: string;
  /** IPv4 CIDR, e.g. "10.0.0.0/24". Nothing larger than a /16. */
  cidr: string;
  label: string;
  /** The user confirmed this public (non-private) range is their own network. Ignored for private ranges. */
  allow_public: boolean;
}

export type HostKind = "windows" | "mac" | "unknown";

/**
 * A machine found by a scan. Every string came from the network and is untrusted: show it as
 * text only. Nothing here is trusted for security (the certificate is pinned on first connect).
 */
export interface FoundHost {
  ip: string;
  /** The open port, or null when closed. */
  rdp: number | null;
  vnc: number | null;
  ssh: number | null;
  /** The best name found, if any. */
  name: string | null;
  names: {
    rdp_certificate: string | null;
    mdns_name: string | null;
    mdns_host: string | null;
    netbios: string | null;
    /** The computer name from the SMB server's NTLM challenge (DNS form when given, else NetBIOS). */
    smb: string | null;
    dns: string | null;
  };
  kind: HostKind;
  /** Information only. */
  rdp_certificate_sha256: string | null;
  rfb_version: string | null;
  ssh_banner: string | null;
  model: string | null;
}

export type ScanEvent =
  | { type: "progress"; done: number; total: number; found: number }
  | { type: "host"; host: FoundHost }
  /** `too_many`: the scan stopped itself because more machines answered than any real subnet has. */
  | { type: "finished"; cancelled: boolean; too_many: boolean; done: number; total: number; found: number };

export const api = {
  listConnections: () => invoke<Connection[]>("list_connections"),
  saveConnection: (connection: Connection) => invoke<SavedConnection>("save_connection", { connection }),
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
  listSubnets: () => invoke<Subnet[]>("list_subnets"),
  /** Replace the saved list. Resolves with it as saved (normalized), rejects with a message. */
  saveSubnets: (subnets: Subnet[]) => invoke<Subnet[]>("save_subnets", { subnets }),
  /**
   * Scan saved subnets (by id). Resolves with a scan id; progress and found machines arrive on
   * the channel, ending with a "finished" event. One scan at a time.
   */
  startScan: (subnetIds: string[], onEvent: (event: ScanEvent) => void) => {
    const events = new Channel<ScanEvent>();
    events.onmessage = onEvent;
    return invoke<string>("start_scan", { args: { subnet_ids: subnetIds }, events });
  },
  cancelScan: (scanId: string) => invoke<void>("cancel_scan", { scanId }),
  appInfo: () => invoke<AppInfo>("app_info"),
  /** The last part of the log (credentials are never logged). */
  logText: () => invoke<string>("log_text"),
  /** Show the log file in Finder / Explorer / the file manager. */
  revealLog: () => invoke<void>("reveal_log"),
};
