// Plain-language text for session errors. Pure: no DOM.
import type { Connection, ErrorKind, IdentityMismatch, SessionError } from "./ipc";

export interface ErrorText {
  headline: string;
  hints: string[];
}

type Target = Pick<Connection, "host" | "protocol" | "ssh_tunnel" | "name">;

const KINDS: readonly ErrorKind[] = [
  "unreachable",
  "tunnel_unavailable",
  "auth_failed",
  "unsupported",
  "security",
  "identity_changed",
  "protocol",
  "disconnected",
  "other",
  "password_required",
];

/** The headline and hints to show for an error on a given connection. */
export function describeError(error: SessionError, target: Target): ErrorText {
  const windows = target.protocol === "rdp";
  const host = target.host || target.name || "the computer";
  switch (error.kind) {
    case "unreachable":
      return {
        headline: `Can't reach ${host}`,
        hints: [
          "Check that the computer is turned on and awake.",
          "Check that this computer and the remote one are on the same network, or that the VPN is connected.",
          windows
            ? "On the Windows PC, check that Remote Desktop is turned on (Settings > System > Remote Desktop)."
            : target.ssh_tunnel
              ? "On the Mac, check that Screen Sharing and Remote Login are both turned on (System Settings > General > Sharing)."
              : "On the Mac, check that Screen Sharing is turned on (System Settings > General > Sharing).",
          "Check the address and port in the connection settings.",
        ],
      };
    case "tunnel_unavailable":
      return {
        headline: `Remote Login is off on ${host}`,
        hints: [
          "This app sends Screen Sharing through an encrypted SSH connection to the Mac (Remote Login), and the Mac refused or did not answer it. That usually means Remote Login is turned off.",
          "To keep the whole session encrypted: on the Mac, turn on Remote Login (System Settings > General > Sharing > Remote Login), then click Reconnect.",
          "Or click Connect without SSH to use Screen Sharing directly. Your password is still protected by Apple's sign-in, but the screen and what you type travel unencrypted on the network.",
          "If Remote Login is already on, check that the Mac is awake and on the same network.",
        ],
      };
    case "auth_failed":
      return {
        headline: "Wrong username or password",
        hints: [
          `${host} did not accept the sign-in. Check the username, then enter the password again.`,
          windows
            ? "For a Microsoft account use the full email address as the username. For a work PC you may need to fill in the domain."
            : "Use the short account name and password of a user on the Mac who is allowed to use Screen Sharing.",
        ],
      };
    case "identity_changed":
      return {
        headline: `The identity of ${host} has changed`,
        hints: [
          "This computer is presenting a different identity from the one saved the first time you connected. Your password was not sent.",
          "That is expected after it was reinstalled, replaced or had its certificate renewed. If none of that happened, someone could be intercepting the connection: do not continue.",
          "Before trusting it, compare the new identity below with the one shown on the computer itself.",
        ],
      };
    case "security":
      return {
        headline: `Couldn't set up a secure connection to ${host}`,
        hints: [
          windows
            ? "The encrypted (TLS) connection to the PC failed, or the PC's certificate could not be used. Your password was not sent."
            : "The secure connection to the Mac failed. Your password was not sent.",
          "Reconnecting may help if the network was interrupted. If it keeps happening, copy the log and send it along.",
        ],
      };
    case "unsupported":
      return {
        headline: `${host} needs something this app does not support`,
        hints: [
          windows
            ? "The PC asked for a sign-in method or security setting this app cannot use. If it requires Network Level Authentication, turn that on in the connection settings (and off if it does not offer it)."
            : "The Mac offered only sign-in methods this app cannot use. Check that Screen Sharing (not only Remote Management with restricted options) is turned on.",
        ],
      };
    case "protocol":
      return {
        headline: "The connection failed unexpectedly",
        hints: [
          "The two computers could not understand each other. Reconnecting often works.",
          "If it keeps happening, copy the log and send it along with what you were doing.",
        ],
      };
    case "disconnected":
      return {
        headline: "The connection was lost",
        hints: [
          "The remote computer may have gone to sleep, restarted, or the network dropped.",
          windows ? "Someone else signing in to the PC also ends your session." : "Reconnect to carry on where you left off.",
        ],
      };
    case "password_required":
      return {
        headline: "A password is needed",
        hints: ["Reconnect and enter the password for this computer."],
      };
    case "other":
    default:
      return {
        headline: "Something went wrong",
        hints: ["Try reconnecting. If it keeps happening, copy the log and send it along with what you were doing."],
      };
  }
}

/** Turn whatever a rejected call produced into a SessionError. */
export function toSessionError(value: unknown): SessionError {
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    const kind = record["kind"];
    if (typeof kind === "string" && (KINDS as readonly string[]).includes(kind)) {
      const detail = record["detail"];
      const error: SessionError = { kind: kind as ErrorKind, detail: typeof detail === "string" ? detail : "" };
      const identity = identityOf(record["identity"]);
      if (identity) error.identity = identity;
      return error;
    }
    if (value instanceof Error) return { kind: "other", detail: value.message };
    try {
      return { kind: "other", detail: JSON.stringify(value) };
    } catch {
      return { kind: "other", detail: String(value) };
    }
  }
  return { kind: "other", detail: value === undefined || value === null ? "" : String(value) };
}

function identityOf(value: unknown): IdentityMismatch | null {
  if (typeof value !== "object" || value === null) return null;
  const r = value as Record<string, unknown>;
  const kind = r["identity_kind"];
  const expected = r["expected_sha256"];
  const received = r["received_sha256"];
  if ((kind !== "tls_certificate" && kind !== "ssh_host_key") || typeof expected !== "string" || typeof received !== "string") {
    return null;
  }
  return { identity_kind: kind, expected_sha256: expected, received_sha256: received };
}

/** A short message for a failed non-session call (saving, deleting, log actions). */
export function messageOf(value: unknown): string {
  if (typeof value === "string") return value;
  return toSessionError(value).detail || "Unknown error";
}
