// Plain-language text for session errors. Pure: no DOM.
import type { Connection, ErrorKind, IdentityMismatch, SessionError } from "./ipc";

export interface ErrorText {
  headline: string;
  hints: string[];
}

type Target = Pick<Connection, "host" | "protocol" | "ssh_tunnel" | "name"> &
  Partial<Pick<Connection, "allow_older_mac_sign_in" | "srp_seen">>;

const KINDS: readonly ErrorKind[] = [
  "unreachable",
  "tunnel_unavailable",
  "auth_failed",
  "unsupported",
  "security",
  "no_verified_sign_in",
  "identity_changed",
  "protocol",
  "disconnected",
  "other",
  "password_required",
];

/** What connecting to a Mac without SSH means, for the editor and the "Connect without SSH" confirmation. */
export const DIRECT_MAC_SUMMARY =
  "Without SSH, Screen Sharing encrypts the session itself, and the app won't connect unencrypted. It also requires Apple's verified sign-in, which proves it's really your Mac; a Mac that doesn't offer it is refused unless you allow older Macs for this connection. SSH (Remote Login) is the most thoroughly protected option.";
/** The editor's warning next to "Allow older Macs without verified sign-in". */
export const OLDER_MAC_WARNING =
  "Only for an older Mac on a network you trust. Without verified sign-in, someone intercepting the network could pretend to be the Mac and capture your password.";
/** The editor's note when the setting is on but this Mac has used verified sign-in before. */
export const OLDER_MAC_IGNORED =
  "This Mac has used verified sign-in before, so the app will not fall back to the older sign-in for it, even with this setting on.";
/** The risk of an encrypted but unverified Mac session (Apple's older sign-in). */
export const DIRECT_MAC_RISK =
  "This Mac's sign-in can't prove it is really your Mac: someone actively intercepting the connection could impersonate it and capture your password.";
/** How to get full protection for a Mac. */
export const DIRECT_MAC_FIX =
  'For full protection, turn on Remote Login on the Mac (System Settings > General > Sharing > Remote Login) and turn on "Secure with SSH tunnel" for this connection.';
const USE_SSH_HINT =
  "On the Mac, turn on Remote Login (System Settings > General > Sharing > Remote Login), then click Use SSH tunnel.";

/** Which encryption problem a VNC "security" error is, from rc-vnc's detail text. */
export type VncSecurityProblem = "downgrade" | "integrity" | "not_encrypted";

export function vncSecurityProblem(detail: string): VncSecurityProblem | null {
  if (/refused while encryption is required|are refused when a username is set/i.test(detail)) return "downgrade";
  if (/encrypted session failed|integrity check/i.test(detail)) return "integrity";
  if (/could not be encrypted/i.test(detail)) return "not_encrypted";
  return null;
}

/** Kind "no_verified_sign_in": the Mac didn't offer Apple's verified sign-in. */
function noVerifiedSignInText(host: string, target: Target): ErrorText {
  const hints = [
    "The app requires Apple's verified sign-in for Screen Sharing without SSH, because it proves it's really your Mac. Your password was not sent.",
    "Either someone on the network is interfering with the connection, or this is an older Mac, or a Mac with that sign-in turned off.",
  ];
  if (target.srp_seen) {
    hints.push(
      "This Mac used verified sign-in before, so a sudden change is suspicious. Don't connect without SSH until you know why.",
      USE_SSH_HINT,
    );
    if (target.allow_older_mac_sign_in) {
      hints.push('"Allow older Macs without verified sign-in" is on for this connection, but it is ignored for a Mac that used verified sign-in before.');
    }
  } else {
    hints.push(
      `The safe option: ${USE_SSH_HINT}`,
      'Only if you trust this network: edit the connection and tick "Allow older Macs without verified sign-in". Someone intercepting the network could then capture your password.',
    );
  }
  return { headline: `${host} didn't offer verified sign-in`, hints };
}

function vncSecurityText(problem: VncSecurityProblem, host: string): ErrorText {
  switch (problem) {
    case "not_encrypted":
      return {
        headline: `Couldn't encrypt the session with ${host}`,
        hints: [
          "Without SSH, this app connects to a Mac only if Screen Sharing encrypts the session, and that could not be set up, so the session was not started.",
          USE_SSH_HINT,
          "Check that the address is a Mac with Screen Sharing turned on. Other VNC servers can't encrypt the session.",
        ],
      };
    case "downgrade":
      return {
        headline: `${host} offered only an unencrypted connection`,
        hints: [
          "The app refused to connect, because the session would not have been encrypted. Either this is not a Mac with Screen Sharing, or someone on the network is tampering with the connection.",
          USE_SSH_HINT,
        ],
      };
    case "integrity":
      return {
        headline: `The encrypted connection to ${host} was broken`,
        hints: [
          "Data arrived damaged or altered, so the session was closed to protect it. A network fault can cause this, and so can someone tampering with the connection.",
          "Reconnect. If it keeps happening, turn on Remote Login on the Mac and use the SSH tunnel.",
        ],
      };
  }
}

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
          "For the best protection: on the Mac, turn on Remote Login (System Settings > General > Sharing > Remote Login), then click Reconnect.",
          "Or click Connect without SSH to use Screen Sharing directly. The session is still encrypted, and the app requires Apple's verified sign-in, which newer Macs offer.",
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
    case "security": {
      const problem = windows ? null : vncSecurityProblem(error.detail);
      if (problem) return vncSecurityText(problem, host);
      return {
        headline: `Couldn't set up a secure connection to ${host}`,
        hints: [
          windows
            ? "The encrypted (TLS) connection to the PC failed, or the PC's certificate could not be used. Your password was not sent."
            : "The secure connection to the Mac failed. Your password was not sent.",
          "Reconnecting may help if the network was interrupted. If it keeps happening, copy the log and send it along.",
        ],
      };
    }
    case "no_verified_sign_in":
      return noVerifiedSignInText(host, target);
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

/**
 * The note to show in the password prompt for a "password_required" error: the backend's reason
 * when a saved password was refused or unreadable, nothing for the plain "none saved" case.
 */
export function passwordRequiredNote(error: SessionError): string | null {
  return /keychain|removed/i.test(error.detail) ? error.detail : null;
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
