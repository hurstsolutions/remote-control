// What the session toolbar's lock shows, from the backend's "security" events. Pure: no DOM.
import { DIRECT_MAC_FIX, DIRECT_MAC_RISK } from "./errors";

/** One "security" event: how one layer of the connection is protected. */
export interface SecurityLayer {
  encrypted: boolean;
  server_verified: boolean;
  method: string;
}

/** Method names the backends send (app/src-tauri, rc-rdp, rc-vnc). */
export const METHOD_SSH = "SSH tunnel";
export const METHOD_APPLE = "Apple Screen Sharing encryption";

export type LockLevel = "verified" | "unverified" | "none";

export interface LockState {
  level: LockLevel;
  /** Toolbar text. */
  label: string;
  /** One line for the toolbar tooltip. */
  tooltip: string;
  /** Details dialog. */
  headline: string;
  /** The layer that protects the session. */
  method: string;
  paragraphs: string[];
}

function rank(layer: SecurityLayer): number {
  if (!layer.encrypted) return 0;
  return layer.server_verified ? 2 : 1;
}

/** The layer that protects the session: verified and encrypted beats encrypted beats neither. */
export function bestLayer(layers: readonly SecurityLayer[]): SecurityLayer | null {
  let best: SecurityLayer | null = null;
  for (const layer of layers) {
    if (!best || rank(layer) > rank(best)) best = layer;
  }
  return best;
}

/** The identity is checked against a pin saved on first use (SSH host key, TLS certificate). */
function pinsIdentity(method: string): boolean {
  return method === METHOD_SSH || method.startsWith("TLS");
}

function isAppleEncryption(method: string): boolean {
  return method.startsWith(METHOD_APPLE);
}

/** The lock for a session's layers, or null before the backend reported any. */
export function lockState(layers: readonly SecurityLayer[]): LockState | null {
  const best = bestLayer(layers);
  if (!best) return null;
  const method = best.method;
  if (!best.encrypted) {
    return {
      level: "none",
      label: "Not encrypted",
      tooltip: "Not encrypted: anyone on the network can see the screen and what you type.",
      headline: "This session is not encrypted",
      method,
      paragraphs: ["Anyone on the network can see the screen and everything you type."],
    };
  }
  if (best.server_verified) {
    let paragraph: string;
    if (method === METHOD_SSH) {
      paragraph = "The session travels inside an encrypted SSH connection, and the Mac's SSH host key matches the one saved the first time you connected.";
    } else if (pinsIdentity(method)) {
      paragraph = "The session is encrypted, and the PC's certificate matches the one saved the first time you connected.";
    } else if (isAppleEncryption(method)) {
      paragraph = "Screen Sharing encrypts the session, and the Mac proved it knows your account password (Apple's SRP sign-in), so this is the right Mac.";
    } else {
      paragraph = "The session is encrypted, and the computer proved its identity.";
    }
    return {
      level: "verified",
      label: "Encrypted",
      tooltip: "Encrypted, and the computer's identity is verified.",
      headline: "Encrypted and verified",
      method,
      paragraphs: [paragraph],
    };
  }
  if (pinsIdentity(method)) {
    return {
      level: "unverified",
      label: "Encrypted",
      tooltip: "Encrypted. First connection: the computer's identity was saved, but there was nothing to check it against yet.",
      headline: "Encrypted, first connection",
      method,
      paragraphs: [
        "The session is encrypted. This is the first connection to this computer, so there was nothing to check its identity against. It has now been saved, and you will be warned before signing in if it ever changes.",
        "To be sure you reached the right computer, compare the identity below with the one shown on it.",
      ],
    };
  }
  return {
    level: "unverified",
    label: "Encrypted",
    tooltip: "Encrypted, but the Mac's identity is not verified. Click for details.",
    headline: "Encrypted, but the Mac is not verified",
    method,
    paragraphs: [
      "The session is encrypted, so someone just listening on the network cannot see it.",
      DIRECT_MAC_RISK,
      DIRECT_MAC_FIX,
    ],
  };
}
