// Validation for the connection editor. Pure: no DOM.
import type { Protocol } from "../ipc";

export interface EditorValues {
  name: string;
  protocol: Protocol;
  host: string;
  port: string;
  username: string;
  sshTunnel: boolean;
  sshPort: string;
}

export type EditorField = "name" | "host" | "port" | "username" | "sshPort";

export function parsePort(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,5}$/.test(trimmed)) return null;
  const port = Number(trimmed);
  return port >= 1 && port <= 65535 ? port : null;
}

/** Field -> message for every invalid field; empty when the form can be saved. */
export function validateEditor(values: EditorValues): Partial<Record<EditorField, string>> {
  const errors: Partial<Record<EditorField, string>> = {};
  if (values.name.trim() === "") errors.name = "Give the connection a name.";
  const host = values.host.trim();
  if (host === "") errors.host = "Enter the computer's name or IP address.";
  else if (/[\s/]/.test(host)) errors.host = "Enter only the name or IP address, without spaces or slashes.";
  if (parsePort(values.port) === null) errors.port = "Enter a port from 1 to 65535.";
  if (values.username.trim() === "") errors.username = "Enter the username you sign in with.";
  if (values.protocol === "vnc" && values.sshTunnel && parsePort(values.sshPort) === null) {
    errors.sshPort = "Enter a port from 1 to 65535.";
  }
  return errors;
}
