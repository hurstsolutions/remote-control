// Shared app state: the saved connections, plus small helpers about connections.
import type { Connection, Protocol } from "./ipc";
import type { Api } from "./platform";

export const DEFAULT_PORT: Record<Protocol, number> = { rdp: 3389, vnc: 5900 };
export const DEFAULT_SSH_PORT = 22;

export function protocolLabel(protocol: Protocol): string {
  return protocol === "rdp" ? "Windows" : "Mac";
}

export function blankConnection(protocol: Protocol = "rdp"): Connection {
  return {
    id: "",
    name: "",
    protocol,
    host: "",
    port: DEFAULT_PORT[protocol],
    username: "",
    domain: "",
    nla: true,
    ssh_tunnel: true,
    ssh_port: DEFAULT_SSH_PORT,
    pinned_identity: null,
    share_clipboard: true,
  };
}

/** "host" or "host:port" when the port is not the default for the protocol. */
export function hostLabel(connection: Connection): string {
  return connection.port === DEFAULT_PORT[connection.protocol]
    ? connection.host
    : `${connection.host}:${connection.port}`;
}

/**
 * The pinned identity belongs to one machine. When an edit points the connection somewhere
 * else, drop it so the next connect pins the new machine instead of raising a false alarm.
 */
export function pinnedIdentityAfterEdit(before: Connection | null, after: Connection): string | null {
  if (!before) return null;
  const sameTarget =
    before.protocol === after.protocol &&
    before.host.trim().toLowerCase() === after.host.trim().toLowerCase() &&
    before.port === after.port &&
    before.ssh_tunnel === after.ssh_tunnel &&
    (!after.ssh_tunnel || before.ssh_port === after.ssh_port);
  return sameTarget ? before.pinned_identity : null;
}

/** Whether saving `after` over `before` removes the saved password (kept in step with lib.rs). */
export function passwordClearedByEdit(before: Connection | null, after: Connection): boolean {
  if (!before) return false;
  const sameAccount = before.username.trim() === after.username.trim() && before.domain.trim().toLowerCase() === after.domain.trim().toLowerCase();
  return pinnedIdentityAfterEdit({ ...before, pinned_identity: "x" }, after) === null || !sameAccount;
}

type Listener = () => void;

/** The saved connections, reloaded from the backend after every change. */
export class ConnectionStore {
  connections: Connection[] = [];
  loadError: string | null = null;
  private readonly listeners = new Set<Listener>();

  constructor(private readonly api: Api) {}

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  get(id: string): Connection | undefined {
    return this.connections.find((c) => c.id === id);
  }

  async reload(): Promise<void> {
    try {
      this.connections = await this.api.listConnections();
      this.loadError = null;
    } catch (error) {
      this.loadError = typeof error === "string" ? error : error instanceof Error ? error.message : JSON.stringify(error);
    }
    for (const listener of this.listeners) listener();
  }
}
