// The home screen: the list of saved connections and the footer with the log actions.
import { confirmDialog } from "../dialog";
import { button, h } from "../dom";
import { messageOf } from "../errors";
import type { Connection, TailscaleStatus } from "../ipc";
import { copyLogButton, showLogFileButton } from "../logs";
import type { Platform } from "../platform";
import { pollWhileVisible } from "../poll";
import { hostLabel, protocolLabel, type ConnectionStore } from "../state";
import { PASSWORD_CLEARED_NOTE, openEditor } from "./editor";
import { FindView } from "./find";
import { TailscaleView } from "./tailscale";
import { REFRESH_MS, deviceForConnection, presenceTooltip } from "./tailscale-logic";

type Page = "list" | "find" | "tailscale";

export interface HomeHost {
  platform: Platform;
  store: ConnectionStore;
  connect(connection: Connection): void;
  /** Close any open session tabs of a connection that is being deleted. */
  closeSessionsFor(connectionId: string): void;
}

export class HomeView {
  /** Holds the connection list and, once opened, "Find computers". */
  readonly element: HTMLElement;
  private readonly listPage: HTMLElement;
  private find: FindView | null = null;
  private tailscale: TailscaleView | null = null;
  /** The last tailnet read, for the online dots; null when Tailscale is unavailable. */
  private tailnet: TailscaleStatus | null = null;
  /** Each row's dot slot, by connection id (rebuilt with the list). */
  private dotSlots = new Map<string, HTMLElement>();
  private readonly list: HTMLElement;
  private readonly problem: HTMLElement;
  private readonly info: HTMLElement;
  private readonly version: HTMLElement;

  constructor(private readonly host: HomeHost) {
    this.list = h("div", { class: "connection-list", attrs: { role: "list" } });
    this.problem = h("p", { class: "notice notice-error", attrs: { role: "alert" } });
    this.problem.hidden = true;
    this.info = h("p", { class: "notice notice-warn", attrs: { role: "status", id: "home-info" } });
    this.info.hidden = true;
    this.version = h("span", { class: "muted selectable", text: "RemoteControl" });
    this.listPage = h(
      "section",
      { class: "home" },
      h(
        "header",
        { class: "home-header" },
        h("h1", { text: "Connections" }),
        h(
          "div",
          { class: "row-actions" },
          button("Tailscale", () => this.show("tailscale"), { title: "Windows PCs and Macs in your tailnet" }),
          button("Find computers", () => this.show("find"), { title: "Scan your subnets for Windows PCs and Macs" }),
          button("Add connection", () => void this.edit(null), { kind: "primary" }),
        ),
      ),
      h("div", { class: "home-body" }, this.problem, this.info, this.list),
      h(
        "footer",
        { class: "home-footer" },
        this.version,
        h("span", { class: "spacer" }),
        copyLogButton(host.platform),
        showLogFileButton(host.platform),
      ),
    );
    this.element = h("div", { class: "home-stack" }, this.listPage);
    host.store.subscribe(() => this.render());
    this.render();
    void this.refreshTailnet();
    pollWhileVisible(this.listPage, REFRESH_MS, () => void this.refreshTailnet());
    host.platform.api.appInfo().then(
      (info) => {
        this.version.textContent = `RemoteControl ${info.version} (${info.os} ${info.arch})`;
        this.version.title = info.log_path ? `Log file: ${info.log_path}` : "";
      },
      (error: unknown) => console.error("app_info failed", error),
    );
  }

  private show(page: Page): void {
    const back = () => this.show("list");
    if (page === "find" && !this.find) {
      this.find = new FindView({ platform: this.host.platform, store: this.host.store, back });
      this.element.append(this.find.element);
    }
    const reopen = page === "tailscale" && this.tailscale !== null;
    if (page === "tailscale" && !this.tailscale) {
      this.tailscale = new TailscaleView({ platform: this.host.platform, store: this.host.store, back });
      this.element.append(this.tailscale.element);
    }
    if (this.find) this.find.element.hidden = page !== "find";
    if (this.tailscale) this.tailscale.element.hidden = page !== "tailscale";
    this.listPage.hidden = page !== "list";
    if (reopen) this.tailscale?.opened();
    if (page === "list") void this.refreshTailnet();
  }

  /** Read the tailnet for the online dots. Unavailable or failing: no dots, nothing said. */
  private async refreshTailnet(): Promise<void> {
    try {
      const status = await this.host.platform.api.tailscaleStatus();
      this.tailnet = status.available ? status : null;
    } catch {
      this.tailnet = null;
    }
    this.renderDots();
  }

  /** Dots only for saved hosts that are a tailnet device's IPv4 or MagicDNS name. */
  private renderDots(): void {
    const devices = this.tailnet?.devices ?? [];
    const now = Date.now();
    for (const connection of this.host.store.connections) {
      const slot = this.dotSlots.get(connection.id);
      if (!slot) continue;
      const device = deviceForConnection(connection, devices);
      if (!device) {
        slot.replaceChildren();
        continue;
      }
      const tooltip = presenceTooltip(device, now);
      slot.replaceChildren(
        h("span", { class: `ts-dot ${device.online ? "ts-dot-online" : "ts-dot-offline"}`, title: tooltip, attrs: { "aria-hidden": "true" } }),
        h("span", { class: "visually-hidden", text: tooltip }),
      );
    }
  }

  private showProblem(message: string | null): void {
    this.problem.textContent = message ?? "";
    this.problem.hidden = message === null;
  }

  private render(): void {
    const { connections, loadError } = this.host.store;
    this.showProblem(loadError ? `Couldn't load the saved connections: ${loadError}` : null);
    this.list.replaceChildren();
    if (connections.length === 0) {
      if (loadError) return;
      this.list.append(
        h(
          "div",
          { class: "empty" },
          h("h2", { text: "No connections yet" }),
          h("p", {
            text: "Add a Windows PC to control it with Remote Desktop, or a Mac to control it with Screen Sharing. You need its name or IP address and the username you sign in with there.",
          }),
          h(
            "div",
            { class: "row-actions" },
            button("Add connection", () => void this.edit(null), { kind: "primary" }),
            button("Find computers", () => this.show("find")),
            button("Tailscale", () => this.show("tailscale")),
          ),
        ),
      );
      return;
    }
    this.dotSlots = new Map();
    for (const connection of connections) this.list.append(this.row(connection));
    this.renderDots();
  }

  private row(connection: Connection): HTMLElement {
    const connect = () => this.host.connect(connection);
    const dot = h("span", { class: "ts-dot-slot" });
    this.dotSlots.set(connection.id, dot);
    const actions = h(
      "div",
      { class: "row-actions" },
      button("Connect", connect, { kind: "primary" }),
      button("Edit", () => void this.edit(connection.id)),
      button("Delete", () => void this.remove(connection), { kind: "quiet" }),
    );
    const row = h(
      "div",
      {
        class: "connection-row",
        attrs: { role: "listitem", tabindex: "0", "aria-label": `${connection.name}, ${protocolLabel(connection.protocol)}, ${connection.host}` },
      },
      h("span", { class: `badge badge-${connection.protocol}`, text: protocolLabel(connection.protocol) }),
      h(
        "div",
        { class: "row-main" },
        h("div", { class: "row-name" }, dot, h("span", { text: connection.name })),
        h("div", { class: "row-detail", text: `${connection.username} at ${hostLabel(connection)}` }),
      ),
      actions,
    );
    row.addEventListener("dblclick", (event) => {
      if (!(event.target instanceof Element) || !event.target.closest("button")) connect();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && event.target === row) {
        event.preventDefault();
        connect();
      }
    });
    return row;
  }

  /** Add (id null) or edit. The list is reloaded first so the editor starts from fresh data. */
  private async edit(id: string | null): Promise<void> {
    let existing: Connection | null = null;
    if (id !== null) {
      await this.host.store.reload();
      existing = this.host.store.get(id) ?? null;
      if (!existing) return;
    }
    const saved = await openEditor(this.host.platform, existing);
    if (!saved) return;
    this.info.hidden = !saved.password_cleared;
    this.info.textContent = saved.password_cleared ? `${saved.connection.name}: ${PASSWORD_CLEARED_NOTE}` : "";
    await this.host.store.reload();
  }

  private async remove(connection: Connection): Promise<void> {
    const confirmed = await confirmDialog({
      title: `Delete "${connection.name}"?`,
      message: "The connection and its saved password are removed from this computer. The remote computer is not changed.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    this.host.closeSessionsFor(connection.id);
    try {
      await this.host.platform.api.deleteConnection(connection.id);
      await this.host.store.reload();
    } catch (error) {
      await this.host.store.reload();
      this.showProblem(`Couldn't delete "${connection.name}": ${messageOf(error)}`);
    }
  }
}
