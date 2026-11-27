// The Tailscale tab: the devices in the user's tailnet, read from the Tailscale client signed in
// on this computer. Every device string was chosen by another tailnet member: it is cleaned and
// shown with textContent only, and never put in an attribute other than title.
import { button, h } from "../dom";
import { messageOf } from "../errors";
import type { TailscaleDevice, TailscaleStatus } from "../ipc";
import type { Platform } from "../platform";
import { pollWhileVisible } from "../poll";
import type { ConnectionStore } from "../state";
import { openEditor } from "./editor";
import { hiddenToggleLabel } from "./find-logic";
import {
  MAX_DNS_CHARS,
  REFRESH_MS,
  cleanDnsName,
  cleanIpv4,
  cleanText,
  displayTags,
  groupDevices,
  hostChoices,
  lastSeenText,
  osKind,
  osLabel,
  prefillFromDevice,
  savedForDevice,
  unavailableText,
} from "./tailscale-logic";

export interface TailscaleHost {
  platform: Platform;
  store: ConnectionStore;
  back(): void;
}

export class TailscaleView {
  readonly element: HTMLElement;
  private status: TailscaleStatus | null = null;
  /** Show devices that are not Windows PCs or Macs. Off whenever the view opens. */
  private showAll = false;
  private loading = false;

  private readonly refreshButton: HTMLButtonElement;
  private readonly problem: HTMLElement;
  private readonly summary: HTMLElement;
  private readonly unavailable: HTMLElement;
  private readonly tools: HTMLElement;
  private readonly showAllCheck: HTMLInputElement;
  private readonly showAllLabel: HTMLElement;
  private readonly groups: HTMLElement;

  constructor(private readonly host: TailscaleHost) {
    this.refreshButton = button("Refresh", () => void this.refresh(), { title: "Read the tailnet again" });
    this.problem = h("p", { class: "notice notice-error", attrs: { role: "alert" } });
    this.problem.hidden = true;
    this.summary = h("p", { class: "muted ts-summary", attrs: { role: "status", "aria-live": "polite" }, text: "Reading Tailscale..." });
    this.unavailable = h("div", { class: "empty ts-unavailable" });
    this.unavailable.hidden = true;
    this.showAllCheck = h("input", { attrs: { type: "checkbox" } });
    this.showAllCheck.checked = false;
    this.showAllCheck.addEventListener("change", () => {
      this.showAll = this.showAllCheck.checked;
      this.render();
    });
    this.showAllLabel = h("span", { text: hiddenToggleLabel(0) });
    this.tools = h("div", { class: "results-tools" }, h("label", { class: "check show-all" }, this.showAllCheck, this.showAllLabel));
    this.tools.hidden = true;
    this.groups = h("div", { class: "ts-groups" });

    this.element = h(
      "section",
      { class: "home find tailscale" },
      h(
        "header",
        { class: "home-header" },
        h("div", { class: "find-title" }, button("Back", () => host.back(), { kind: "quiet", title: "Back to connections" }), h("h1", { text: "Tailscale" })),
        this.refreshButton,
      ),
      h(
        "div",
        { class: "home-body find-body" },
        h("p", {
          class: "notice",
          text: "The devices in your tailnet, as the Tailscale app signed in on this computer sees them. Device names are chosen by whoever added each device.",
        }),
        this.problem,
        this.summary,
        this.unavailable,
        this.tools,
        this.groups,
      ),
    );
    host.store.subscribe(() => this.render());
    pollWhileVisible(this.element, REFRESH_MS, () => void this.refresh());
    void this.refresh();
  }

  /** Called when the tab is shown again: back to the default filter, with fresh data. */
  opened(): void {
    this.showAll = false;
    this.showAllCheck.checked = false;
    this.render();
    void this.refresh();
  }

  private async refresh(): Promise<void> {
    if (this.loading) return;
    this.loading = true;
    this.refreshButton.disabled = true;
    try {
      this.status = await this.host.platform.api.tailscaleStatus();
      this.problem.hidden = true;
    } catch (error) {
      this.problem.textContent = `Couldn't read Tailscale: ${messageOf(error)}`;
      this.problem.hidden = false;
    } finally {
      this.loading = false;
      this.refreshButton.disabled = false;
    }
    this.render();
  }

  private render(): void {
    const status = this.status;
    const problemText = status ? unavailableText(status) : null;
    this.unavailable.hidden = problemText === null;
    this.unavailable.replaceChildren();
    if (problemText) {
      this.unavailable.append(
        h("h2", { text: problemText.headline }),
        h("p", { text: problemText.next }),
        problemText.link ? h("p", { class: "selectable ts-link", text: problemText.link }) : "",
        button("Refresh", () => void this.refresh()),
      );
    }
    if (!status || !status.available) {
      this.summary.hidden = status !== null;
      this.tools.hidden = true;
      this.groups.replaceChildren();
      return;
    }
    const { online, offline, hidden } = groupDevices(status.devices, this.showAll);
    const tailnet = cleanText(status.tailnet, MAX_DNS_CHARS);
    this.summary.hidden = false;
    this.summary.textContent = tailnet ? `Tailnet ${tailnet}` : "Your tailnet";
    this.tools.hidden = false;
    this.showAllLabel.textContent = hiddenToggleLabel(this.showAll ? 0 : hidden);
    const now = Date.now();
    this.groups.replaceChildren(this.group("Online", online, now), this.group("Offline", offline, now));
    if (online.length === 0 && offline.length === 0) {
      this.groups.append(
        h("p", {
          class: "muted results-note",
          text: hidden > 0 ? "No Windows PCs or Macs in your tailnet. Tick “Show all devices” to see the others." : "No other devices in your tailnet.",
        }),
      );
    }
  }

  private group(title: string, devices: TailscaleDevice[], now: number): HTMLElement | string {
    if (devices.length === 0) return "";
    return h(
      "div",
      { class: "ts-group" },
      h("h2", { class: "ts-group-title", text: `${title} (${devices.length})` }),
      h("div", { class: "connection-list", attrs: { role: "list", "aria-label": `${title} devices` } }, ...devices.map((d) => this.row(d, now))),
    );
  }

  private row(device: TailscaleDevice, now: number): HTMLElement {
    const name = cleanText(device.name);
    const fullName = cleanText(device.name, 256);
    const suffix = this.status?.magicDnsSuffix;
    const dns = cleanDnsName(device.dnsName, suffix);
    const ip = cleanIpv4(device.ipv4);
    const kind = osKind(device.os);
    const saved = savedForDevice(device, this.host.store.connections, suffix);
    const details = [cleanText(dns, MAX_DNS_CHARS), ip].filter(Boolean);
    const seen = device.online ? null : lastSeenText(device, now);
    const tags = displayTags(device);

    const nameLine = h("div", { class: "row-name" }, h("span", { class: "selectable", text: name || "(no name)" }));
    if (saved.length > 0) {
      nameLine.append(
        " ",
        h("span", {
          class: "saved-tag",
          text: saved.length === 1 ? `Saved: ${saved[0]?.name ?? ""}` : `Saved (${saved.length})`,
          title: saved.map((c) => c.name).join(", "),
        }),
      );
    }
    const canAdd = dns !== "" || ip !== "";
    const row = h(
      "div",
      { class: "connection-row ts-row", attrs: { role: "listitem" } },
      h("span", { class: `badge ts-os ts-os-${kind}`, text: osLabel(device.os) }),
      h(
        "div",
        { class: "row-main" },
        nameLine,
        details.length > 0 ? h("div", { class: "row-detail selectable", text: details.join(" · ") }) : null,
        seen || tags.length > 0
          ? h("div", { class: "row-detail" }, seen ? h("span", { text: seen }) : null, ...tags.map((t) => h("span", { class: "service-tag ts-tag", text: t, title: "A Tailscale tag (information only)" })))
          : null,
      ),
      h(
        "div",
        { class: "row-actions" },
        canAdd ? button("Add connection", () => void this.add(device), { kind: saved.length > 0 ? "default" : "primary" }) : null,
      ),
    );
    // Device data goes in no attribute but the tooltip.
    if (fullName !== name) row.title = fullName;
    return row;
  }

  private async add(device: TailscaleDevice): Promise<void> {
    const suffix = this.status?.magicDnsSuffix;
    const template = prefillFromDevice(device, this.host.store.connections, suffix);
    const saved = await openEditor(this.host.platform, null, template, { tailscaleHosts: hostChoices(device, suffix) });
    if (saved) await this.host.store.reload();
  }
}
