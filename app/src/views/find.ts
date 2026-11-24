// "Find computers": saved subnets, an on-demand scan of the chosen ones, and the machines found.
// Scan results come from the network: every string is shown with textContent only.
import { confirmDialog, openDialog } from "../dialog";
import { button, h } from "../dom";
import { messageOf } from "../errors";
import type { FoundHost, Protocol, ScanEvent, Subnet } from "../ipc";
import type { Platform } from "../platform";
import { protocolLabel, type ConnectionStore } from "../state";
import { openEditor } from "./editor";
import {
  addableProtocols,
  allNames,
  estimateDuration,
  filterHosts,
  hiddenToggleLabel,
  isComputer,
  nameMatchWarning,
  nameSource,
  nameOnlyMatches,
  parseCidr,
  prefillConnection,
  progressText,
  savedMatches,
  serviceLabels,
  sortHosts,
  upsertHost,
  withoutSubnets,
  type SortKey,
} from "./find-logic";

export interface FindHost {
  platform: Platform;
  store: ConnectionStore;
  back(): void;
}

/** Ask before scanning more addresses than this. */
const CONFIRM_ABOVE = 1024;
/** Found machines arriving during a scan are shown in batches, at most this often. */
const RENDER_BATCH_MS = 150;
export const TOO_MANY_MESSAGE =
  "The scan stopped: too many addresses answered. A proxy or firewall may be answering for every address, so these results don't show real computers.";
let fieldCounter = 0;

export class FindView {
  readonly element: HTMLElement;
  private subnets: Subnet[] = [];
  private readonly selected = new Set<string>();
  private hosts: FoundHost[] = [];
  private sortKey: SortKey = "ip";
  private ascending = true;
  private scanning = false;
  /** Show devices that are not Windows PCs or Macs. Off whenever the view opens. */
  private showAll = false;
  private scanId: string | null = null;
  /** Bumped per scan, so events of an earlier scan are ignored. */
  private generation = 0;
  /** A batched results render is pending. */
  private renderTimer = 0;
  /** Built rows, reused across renders; dropped when the saved connections change. */
  private rows = new WeakMap<FoundHost, HTMLElement>();

  private readonly problem: HTMLElement;
  private readonly subnetList: HTMLElement;
  private readonly scanButton: HTMLButtonElement;
  private readonly cancelButton: HTMLButtonElement;
  private readonly progress: HTMLProgressElement;
  private readonly status: HTMLElement;
  private readonly filter: HTMLInputElement;
  private readonly showAllCheck: HTMLInputElement;
  private readonly showAllLabel: HTMLElement;
  private readonly resultsBody: HTMLTableSectionElement;
  private readonly resultsNote: HTMLElement;
  private readonly sortButtons: Record<SortKey, HTMLButtonElement>;
  private readonly sortHeaders: Record<SortKey, HTMLElement>;

  constructor(private readonly host: FindHost) {
    this.problem = h("p", { class: "notice notice-error", attrs: { role: "alert" } });
    this.problem.hidden = true;
    this.subnetList = h("div", { class: "connection-list subnet-list", attrs: { role: "list", "aria-label": "Subnets" } });
    this.scanButton = button("Scan all", () => void this.scan(this.chosen()), { kind: "primary" });
    this.cancelButton = button("Cancel scan", () => void this.cancel());
    this.cancelButton.hidden = true;
    this.progress = h("progress", { class: "scan-progress", attrs: { max: "1", value: "0", "aria-label": "Scan progress" } });
    this.progress.hidden = true;
    this.status = h("span", { class: "muted scan-status", attrs: { role: "status", "aria-live": "polite" } });
    this.filter = h("input", {
      class: "input results-filter",
      attrs: { type: "search", placeholder: "Filter by address, name or service", "aria-label": "Filter results", spellcheck: "false" },
    });
    this.filter.addEventListener("input", () => this.renderResults());
    this.showAllCheck = h("input", { attrs: { type: "checkbox" } });
    this.showAllCheck.checked = false;
    this.showAllCheck.addEventListener("change", () => {
      this.showAll = this.showAllCheck.checked;
      this.renderResults();
    });
    this.showAllLabel = h("span", { text: hiddenToggleLabel(0) });
    this.resultsBody = h("tbody");
    this.resultsNote = h("p", { class: "muted results-note" });

    const sortButton = (key: SortKey, label: string) =>
      h("button", { class: "sort-button", text: label, attrs: { type: "button" }, on: { click: () => this.sortBy(key) } });
    this.sortButtons = { ip: sortButton("ip", "Address"), name: sortButton("name", "Name") };
    this.sortHeaders = {
      ip: h("th", { attrs: { scope: "col" } }, this.sortButtons.ip),
      name: h("th", { attrs: { scope: "col" } }, this.sortButtons.name),
    };

    this.element = h(
      "section",
      { class: "home find" },
      h(
        "header",
        { class: "home-header" },
        h("div", { class: "find-title" }, button("Back", () => host.back(), { kind: "quiet", title: "Back to connections" }), h("h1", { text: "Find computers" })),
        button("Add subnet", () => void this.editSubnet(null)),
      ),
      h(
        "div",
        { class: "home-body find-body" },
        h("p", {
          class: "notice",
          text:
            "Scanning checks each address in the chosen subnets for Remote Desktop (port 3389), Screen Sharing (5900) and Remote Login / SSH (22). " +
            "To find their names, it also asks the computers it finds for their file sharing (445), NetBIOS (137) and Bonjour (5353) names. " +
            "It never sends a username or password, but network security tools may notice it and flag it as a port scan. Only scan networks you are allowed to.",
        }),
        this.problem,
        this.subnetList,
        h("div", { class: "scan-bar" }, this.scanButton, this.cancelButton, this.progress, this.status),
        h("div", { class: "results-tools" }, this.filter, h("label", { class: "check show-all" }, this.showAllCheck, this.showAllLabel)),
        h(
          "table",
          { class: "results" },
          h(
            "thead",
            {},
            h(
              "tr",
              {},
              this.sortHeaders.ip,
              this.sortHeaders.name,
              h("th", { text: "Services", attrs: { scope: "col" } }),
              h("th", { text: "Saved", attrs: { scope: "col" } }),
              h("th", { attrs: { scope: "col" } }, h("span", { class: "visually-hidden", text: "Actions" })),
            ),
          ),
          this.resultsBody,
        ),
        this.resultsNote,
      ),
    );
    host.store.subscribe(() => {
      this.rows = new WeakMap();
      this.renderResults();
    });
    this.renderSort();
    this.renderResults();
    void this.loadSubnets();
  }

  private showProblem(message: string | null): void {
    this.problem.textContent = message ?? "";
    this.problem.hidden = message === null;
  }

  // ---- subnets ----------------------------------------------------------------------------

  private async loadSubnets(): Promise<void> {
    try {
      this.setSubnets(await this.host.platform.api.listSubnets(), true);
    } catch (error) {
      this.showProblem(`Couldn't load the saved subnets: ${messageOf(error)}`);
    }
  }

  /** Take a fresh list; new ids start selected when `selectNew`. */
  private setSubnets(list: Subnet[], selectNew: boolean, known: Set<string> = new Set(this.subnets.map((s) => s.id))): void {
    this.subnets = list;
    const ids = new Set(list.map((s) => s.id));
    for (const id of [...this.selected]) if (!ids.has(id)) this.selected.delete(id);
    if (selectNew) for (const s of list) if (!known.has(s.id)) this.selected.add(s.id);
    this.renderSubnets();
  }

  private renderSubnets(): void {
    this.subnetList.replaceChildren();
    if (this.subnets.length === 0) {
      this.subnetList.append(
        h(
          "div",
          { class: "empty" },
          h("h2", { text: "No subnets yet" }),
          h("p", { text: "Add the subnets (VLANs) your computers are on, such as 10.0.0.0/24, then scan them to find Windows PCs and Macs." }),
          button("Add subnet", () => void this.editSubnet(null), { kind: "primary" }),
        ),
      );
    }
    for (const subnet of this.subnets) this.subnetList.append(this.subnetRow(subnet));
    this.renderScanState();
  }

  private subnetRow(subnet: Subnet): HTMLElement {
    const parsed = parseCidr(subnet.cidr);
    const check = h("input", { attrs: { type: "checkbox", "aria-label": `Scan ${subnet.cidr}${subnet.label ? ` (${subnet.label})` : ""}` } });
    check.checked = this.selected.has(subnet.id);
    check.disabled = this.scanning;
    check.addEventListener("change", () => {
      if (check.checked) this.selected.add(subnet.id);
      else this.selected.delete(subnet.id);
      this.renderScanState();
    });
    const details: string[] = [];
    if (parsed.ok) {
      details.push(`${parsed.value.hostCount.toLocaleString("en-US")} addresses`);
      if (parsed.value.isLarge) details.push(`large: ${estimateDuration(parsed.value.hostCount)} to scan`);
      if (!parsed.value.isPrivate) details.push(subnet.allow_public ? "public range, confirmed as your network" : "public range, not confirmed");
    }
    return h(
      "div",
      { class: "connection-row subnet-row", attrs: { role: "listitem" } },
      check,
      h(
        "div",
        { class: "row-main" },
        h("div", { class: "row-name" }, h("span", { class: "selectable", text: subnet.cidr }), subnet.label ? h("span", { class: "subnet-label", text: ` - ${subnet.label}` }) : null),
        h("div", { class: "row-detail", text: details.join(", ") }),
      ),
      h(
        "div",
        { class: "row-actions" },
        button("Scan", () => void this.scan([subnet]), { title: `Scan ${subnet.cidr} only; results from other subnets stay` }),
        button("Edit", () => void this.editSubnet(subnet)),
        button("Remove", () => void this.removeSubnet(subnet), { kind: "quiet" }),
      ),
    );
  }

  private async editSubnet(existing: Subnet | null): Promise<void> {
    const cidrId = `subnet-field-${++fieldCounter}`;
    const labelId = `subnet-field-${++fieldCounter}`;
    const cidr = h("input", { class: "input", attrs: { id: cidrId, type: "text", autocomplete: "off", spellcheck: "false", placeholder: "10.0.0.0/24", "data-autofocus": "" } });
    cidr.value = existing?.cidr ?? "";
    const label = h("input", { class: "input", attrs: { id: labelId, type: "text", autocomplete: "off", maxlength: "80", placeholder: "Office VLAN" } });
    label.value = existing?.label ?? "";
    const cidrError = h("p", { class: "field-error", attrs: { role: "alert" } });
    cidrError.hidden = true;
    const info = h("p", { class: "notice" });
    const publicCheck = h("input", { attrs: { type: "checkbox" } });
    publicCheck.checked = existing?.allow_public ?? false;
    const publicRow = h(
      "div",
      { class: "form-group" },
      h("p", { class: "notice notice-warn", text: "This is a public address range, not a private network. Scanning addresses that are not yours can break the law or your provider's terms." }),
      h("label", { class: "check" }, publicCheck, h("span", { text: "This is my network, and I am allowed to scan it" })),
    );
    const saveError = h("p", { class: "notice notice-error", attrs: { role: "alert" } });
    saveError.hidden = true;

    const sync = () => {
      const parsed = parseCidr(cidr.value);
      publicRow.hidden = !parsed.ok || parsed.value.isPrivate;
      info.hidden = !parsed.ok;
      info.classList.toggle("notice-warn", parsed.ok && parsed.value.isLarge);
      if (parsed.ok) {
        const count = parsed.value.hostCount.toLocaleString("en-US");
        info.textContent = parsed.value.isLarge
          ? `${parsed.value.cidr}: ${count} addresses. A subnet this large takes ${estimateDuration(parsed.value.hostCount)} to scan and is more likely to be noticed by network security tools.`
          : `${parsed.value.cidr}: ${count} addresses.`;
      }
    };
    cidr.addEventListener("input", () => {
      saveError.hidden = true;
      cidrError.hidden = true;
      cidr.setAttribute("aria-invalid", "false");
      sync();
    });
    sync();

    const body = h(
      "div",
      { class: "form" },
      h("div", { class: "field" }, h("label", { class: "field-label", text: "Subnet (CIDR)", attrs: { for: cidrId } }), cidr, h("p", { class: "field-hint", text: "An IPv4 network and prefix length, from /16 (65,536 addresses) to /32 (one address)." }), cidrError),
      h("div", { class: "field" }, h("label", { class: "field-label", text: "Label (optional)", attrs: { for: labelId } }), label),
      info,
      publicRow,
      saveError,
    );

    const saved = await openDialog<Subnet[]>({
      title: existing ? "Edit subnet" : "Add subnet",
      body,
      submitLabel: existing ? "Save" : "Add",
      onSubmit: async () => {
        saveError.hidden = true;
        const parsed = parseCidr(cidr.value);
        cidrError.textContent = parsed.ok ? "" : parsed.error;
        cidrError.hidden = parsed.ok;
        cidr.setAttribute("aria-invalid", parsed.ok ? "false" : "true");
        if (!parsed.ok) {
          cidr.focus();
          return undefined;
        }
        if (!parsed.value.isPrivate && !publicCheck.checked) {
          saveError.textContent = "Confirm that this public range is your own network, or enter a private subnet.";
          saveError.hidden = false;
          return undefined;
        }
        const entry: Subnet = { id: existing?.id ?? "", cidr: parsed.value.cidr, label: label.value.trim(), allow_public: publicCheck.checked };
        const list = existing ? this.subnets.map((s) => (s.id === existing.id ? entry : s)) : [...this.subnets, entry];
        try {
          return await this.host.platform.api.saveSubnets(list);
        } catch (error) {
          saveError.textContent = `Couldn't save the subnet: ${messageOf(error)}`;
          saveError.hidden = false;
          return undefined;
        }
      },
    });
    if (saved) {
      this.showProblem(null);
      this.setSubnets(saved, true);
    }
  }

  private async removeSubnet(subnet: Subnet): Promise<void> {
    const confirmed = await confirmDialog({
      title: `Remove ${subnet.cidr}?`,
      message: "The subnet is removed from this list. Saved connections are not changed.",
      confirmLabel: "Remove",
      danger: true,
    });
    if (!confirmed) return;
    try {
      this.setSubnets(await this.host.platform.api.saveSubnets(this.subnets.filter((s) => s.id !== subnet.id)), false);
    } catch (error) {
      this.showProblem(`Couldn't remove ${subnet.cidr}: ${messageOf(error)}`);
    }
  }

  // ---- scanning ---------------------------------------------------------------------------

  private chosen(): Subnet[] {
    return this.subnets.filter((s) => this.selected.has(s.id));
  }

  private renderScanState(): void {
    const chosen = this.chosen().length;
    this.scanButton.disabled = this.scanning || chosen === 0;
    this.scanButton.textContent = this.scanning
      ? "Scanning..."
      : chosen === this.subnets.length || chosen === 0
        ? "Scan all"
        : `Scan selected (${chosen})`;
    this.cancelButton.hidden = !this.scanning;
    for (const input of this.subnetList.querySelectorAll<HTMLInputElement>("input[type=checkbox]")) input.disabled = this.scanning;
    for (const b of this.subnetList.querySelectorAll<HTMLButtonElement>(".row-actions button")) b.disabled = this.scanning;
    if (!this.scanning && this.subnets.length > 0 && this.chosen().length === 0 && !this.status.textContent) {
      this.status.textContent = "Tick the subnets to scan.";
    } else if (this.status.textContent === "Tick the subnets to scan." && this.chosen().length > 0) {
      this.status.textContent = "";
    }
  }

  /** Scan these subnets. Results from other subnets stay; results inside these are replaced. */
  private async scan(chosen: Subnet[]): Promise<void> {
    if (chosen.length === 0 || this.scanning) return;
    const total = chosen.reduce((sum, s) => {
      const parsed = parseCidr(s.cidr);
      return sum + (parsed.ok ? parsed.value.hostCount : 0);
    }, 0);
    if (total > CONFIRM_ABOVE) {
      const ok = await confirmDialog({
        title: `Scan ${total.toLocaleString("en-US")} addresses?`,
        message: `This takes ${estimateDuration(total)}. Scanning this many addresses is more likely to be noticed by network security tools.`,
        confirmLabel: "Scan",
      });
      if (!ok) return;
    }
    const generation = ++this.generation;
    this.showProblem(null);
    this.hosts = withoutSubnets(this.hosts, chosen.map((s) => s.cidr));
    this.scanning = true;
    this.scanId = null;
    this.progress.hidden = false;
    this.progress.value = 0;
    this.status.textContent = progressText(0, total, 0);
    this.renderScanState();
    this.renderResults();
    try {
      const id = await this.host.platform.api.startScan(
        chosen.map((s) => s.id),
        (event) => {
          if (generation === this.generation) this.onEvent(event);
        },
      );
      if (generation === this.generation && this.scanning) this.scanId = id;
    } catch (error) {
      if (generation !== this.generation) return;
      this.scanning = false;
      this.progress.hidden = true;
      this.status.textContent = "";
      this.showProblem(`Couldn't start the scan: ${messageOf(error)}`);
      this.renderScanState();
    }
  }

  private onEvent(event: ScanEvent): void {
    switch (event.type) {
      case "progress":
        this.progress.value = event.total > 0 ? event.done / event.total : 1;
        this.status.textContent = progressText(event.done, event.total, event.found);
        break;
      case "host":
        this.hosts = upsertHost(this.hosts, event.host);
        this.scheduleRender();
        break;
      case "finished": {
        this.scanning = false;
        this.scanId = null;
        this.progress.hidden = true;
        const summary = progressText(event.done, event.total, event.found);
        this.status.textContent = event.too_many
          ? `Scan stopped: ${summary}.`
          : event.cancelled
            ? `Scan cancelled: ${summary}.`
            : `Scan finished: ${summary}.`;
        if (event.too_many) this.showProblem(TOO_MANY_MESSAGE);
        this.renderScanState();
        this.renderResults();
        break;
      }
    }
  }

  private async cancel(): Promise<void> {
    if (!this.scanning) return;
    this.cancelButton.disabled = true;
    try {
      if (this.scanId) await this.host.platform.api.cancelScan(this.scanId);
    } catch (error) {
      this.showProblem(`Couldn't cancel the scan: ${messageOf(error)}`);
    } finally {
      this.cancelButton.disabled = false;
    }
  }

  // ---- results ----------------------------------------------------------------------------

  private sortBy(key: SortKey): void {
    if (this.sortKey === key) this.ascending = !this.ascending;
    else {
      this.sortKey = key;
      this.ascending = true;
    }
    this.renderSort();
    this.renderResults();
  }

  private renderSort(): void {
    for (const key of ["ip", "name"] as SortKey[]) {
      const active = this.sortKey === key;
      this.sortHeaders[key].setAttribute("aria-sort", active ? (this.ascending ? "ascending" : "descending") : "none");
      this.sortButtons[key].dataset["sort"] = active ? (this.ascending ? "asc" : "desc") : "";
    }
  }

  /** Render soon, once for everything that arrived meanwhile. */
  private scheduleRender(): void {
    if (this.renderTimer) return;
    this.renderTimer = window.setTimeout(() => this.renderResults(), RENDER_BATCH_MS);
  }

  private renderResults(): void {
    window.clearTimeout(this.renderTimer);
    this.renderTimer = 0;
    const computers = this.hosts.filter(isComputer);
    const hidden = this.hosts.length - computers.length;
    this.showAllLabel.textContent = hiddenToggleLabel(this.showAll ? 0 : hidden);
    const pool = this.showAll ? this.hosts : computers;
    const shown = sortHosts(filterHosts(pool, this.filter.value), this.sortKey, this.ascending);
    this.resultsBody.replaceChildren(...shown.map((host) => this.cachedRow(host)));
    if (this.hosts.length === 0) {
      this.resultsNote.textContent = this.scanning ? "Computers appear here as they are found." : "No results yet. Choose subnets and press Scan.";
    } else if (pool.length === 0) {
      this.resultsNote.textContent = this.scanning
        ? "No Windows PCs or Macs yet. Other devices are hidden."
        : "No Windows PCs or Macs found. Tick \u201cShow all devices\u201d to see the other devices that answered.";
    } else if (shown.length < pool.length) {
      this.resultsNote.textContent = `Showing ${shown.length} of ${pool.length} ${this.showAll ? "devices" : "computers"}.`;
    } else {
      this.resultsNote.textContent = "";
    }
    this.resultsNote.hidden = this.resultsNote.textContent === "";
  }

  private cachedRow(found: FoundHost): HTMLElement {
    let row = this.rows.get(found);
    if (!row) {
      row = this.resultRow(found);
      this.rows.set(found, row);
    }
    return row;
  }

  private resultRow(found: FoundHost): HTMLElement {
    const names = allNames(found);
    const others = names.slice(1);
    const extra = [...others];
    if (found.model) extra.push(found.model);
    const tooltip: string[] = [];
    if (found.names.rdp_certificate) tooltip.push(`Certificate name: ${found.names.rdp_certificate}`);
    if (found.names.mdns_name || found.names.mdns_host) tooltip.push(`Bonjour: ${[found.names.mdns_name, found.names.mdns_host].filter(Boolean).join(", ")}`);
    if (found.names.smb) tooltip.push(`File sharing (SMB): ${found.names.smb}`);
    if (found.names.netbios) tooltip.push(`NetBIOS: ${found.names.netbios}`);
    if (found.names.dns) tooltip.push(`DNS: ${found.names.dns}`);
    if (found.rfb_version) tooltip.push(`VNC version: ${found.rfb_version}`);
    if (found.ssh_banner) tooltip.push(`SSH: ${found.ssh_banner}`);
    if (found.rdp_certificate_sha256) tooltip.push(`Certificate SHA-256 (information only, not trusted): ${found.rdp_certificate_sha256}`);

    const matches = savedMatches(found, this.host.store.connections);
    const savedCell = h("td", { class: "results-saved" });
    if (matches.length > 0) {
      savedCell.append(h("span", { class: "saved-tag", text: matches.length === 1 ? `Saved: ${matches[0]?.name ?? ""}` : `Saved (${matches.length})`, title: matches.map((m) => m.name).join(", ") }));
    }
    // Names are announced by the machine itself: a name match alone is only worth a warning.
    for (const match of nameOnlyMatches(found, this.host.store.connections)) {
      savedCell.append(h("span", { class: "saved-tag name-only", text: nameMatchWarning(match), title: "Anyone on the network can announce any name. Only the address identifies a saved computer." }));
    }

    const protocols = addableProtocols(found);
    const actions = h("td", { class: "results-actions" });
    for (const protocol of protocols) {
      const label = protocols.length > 1 ? `Add as ${protocolLabel(protocol)}` : "Add connection";
      actions.append(button(label, () => void this.add(found, protocol), { kind: matches.length > 0 ? "default" : "primary" }));
    }
    if (protocols.length === 0) actions.append(h("span", { class: "muted", text: "SSH only", title: "RemoteControl connects with Remote Desktop or Screen Sharing; neither answered." }));

    const kindLabel = found.kind === "windows" ? "Windows" : found.kind === "mac" ? "Mac" : "Other";
    const source = nameSource(found);
    const row = h(
      "tr",
      { attrs: { "data-ip": found.ip } },
      h("td", { class: "selectable results-ip", text: found.ip }),
      h(
        "td",
        { class: "results-name" },
        h("div", { class: "row-name selectable", text: names[0] ?? "(no name found)" }),
        source ? h("div", { class: "row-detail muted name-source", text: `Name from ${source}` }) : null,
        extra.length > 0 ? h("div", { class: "row-detail selectable", text: extra.join(", ") }) : null,
      ),
      h("td", {}, h("span", { class: `kind-tag kind-${found.kind}`, text: kindLabel }), ...serviceLabels(found).map((s) => h("span", { class: "service-tag", text: s }))),
      savedCell,
      actions,
    );
    row.title = tooltip.join("\n");
    return row;
  }

  private async add(found: FoundHost, protocol: Protocol): Promise<void> {
    const saved = await openEditor(this.host.platform, null, prefillConnection(found, protocol, this.host.store.connections));
    if (saved) await this.host.store.reload();
  }
}
