// App shell: loads the platform, owns the tab strip and wires the views together.
import "./styles.css";
import { h } from "./dom";
import type { Connection } from "./ipc";
import { loadPlatform, type Platform } from "./platform";
import { ConnectionStore } from "./state";
import { HomeView } from "./views/home";
import { SessionView, type SessionHost } from "./views/session";

const HOME = "home";

class App implements SessionHost {
  readonly store: ConnectionStore;
  private readonly tabStrip: HTMLElement;
  private readonly content: HTMLElement;
  private readonly home: HomeView;
  private readonly sessions: SessionView[] = [];
  private activeId: string = HOME;
  private fullscreen = false;

  constructor(
    root: HTMLElement,
    readonly platform: Platform,
  ) {
    this.store = new ConnectionStore(platform.api);
    this.tabStrip = h("nav", { class: "tabstrip", attrs: { role: "tablist", "aria-label": "Open sessions" } });
    this.content = h("main", { class: "content" });
    this.home = new HomeView({
      platform,
      store: this.store,
      connect: (connection) => this.openSession(connection),
      closeSessionsFor: (id) => {
        for (const view of this.sessions.filter((s) => s.connection.id === id)) this.close(view);
      },
    });
    this.content.append(this.home.element);
    root.replaceChildren(this.tabStrip, this.content);
    this.renderTabs();

    window.addEventListener("focus", () => this.activeSession()?.windowFocused());
    // The window can leave full screen without us (the green button, a system shortcut).
    // Checked once the resize has settled: during the transition the answer is still the old one.
    let settle = 0;
    window.addEventListener("resize", () => {
      window.clearTimeout(settle);
      settle = window.setTimeout(() => void this.syncFullscreen(), 300);
    });
    void this.store.reload();
  }

  // ---- SessionHost ------------------------------------------------------------------------

  isActive(view: SessionView): boolean {
    return this.activeId === view.tabId;
  }

  close(view: SessionView): void {
    const index = this.sessions.indexOf(view);
    if (index < 0) return;
    const wasActive = this.isActive(view);
    this.sessions.splice(index, 1);
    view.destroy();
    view.element.remove();
    if (wasActive) {
      const neighbour = this.sessions[index] ?? this.sessions[index - 1];
      this.activeId = HOME; // the closed tab must not be deactivated again
      this.activate(neighbour ? neighbour.tabId : HOME);
    } else {
      this.renderTabs();
    }
  }

  toggleFullscreen(): void {
    void this.setFullscreen(!this.fullscreen);
  }

  isFullscreen(): boolean {
    return this.fullscreen;
  }

  changed(_view: SessionView): void {
    this.renderTabs();
  }

  // ---- tabs -------------------------------------------------------------------------------

  private activeSession(): SessionView | undefined {
    return this.sessions.find((s) => s.tabId === this.activeId);
  }

  private openSession(connection: Connection): void {
    const open = this.sessions.find((s) => s.connection.id === connection.id);
    if (open) {
      this.activate(open.tabId);
      return;
    }
    const view = new SessionView(this, connection);
    this.sessions.push(view);
    view.element.hidden = true;
    this.content.append(view.element);
    // Activate first so the session can measure the area it will be shown in.
    this.activate(view.tabId);
    view.begin();
  }

  private activate(id: string): void {
    const previous = this.activeSession();
    if (previous && previous.tabId !== id) previous.deactivate();
    this.activeId = id;
    this.home.element.hidden = id !== HOME;
    for (const view of this.sessions) view.element.hidden = view.tabId !== id;
    const current = this.activeSession();
    if (!current && this.fullscreen) void this.setFullscreen(false);
    this.applyFullscreenClass();
    this.renderTabs();
    current?.activate();
  }

  private renderTabs(): void {
    const tabs: HTMLElement[] = [this.tab(HOME, "Home", null)];
    for (const view of this.sessions) tabs.push(this.tab(view.tabId, view.label, view));
    this.tabStrip.replaceChildren(...tabs);
  }

  private tab(id: string, label: string, view: SessionView | null): HTMLElement {
    const selected = this.activeId === id;
    const select = h("button", {
      class: "tab-select",
      attrs: { type: "button", role: "tab", "aria-selected": String(selected) },
      on: { click: () => this.activate(id) },
    });
    if (view) {
      const stateText = view.state === "connected" ? "connected" : view.state === "connecting" ? "connecting" : "not connected";
      select.append(h("span", { class: `tab-dot tab-dot-${view.state}`, attrs: { "aria-hidden": "true" } }));
      select.title = `${label} (${stateText})`;
    }
    select.append(h("span", { class: "tab-label", text: label }));
    const tab = h("div", { class: selected ? "tab tab-active" : "tab" }, select);
    if (view) {
      const close = h("button", {
        class: "tab-close",
        title: "Close and disconnect",
        attrs: { type: "button", "aria-label": `Close ${label} and disconnect` },
        on: { click: () => this.close(view) },
      });
      close.append(closeIcon());
      tab.append(close);
      tab.addEventListener("auxclick", (event) => {
        if (event.button === 1) this.close(view);
      });
    }
    return tab;
  }

  // ---- full screen ------------------------------------------------------------------------

  private async setFullscreen(on: boolean): Promise<void> {
    try {
      await this.platform.setFullscreen(on);
    } catch (error) {
      console.error("could not change full screen", error);
      return;
    }
    this.fullscreenIs(on);
  }

  private async syncFullscreen(): Promise<void> {
    try {
      this.fullscreenIs(await this.platform.isFullscreen());
    } catch {
      // Keep what we believe.
    }
  }

  private fullscreenIs(on: boolean): void {
    if (on === this.fullscreen) return;
    this.fullscreen = on;
    this.applyFullscreenClass();
    for (const view of this.sessions) view.fullscreenChanged(on);
  }

  /** The tab strip only hides (and the toolbar only tucks away) while a session is showing. */
  private applyFullscreenClass(): void {
    document.body.classList.toggle("fullscreen", this.fullscreen && this.activeSession() !== undefined);
  }
}

function closeIcon(): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 10 10");
  svg.setAttribute("width", "10");
  svg.setAttribute("height", "10");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M1.5 1.5l7 7M8.5 1.5l-7 7");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.4");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("fill", "none");
  svg.append(path);
  return svg;
}

async function boot(): Promise<void> {
  const root = document.getElementById("app");
  if (!root) throw new Error("index.html has no #app element");
  try {
    const platform = await loadPlatform();
    new App(root, platform);
  } catch (error) {
    console.error("startup failed", error);
    root.replaceChildren(
      h(
        "div",
        { class: "boot-error selectable" },
        h("h1", { text: "RemoteControl could not start" }),
        h("pre", { text: error instanceof Error ? (error.stack ?? error.message) : String(error) }),
      ),
    );
  }
}

void boot();
