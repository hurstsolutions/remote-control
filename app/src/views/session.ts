// One session tab: the connect flow, the toolbar, the remote screen and the failure panels.
import { isDialogOpen } from "../dialog";
import { button, h } from "../dom";
import { describeError, toSessionError } from "../errors";
import type { ChannelMessage, Connection, SessionError, SessionEvent, SessionInput } from "../ipc";
import { copyLogButton } from "../logs";
import { isMac, type Platform } from "../platform";
import { ClipboardSync } from "../remote/clipboard";
import { remoteSizeForViewport, type DisplayMode } from "../remote/geometry";
import { InputController } from "../remote/input";
import { RemoteScreen } from "../remote/screen";
import { hostLabel, type ConnectionStore } from "../state";
import { askPassword } from "./password";

export interface SessionHost {
  platform: Platform;
  store: ConnectionStore;
  isActive(view: SessionView): boolean;
  /** Close the tab (the view disconnects itself). */
  close(view: SessionView): void;
  toggleFullscreen(): void;
  isFullscreen(): boolean;
  /** The tab's label or state changed. */
  changed(view: SessionView): void;
}

export type SessionState = "connecting" | "connected" | "closed";

interface ConnectOptions {
  /** null = use the saved password. */
  password: string | null;
  save: boolean;
  trust: boolean;
}

const RESIZE_DEBOUNCE_MS = 400;
const FALLBACK_SIZE = { width: 1280, height: 800 };
const AUTH_NOTE = "The username or password was not accepted. Enter the password again.";

let nextTabId = 1;

export class SessionView {
  readonly tabId = `session-${nextTabId++}`;
  readonly element: HTMLElement;
  state: SessionState = "connecting";
  connection: Connection;

  private readonly screen: RemoteScreen;
  private readonly input: InputController;
  private readonly clipboard: ClipboardSync;
  private readonly overlay: HTMLElement;
  private readonly title: HTMLElement;
  private readonly subtitle: HTMLElement;
  private readonly fitButton: HTMLButtonElement;
  private readonly actualButton: HTMLButtonElement;
  private readonly fullscreenButton: HTMLButtonElement;
  private readonly disconnectButton: HTMLButtonElement;
  private readonly cadButton: HTMLButtonElement | null;
  private readonly hint: HTMLElement;

  /** Bumped for every connect attempt; messages from older attempts are ignored. */
  private attempt = 0;
  private sessionId: string | null = null;
  private resizeTimer = 0;
  private hintTimer = 0;
  private requestedSize: { width: number; height: number } | null = null;
  private destroyed = false;

  constructor(
    private readonly host: SessionHost,
    connection: Connection,
  ) {
    this.connection = connection;
    const windows = connection.protocol === "rdp";

    this.screen = new RemoteScreen(() => this.onViewportChange());
    this.input = new InputController(this.screen.canvas, {
      mac: isMac(),
      remoteSize: () => ({ width: this.screen.remoteWidth, height: this.screen.remoteHeight }),
      send: (input) => this.send(input),
    });
    this.clipboard = new ClipboardSync(
      host.platform,
      (text) => this.send({ type: "clipboard", text }),
      () => this.state === "connected" && this.sessionId !== null,
    );

    this.title = h("span", { class: "toolbar-title", text: connection.name });
    this.subtitle = h("span", { class: "toolbar-subtitle", text: hostLabel(connection) });

    // Toolbar buttons hand the keyboard straight back to the remote screen.
    const tool = (label: string, action: () => void, title?: string) =>
      button(
        label,
        () => {
          action();
          this.focusScreen();
        },
        title ? { title } : {},
      );

    this.cadButton = windows
      ? tool("Send Ctrl+Alt+Del", () => this.input.sendCtrlAltDel(), "Press Ctrl+Alt+Del on the remote PC")
      : null;
    this.fitButton = tool("Fit to window", () => this.setMode("fit"), "Scale the remote screen to fit this window");
    this.actualButton = tool("Actual size", () => this.setMode("actual"), "Show the remote screen pixel for pixel");
    this.fullscreenButton = tool("Full screen", () => host.toggleFullscreen());
    this.disconnectButton = button("Disconnect", () => this.disconnect());

    const toolbar = h(
      "div",
      { class: "toolbar", attrs: { role: "toolbar", "aria-label": "Session" } },
      this.title,
      this.subtitle,
      h("span", { class: "spacer" }),
      this.cadButton,
      h("div", { class: "segmented", attrs: { role: "group", "aria-label": "Display size" } }, this.fitButton, this.actualButton),
      this.fullscreenButton,
      this.disconnectButton,
    );

    this.overlay = h("div", { class: "overlay" });
    this.hint = h("div", { class: "hint", text: "Move the pointer to the top edge to show the toolbar." });
    this.hint.hidden = true;
    this.screen.stage.append(this.overlay, this.hint);
    this.element = h(
      "section",
      { class: "session", attrs: { "data-protocol": connection.protocol } },
      h("div", { class: "session-top" }, toolbar),
      this.screen.stage,
    );
    this.updateToolbar();
  }

  get label(): string {
    return this.connection.name;
  }

  /** Begin the first connection. Call once the view is in the page and visible. */
  begin(): void {
    void this.start({ password: null, save: false, trust: false });
  }

  /** The tab became the active one. */
  activate(): void {
    this.screen.relayout();
    this.onViewportChange();
    if (this.state === "connected") {
      this.focusScreen();
      void this.clipboard.pushLocal();
    }
  }

  /** Another tab became active. */
  deactivate(): void {
    this.input.releaseAll();
  }

  /** The window gained focus while this tab is active. */
  windowFocused(): void {
    if (this.state === "connected") void this.clipboard.pushLocal();
  }

  fullscreenChanged(on: boolean): void {
    this.updateToolbar();
    window.clearTimeout(this.hintTimer);
    this.hint.hidden = !(on && this.host.isActive(this));
    if (!this.hint.hidden) {
      this.hintTimer = window.setTimeout(() => {
        this.hint.hidden = true;
      }, 4000);
    }
  }

  /** Disconnect and release everything; the tab is being closed. */
  destroy(): void {
    this.destroyed = true;
    this.endSession();
    window.clearTimeout(this.hintTimer);
    this.input.destroy();
    this.screen.destroy();
  }

  // ---- connecting -------------------------------------------------------------------------

  private async start(options: ConnectOptions): Promise<void> {
    this.endSession();
    const attempt = this.attempt;
    // Pick up edits made to the connection since the tab was opened.
    this.connection = this.host.store.get(this.connection.id) ?? this.connection;
    this.title.textContent = this.connection.name;
    this.subtitle.textContent = hostLabel(this.connection);
    this.clipboard.reset();
    this.screen.setCursor({ kind: "default" });
    this.setState("connecting");
    this.showConnecting(`Connecting to ${this.connection.host}...`);

    const view = this.screen.viewportSize();
    const size =
      view.width > 0 && view.height > 0
        ? remoteSizeForViewport(view.width, view.height, window.devicePixelRatio)
        : FALLBACK_SIZE;
    this.requestedSize = size;
    const api = this.host.platform.api;
    try {
      const sessionId = await api.connect(
        {
          id: this.connection.id,
          password: options.password,
          save_password: options.password !== null && options.save,
          width: size.width,
          height: size.height,
          scale_factor: Math.round(window.devicePixelRatio * 100),
          trust_new_identity: options.trust,
        },
        (message) => this.onMessage(attempt, message),
      );
      if (attempt !== this.attempt) {
        // Cancelled or superseded while the call was in flight.
        api.disconnect(sessionId).catch(() => undefined);
        return;
      }
      this.sessionId = sessionId;
      if (this.state === "connected" && this.host.isActive(this)) void this.clipboard.pushLocal();
    } catch (raw) {
      if (attempt !== this.attempt) return;
      const error = toSessionError(raw);
      if (error.kind === "password_required") {
        await this.promptPassword(options.trust, null, true);
      } else {
        this.setState("closed");
        this.showError(error);
      }
    }
  }

  /**
   * Ask for the password, then connect with it (the saved one is not used). Cancelling leaves
   * a panel to try again from: the current error panel, or a plain one when `replacePanel`.
   */
  private async promptPassword(trust: boolean, note: string | null, replacePanel: boolean): Promise<void> {
    const attempt = this.attempt;
    if (replacePanel) {
      this.setState("closed");
      this.showPanel({
        headline: "A password is needed",
        hints: [`Enter the password for ${this.connection.username || "this account"} to connect.`],
        detail: null,
        buttons: [button("Enter password", () => void this.promptPassword(trust, note, false), { kind: "primary" })],
      });
    }
    const answer = await askPassword(this.connection, note);
    if (attempt !== this.attempt || this.destroyed) return;
    if (answer) void this.start({ password: answer.password, save: answer.save, trust });
  }

  private onMessage(attempt: number, message: ChannelMessage): void {
    if (attempt !== this.attempt) return;
    if (message instanceof ArrayBuffer) {
      this.screen.paint(message);
      return;
    }
    this.onEvent(message);
  }

  private onEvent(event: SessionEvent): void {
    switch (event.type) {
      case "status":
        if (this.state === "connecting") this.showConnecting(event.text);
        break;
      case "identity":
        // The backend pinned this machine's identity; refresh so a later edit keeps the pin.
        void this.host.store.reload();
        break;
      case "connected":
        this.screen.setRemoteSize(event.width, event.height);
        this.setState("connected");
        this.overlay.replaceChildren();
        this.overlay.hidden = true;
        this.element.title = "";
        this.subtitle.textContent = event.name ? `${hostLabel(this.connection)} - ${event.name}` : hostLabel(this.connection);
        if (this.host.isActive(this)) {
          if (!isDialogOpen()) this.focusScreen();
          void this.clipboard.pushLocal();
        }
        // The window may have been resized while connecting.
        this.onViewportChange();
        break;
      case "resized":
        this.screen.setRemoteSize(event.width, event.height);
        break;
      case "cursor":
        this.screen.setCursor(event);
        break;
      case "clipboard":
        void this.clipboard.receiveRemote(event.text);
        break;
      case "bell":
        break;
      case "closed":
        this.attempt++;
        this.sessionId = null;
        this.stopInput();
        this.setState("closed");
        if (event.error) this.showError(event.error);
        else this.showDisconnected();
        break;
    }
  }

  // ---- ending -----------------------------------------------------------------------------

  /** Invalidate the current attempt and tell the backend to drop its session, if any. */
  private endSession(): void {
    this.attempt++;
    window.clearTimeout(this.resizeTimer);
    this.stopInput();
    const sessionId = this.sessionId;
    this.sessionId = null;
    if (sessionId !== null) {
      this.host.platform.api.disconnect(sessionId).catch((error: unknown) => console.warn("disconnect failed", error));
    }
  }

  private stopInput(): void {
    window.clearTimeout(this.resizeTimer);
    this.input.enabled = false;
    this.input.reset();
  }

  /** The Disconnect button, and Cancel while connecting. */
  private disconnect(): void {
    this.endSession();
    this.setState("closed");
    this.showDisconnected();
  }

  private reconnect(): void {
    void this.start({ password: null, save: false, trust: false });
  }

  // ---- input ------------------------------------------------------------------------------

  private send(input: SessionInput): void {
    const sessionId = this.sessionId;
    if (sessionId === null || this.state !== "connected") return;
    this.host.platform.api.sendInput(sessionId, input).catch(() => undefined);
  }

  private focusScreen(): void {
    if (this.state === "connected" && this.host.isActive(this)) this.screen.canvas.focus({ preventScroll: true });
  }

  private setMode(mode: DisplayMode): void {
    this.screen.setMode(mode);
    this.updateToolbar();
  }

  /** Windows sessions follow the window size: ask the remote to resize, debounced. */
  private onViewportChange(): void {
    if (this.connection.protocol !== "rdp" || this.state !== "connected") return;
    window.clearTimeout(this.resizeTimer);
    this.resizeTimer = window.setTimeout(() => {
      if (this.state !== "connected") return;
      const view = this.screen.viewportSize();
      if (view.width === 0 || view.height === 0) return; // hidden tab
      const size = remoteSizeForViewport(view.width, view.height, window.devicePixelRatio);
      const last = this.requestedSize;
      if (last && last.width === size.width && last.height === size.height) return;
      this.requestedSize = size;
      this.send({ type: "resize", width: size.width, height: size.height });
    }, RESIZE_DEBOUNCE_MS);
  }

  // ---- presentation -----------------------------------------------------------------------

  private setState(state: SessionState): void {
    this.state = state;
    this.input.enabled = state === "connected";
    this.element.dataset["state"] = state;
    this.updateToolbar();
    this.host.changed(this);
  }

  private updateToolbar(): void {
    const connected = this.state === "connected";
    if (this.cadButton) this.cadButton.disabled = !connected;
    this.fitButton.setAttribute("aria-pressed", String(this.screen.mode === "fit"));
    this.actualButton.setAttribute("aria-pressed", String(this.screen.mode === "actual"));
    this.fullscreenButton.textContent = this.host.isFullscreen() ? "Exit full screen" : "Full screen";
    this.disconnectButton.disabled = this.state === "closed";
  }

  private showConnecting(text: string): void {
    this.overlay.hidden = false;
    const existing = this.overlay.querySelector<HTMLElement>(".status-text");
    if (existing) {
      existing.textContent = text;
      return;
    }
    this.overlay.replaceChildren(
      h(
        "div",
        { class: "panel panel-status", attrs: { role: "status" } },
        h("div", { class: "spinner", attrs: { "aria-hidden": "true" } }),
        h("p", { class: "status-text", text }),
        button("Cancel", () => this.disconnect()),
      ),
    );
  }

  private showDisconnected(): void {
    this.showPanel({
      headline: "Disconnected",
      hints: [],
      detail: null,
      buttons: [button("Reconnect", () => this.reconnect(), { kind: "primary" })],
    });
  }

  private showError(error: SessionError): void {
    const text = describeError(error, this.connection);
    const copyLog = copyLogButton(this.host.platform);
    const reconnect = (kind: "primary" | "default") => button("Reconnect", () => this.reconnect(), { kind });
    let buttons: HTMLButtonElement[];
    if (error.kind === "auth_failed") {
      const note = AUTH_NOTE;
      // Retry with a typed password: the saved one is not used.
      buttons = [
        button("Enter password", () => void this.promptPassword(false, note, false), { kind: "primary" }),
        reconnect("default"),
        copyLog,
      ];
    } else if (error.kind === "security") {
      buttons = [
        button("Cancel", () => this.host.close(this)),
        button("Trust new identity and connect", () => void this.start({ password: null, save: false, trust: true }), {
          kind: "danger",
        }),
        reconnect("default"),
        copyLog,
      ];
    } else {
      buttons = [reconnect("primary"), copyLog];
    }
    this.showPanel({ headline: text.headline, hints: text.hints, detail: error.detail, buttons, error: true });
    // Re-prompt straight away after a refused sign-in; cancelling returns to this panel.
    if (error.kind === "auth_failed" && this.host.isActive(this) && !isDialogOpen()) {
      void this.promptPassword(false, AUTH_NOTE, false);
    }
  }

  private showPanel(options: {
    headline: string;
    hints: string[];
    detail: string | null;
    buttons: HTMLButtonElement[];
    error?: boolean;
  }): void {
    const panel = h(
      "div",
      { class: options.error ? "panel panel-error" : "panel", attrs: { role: options.error ? "alert" : "status" } },
      h("h2", { class: "panel-headline selectable", text: options.headline }),
    );
    if (options.hints.length === 1) {
      panel.append(h("p", { class: "panel-hint selectable", text: options.hints[0] ?? "" }));
    } else if (options.hints.length > 1) {
      panel.append(h("ul", { class: "panel-hints selectable" }, ...options.hints.map((hint) => h("li", { text: hint }))));
    }
    if (options.detail !== null) {
      panel.append(
        h("div", { class: "panel-detail-label", text: "Technical detail" }),
        h("pre", { class: "panel-detail selectable", text: options.detail || "(no detail was given)", attrs: { tabindex: "0" } }),
      );
    }
    panel.append(h("div", { class: "panel-buttons" }, ...options.buttons));
    this.overlay.hidden = false;
    this.overlay.replaceChildren(panel);
    if (this.host.isActive(this) && !isDialogOpen()) options.buttons.find((b) => b.classList.contains("btn-primary"))?.focus();
  }
}
