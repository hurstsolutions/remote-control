// Pointer, wheel and keyboard capture on the remote canvas.
import type { SessionInput } from "../ipc";
import { ALL_BUTTONS_MASK, changedButtons, clientToRemote, wheelNotches, type Point } from "./geometry";
import { HeldKeys } from "./keys";

export interface InputOptions {
  mac: boolean;
  remoteSize: () => { width: number; height: number };
  send: (input: SessionInput) => void;
}

export class InputController {
  /** Only a connected session forwards input. */
  enabled = false;

  private readonly keys: HeldKeys;
  private readonly abort = new AbortController();
  private buttons = 0;
  private pendingMove: Point | null = null;
  private frameRequest = 0;
  /** Something was sent since the last release_all. */
  private dirty = false;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    private readonly options: InputOptions,
  ) {
    this.keys = new HeldKeys({ macCapsLock: options.mac });
    const signal = this.abort.signal;
    const on = <K extends keyof HTMLElementEventMap>(
      type: K,
      handler: (event: HTMLElementEventMap[K]) => void,
      passive = false,
    ) => canvas.addEventListener(type, handler, { signal, passive });

    on("pointerdown", (e) => this.onPointer(e));
    on("pointermove", (e) => this.onPointer(e), true);
    on("pointerup", (e) => this.onPointer(e));
    on("pointercancel", (e) => this.dropButtons(e));
    on("lostpointercapture", (e) => this.dropButtons(e));
    on("wheel", (e) => this.onWheel(e));
    on("keydown", (e) => this.onKey(e, true));
    on("keyup", (e) => this.onKey(e, false));
    on("blur", () => this.releaseAll());
    // Keep the webview from acting on presses meant for the remote: the context menu, text
    // selection and drags, middle-click autoscroll, and back / forward navigation.
    const swallow = (e: Event) => e.preventDefault();
    on("contextmenu", swallow);
    on("mousedown", swallow);
    on("mouseup", swallow);
    on("auxclick", swallow);
    on("dragstart", swallow);

    window.addEventListener("blur", () => this.releaseAll(), { signal });
    document.addEventListener(
      "visibilitychange",
      () => {
        if (document.visibilityState !== "visible") this.releaseAll();
      },
      { signal },
    );
  }

  /** Release everything held on the remote (blur, tab switch, window blur, hidden). */
  releaseAll(): void {
    this.pendingMove = null;
    const anything = this.dirty || this.buttons !== 0 || this.keys.size > 0;
    this.reset();
    if (anything && this.enabled) this.options.send({ type: "release_all" });
  }

  /** Forget local state without telling the remote (the session has ended). */
  reset(): void {
    this.keys.clear();
    this.buttons = 0;
    this.dirty = false;
    this.pendingMove = null;
  }

  sendCtrlAltDel(): void {
    if (!this.enabled) return;
    this.flushMove();
    const combo: Array<[code: string, key: string]> = [
      ["ControlLeft", "Control"],
      ["AltLeft", "Alt"],
      ["Delete", "Delete"],
    ];
    for (const [code, key] of combo) this.options.send({ type: "key", code, key, down: true });
    for (const [code, key] of [...combo].reverse()) this.options.send({ type: "key", code, key, down: false });
  }

  destroy(): void {
    this.abort.abort();
    if (this.frameRequest) cancelAnimationFrame(this.frameRequest);
    this.frameRequest = 0;
  }

  private locate(event: MouseEvent): Point {
    const size = this.options.remoteSize();
    return clientToRemote(event.clientX, event.clientY, this.canvas.getBoundingClientRect(), size.width, size.height);
  }

  private onPointer(event: PointerEvent): void {
    if (!this.enabled) return;
    const isDown = event.type === "pointerdown";
    if (isDown) {
      event.preventDefault();
      // mousedown is swallowed above, so focus has to be taken by hand.
      if (document.activeElement !== this.canvas) this.canvas.focus({ preventScroll: true });
      try {
        this.canvas.setPointerCapture(event.pointerId);
      } catch {
        // The pointer is already gone; carry on without capture.
      }
    }
    const position = this.locate(event);
    // A button that went down outside the canvas is not ours: only start tracking on a press here.
    const tracking = isDown || this.buttons !== 0;
    const next = tracking ? event.buttons & ALL_BUTTONS_MASK : 0;
    const changes = changedButtons(this.buttons, next);
    if (changes.length === 0) {
      this.queueMove(position);
      return;
    }
    this.pendingMove = position;
    this.flushMove();
    this.buttons = next;
    this.dirty = true;
    for (const change of changes) {
      this.options.send({ type: "pointer_button", button: change.button, down: change.down, x: position.x, y: position.y });
    }
  }

  /** Capture was lost mid-drag: let go of whatever is still held. */
  private dropButtons(event: PointerEvent): void {
    if (this.buttons === 0) return;
    const changes = changedButtons(this.buttons, 0);
    this.buttons = 0;
    if (!this.enabled) return;
    const position = this.locate(event);
    this.pendingMove = position;
    this.flushMove();
    for (const change of changes) {
      this.options.send({ type: "pointer_button", button: change.button, down: false, x: position.x, y: position.y });
    }
  }

  private onWheel(event: WheelEvent): void {
    event.preventDefault();
    if (!this.enabled) return;
    const position = this.locate(event);
    this.pendingMove = position;
    this.flushMove();
    const { dx, dy } = wheelNotches(event.deltaX, event.deltaY, event.deltaMode);
    if (dx === 0 && dy === 0) return;
    this.options.send({ type: "wheel", dx, dy, x: position.x, y: position.y });
  }

  private onKey(event: KeyboardEvent, down: boolean): void {
    if (!this.enabled) return;
    event.preventDefault();
    event.stopPropagation();
    this.flushMove();
    const messages = down ? this.keys.keyDown(event.code, event.key) : this.keys.keyUp(event.code, event.key);
    for (const message of messages) {
      this.dirty = true;
      this.options.send({ type: "key", code: message.code, key: message.key, down: message.down });
    }
  }

  /** At most one pointer_move per animation frame; the latest position wins. */
  private queueMove(position: Point): void {
    this.pendingMove = position;
    if (this.frameRequest === 0) {
      this.frameRequest = requestAnimationFrame(() => {
        this.frameRequest = 0;
        this.flushMove();
      });
    }
  }

  private flushMove(): void {
    const move = this.pendingMove;
    if (!move) return;
    this.pendingMove = null;
    if (this.enabled) this.options.send({ type: "pointer_move", x: move.x, y: move.y });
  }
}
