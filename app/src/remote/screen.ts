// The remote screen: a canvas the size of the remote framebuffer, frame painting, display
// scaling and the remote cursor.
import { h } from "../dom";
import {
  HEADER_BYTES,
  base64ToBytes,
  cursorCssSize,
  layoutScreen,
  readFrameHeader,
  rectFits,
  type DisplayMode,
  type FrameRect,
  type Layout,
} from "./geometry";

export type CursorShape =
  | { kind: "default" | "hidden" }
  | { kind: "bitmap"; width: number; height: number; hot_x: number; hot_y: number; rgba_base64: string };

const MAX_CURSOR_SOURCE = 512;

export class RemoteScreen {
  /** Fills the session below the toolbar; never scrolls, so its size is the available area. */
  readonly stage: HTMLDivElement;
  readonly canvas: HTMLCanvasElement;
  remoteWidth = 0;
  remoteHeight = 0;
  mode: DisplayMode = "fit";

  private readonly viewport: HTMLDivElement;
  private readonly context: CanvasRenderingContext2D;
  private readonly rect: FrameRect = { x: 0, y: 0, w: 0, h: 0 };
  private readonly observer: ResizeObserver;
  private layout: Layout | null = null;
  private cursor: CursorShape = { kind: "default" };
  private cursorSource: HTMLCanvasElement | null = null;
  private cursorScale = 0;
  private dprQuery: MediaQueryList | null = null;
  private readonly onDprChange = () => {
    this.watchDpr();
    this.relayout();
    this.onViewportChange();
  };

  /** `onViewportChange` is called whenever the available area or the pixel ratio changes. */
  constructor(private readonly onViewportChange: () => void) {
    this.canvas = h("canvas", { class: "remote-canvas", attrs: { tabindex: "0", "aria-label": "Remote screen" } });
    this.canvas.width = 0;
    this.canvas.height = 0;
    const context = this.canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("This webview cannot create a 2D canvas");
    this.context = context;
    this.viewport = h("div", { class: "viewport" }, this.canvas);
    this.stage = h("div", { class: "stage" }, this.viewport);
    this.observer = new ResizeObserver(() => {
      this.relayout();
      this.onViewportChange();
    });
    this.observer.observe(this.stage);
    this.watchDpr();
  }

  /** Available area in CSS pixels; 0 x 0 while the tab is hidden. */
  viewportSize(): { width: number; height: number } {
    // The exact (possibly fractional) size: clientWidth rounds, which can overstate it.
    const box = this.stage.getBoundingClientRect();
    return { width: box.width, height: box.height };
  }

  /** Set the framebuffer size (on connected / resized). Clears the canvas when it changes. */
  setRemoteSize(width: number, height: number): void {
    if (width === this.remoteWidth && height === this.remoteHeight) return;
    this.remoteWidth = width;
    this.remoteHeight = height;
    this.canvas.width = width;
    this.canvas.height = height;
    this.relayout();
  }

  /**
   * Paint every frame in a binary message. Stops at the first frame that is cut short;
   * skips frames whose rectangle does not lie inside the canvas.
   */
  paint(buffer: ArrayBuffer): void {
    const view = new DataView(buffer);
    const rect = this.rect;
    const length = view.byteLength;
    let offset = 0;
    while (offset < length) {
      const next = readFrameHeader(view, offset, rect);
      if (next < 0) return;
      if (rect.w > 0 && rect.h > 0 && rectFits(rect, this.remoteWidth, this.remoteHeight)) {
        const pixels = new Uint8ClampedArray(buffer, offset + HEADER_BYTES, rect.w * rect.h * 4);
        this.context.putImageData(new ImageData(pixels, rect.w, rect.h), rect.x, rect.y);
      }
      offset = next;
    }
  }

  setMode(mode: DisplayMode): void {
    if (mode === this.mode) return;
    this.mode = mode;
    this.viewport.scrollTo(0, 0);
    this.relayout();
  }

  /** Recompute the canvas's CSS size and position. No-op while hidden or before connecting. */
  relayout(): void {
    const { width, height } = this.viewportSize();
    if (width === 0 || height === 0 || this.remoteWidth === 0 || this.remoteHeight === 0) return;
    const layout = layoutScreen(this.mode, width, height, this.remoteWidth, this.remoteHeight, window.devicePixelRatio);
    this.layout = layout;
    const style = this.canvas.style;
    style.width = `${layout.cssWidth}px`;
    style.height = `${layout.cssHeight}px`;
    style.left = `${layout.left}px`;
    style.top = `${layout.top}px`;
    style.imageRendering = layout.smooth ? "auto" : "pixelated";
    this.viewport.classList.toggle("scroll", layout.scroll);
    if (this.cursor.kind === "bitmap" && layout.scale !== this.cursorScale) this.applyCursor();
  }

  setCursor(shape: CursorShape): void {
    this.cursor = shape;
    this.cursorSource = null;
    if (shape.kind === "bitmap") this.cursorSource = decodeCursor(shape);
    this.applyCursor();
  }

  destroy(): void {
    this.observer.disconnect();
    this.dprQuery?.removeEventListener("change", this.onDprChange);
  }

  private applyCursor(): void {
    const style = this.canvas.style;
    const shape = this.cursor;
    if (shape.kind === "hidden") {
      style.cursor = "none";
      return;
    }
    const source = this.cursorSource;
    const scale = this.layout?.scale ?? 1 / window.devicePixelRatio;
    this.cursorScale = scale;
    const size = shape.kind === "bitmap" && source ? cursorCssSize(shape.width, shape.height, scale) : null;
    if (shape.kind !== "bitmap" || !source || !size) {
      style.cursor = "default";
      return;
    }
    const hotX = Math.min(size.width - 1, Math.max(0, Math.round(shape.hot_x * scale)));
    const hotY = Math.min(size.height - 1, Math.max(0, Math.round(shape.hot_y * scale)));
    const plain = renderCursor(source, size.width, size.height);
    if (!plain) {
      style.cursor = "default";
      return;
    }
    style.cursor = `url("${plain}") ${hotX} ${hotY}, default`;
    // On high-density displays also offer a sharp image. A webview that does not understand
    // image-set() in a cursor ignores the assignment and keeps the plain one set above.
    const dpr = window.devicePixelRatio;
    if (dpr > 1) {
      const sharp = renderCursor(source, Math.round(size.width * dpr), Math.round(size.height * dpr));
      if (sharp) {
        const set = `url("${plain}") 1x, url("${sharp}") ${dpr}x`;
        style.cursor = `-webkit-image-set(${set}) ${hotX} ${hotY}, default`;
        style.cursor = `image-set(${set}) ${hotX} ${hotY}, default`;
      }
    }
  }

  // matchMedia fires once when the ratio stops matching, so re-arm it for the new ratio.
  private watchDpr(): void {
    this.dprQuery?.removeEventListener("change", this.onDprChange);
    this.dprQuery = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
    this.dprQuery.addEventListener("change", this.onDprChange);
  }
}

function decodeCursor(shape: Extract<CursorShape, { kind: "bitmap" }>): HTMLCanvasElement | null {
  const { width, height } = shape;
  if (!Number.isInteger(width) || !Number.isInteger(height)) return null;
  if (width <= 0 || height <= 0 || width > MAX_CURSOR_SOURCE || height > MAX_CURSOR_SOURCE) return null;
  const bytes = base64ToBytes(shape.rgba_base64);
  if (!bytes || bytes.length !== width * height * 4) return null;
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d");
  if (!context) return null;
  context.putImageData(new ImageData(bytes, width, height), 0, 0);
  return canvas;
}

function renderCursor(source: HTMLCanvasElement, width: number, height: number): string | null {
  try {
    if (width === source.width && height === source.height) return source.toDataURL("image/png");
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    if (!context) return null;
    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = "high";
    context.drawImage(source, 0, 0, width, height);
    return canvas.toDataURL("image/png");
  } catch {
    return null;
  }
}
