// Pure maths for the remote screen: frame headers, scaling, coordinate mapping, wheel and
// button conversion. Nothing in here touches the DOM, so all of it is unit tested.
import type { MouseButton } from "../ipc";

/** Must equal FRAME_HEADER_BYTES in ipc.ts (checked by a test). */
export const HEADER_BYTES = 8;

export interface FrameRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * A binary message holds one or more frames back to back, each an 8-byte little-endian header
 * (x, y, w, h as u16) followed by w*h*4 bytes of RGBA.
 *
 * Read the header at `offset` into `out` and return the offset of the next frame (the pixels
 * are at `offset + HEADER_BYTES`). Returns -1 when no complete frame starts at `offset`: the
 * header is cut short or claims more pixel bytes than remain. The caller then stops and
 * ignores the rest of the message. An empty rectangle (w or h of 0) is valid and has no pixels.
 */
export function readFrameHeader(view: DataView, offset: number, out: FrameRect): number {
  if (offset < 0 || offset + HEADER_BYTES > view.byteLength) return -1;
  out.x = view.getUint16(offset, true);
  out.y = view.getUint16(offset + 2, true);
  out.w = view.getUint16(offset + 4, true);
  out.h = view.getUint16(offset + 6, true);
  const next = offset + HEADER_BYTES + out.w * out.h * 4;
  return next <= view.byteLength ? next : -1;
}

/** Every complete frame in a message, in order. For tests and tools; painting uses the loop directly. */
export function listFrames(buffer: ArrayBuffer): Array<FrameRect & { pixelOffset: number }> {
  const view = new DataView(buffer);
  const out: Array<FrameRect & { pixelOffset: number }> = [];
  const rect: FrameRect = { x: 0, y: 0, w: 0, h: 0 };
  let offset = 0;
  while (offset < view.byteLength) {
    const next = readFrameHeader(view, offset, rect);
    if (next < 0) break;
    out.push({ ...rect, pixelOffset: offset + HEADER_BYTES });
    offset = next;
  }
  return out;
}

/** True when the rectangle lies entirely inside a width x height framebuffer. */
export function rectFits(rect: FrameRect, width: number, height: number): boolean {
  return rect.x + rect.w <= width && rect.y + rect.h <= height;
}

export type DisplayMode = "fit" | "actual";

export interface Layout {
  /** CSS size and position of the canvas inside the viewport. */
  cssWidth: number;
  cssHeight: number;
  left: number;
  top: number;
  /** CSS pixels per remote pixel. */
  scale: number;
  /** Smooth interpolation (true) or crisp pixels (false). */
  smooth: boolean;
  /** The canvas is larger than the viewport, so the viewport scrolls. */
  scroll: boolean;
}

/** An upscale smaller than this is not worth the blur: show 1:1 with a thin border instead. */
const SNAP_TO_ONE = 1.05;

/**
 * Work out where and how large the canvas is drawn.
 *
 * "fit": the largest size that fits the viewport with the aspect ratio kept, centred. When the
 * remote is larger than the viewport (in physical pixels) it is scaled down; when it is
 * smaller it is scaled up, except that a nearly exact match stays at exactly 1 remote pixel =
 * 1 physical pixel so that a session sized to the window is perfectly sharp.
 * "actual": 1 remote pixel = 1 physical pixel, centred when smaller, scrolling when larger.
 */
export function layoutScreen(
  mode: DisplayMode,
  viewWidth: number,
  viewHeight: number,
  remoteWidth: number,
  remoteHeight: number,
  dpr: number,
): Layout {
  const ratio = dpr > 0 ? dpr : 1;
  let physScale = 1;
  if (mode === "fit") {
    physScale = Math.min((viewWidth * ratio) / remoteWidth, (viewHeight * ratio) / remoteHeight);
    if (!(physScale > 0) || !Number.isFinite(physScale)) physScale = 1;
    if (physScale >= 1 && physScale < SNAP_TO_ONE) physScale = 1;
  }
  const scale = physScale / ratio;
  const cssWidth = remoteWidth * scale;
  const cssHeight = remoteHeight * scale;
  // Snap the offset to whole physical pixels so that 1:1 content is not resampled.
  const snap = (v: number) => Math.max(0, Math.round(v * ratio) / ratio);
  const nearInteger = Math.abs(physScale - Math.round(physScale)) < 1e-3;
  return {
    cssWidth,
    cssHeight,
    left: snap((viewWidth - cssWidth) / 2),
    top: snap((viewHeight - cssHeight) / 2),
    scale,
    smooth: !(physScale >= 1 && nearInteger),
    scroll: cssWidth > viewWidth + 0.5 || cssHeight > viewHeight + 0.5,
  };
}

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface Point {
  x: number;
  y: number;
}

/** Map a client (CSS) position to a remote framebuffer pixel, clamped to the framebuffer. */
export function clientToRemote(
  clientX: number,
  clientY: number,
  box: Box,
  remoteWidth: number,
  remoteHeight: number,
): Point {
  const map = (client: number, start: number, size: number, remote: number) => {
    if (!(size > 0) || remote <= 0) return 0;
    const v = Math.floor(((client - start) * remote) / size);
    return Math.min(remote - 1, Math.max(0, v));
  };
  return {
    x: map(clientX, box.left, box.width, remoteWidth),
    y: map(clientY, box.top, box.height, remoteHeight),
  };
}

/**
 * Convert a browser wheel event to notches. The browser's deltaY is positive when scrolling
 * down, the remote wants positive dy for wheel up; dx is positive to the right in both.
 * deltaMode: 0 = pixels, 1 = lines, 2 = pages.
 */
export function wheelNotches(deltaX: number, deltaY: number, deltaMode: number): { dx: number; dy: number } {
  const divisor = deltaMode === 0 ? 100 : deltaMode === 1 ? 3 : 1;
  const dx = deltaX / divisor;
  const dy = -deltaY / divisor;
  // Avoid sending -0.
  return { dx: dx === 0 ? 0 : dx, dy: dy === 0 ? 0 : dy };
}

export const MIN_REMOTE_WIDTH = 640;
export const MIN_REMOTE_HEIGHT = 480;
const MAX_REMOTE_SIZE = 8192;

/** The remote desktop size to ask for, in physical pixels, for a viewport in CSS pixels. */
export function remoteSizeForViewport(cssWidth: number, cssHeight: number, dpr: number): { width: number; height: number } {
  const ratio = dpr > 0 ? dpr : 1;
  // Round down (to an even number) so the remote never exceeds the viewport: it then shows at
  // exactly 1:1 instead of being scaled down by a fraction of a percent, which would blur it.
  const even = (css: number, min: number) => {
    const px = Math.floor(css * ratio + 1e-6) & ~1;
    return Math.min(MAX_REMOTE_SIZE, Math.max(min, px));
  };
  return { width: even(cssWidth, MIN_REMOTE_WIDTH), height: even(cssHeight, MIN_REMOTE_HEIGHT) };
}

export const MAX_CURSOR_CSS = 128;

/**
 * The CSS size of a remote cursor bitmap at the current display scale, or null when it would
 * be empty or larger than 128x128 CSS pixels (the caller then falls back to the arrow).
 */
export function cursorCssSize(width: number, height: number, scale: number): { width: number; height: number } | null {
  if (!(width > 0) || !(height > 0) || !(scale > 0)) return null;
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  if (w > MAX_CURSOR_CSS || h > MAX_CURSOR_CSS) return null;
  return { width: w, height: h };
}

/** MouseEvent.button -> remote button. */
export function buttonFromIndex(index: number): MouseButton | null {
  switch (index) {
    case 0:
      return "left";
    case 1:
      return "middle";
    case 2:
      return "right";
    case 3:
      return "back";
    case 4:
      return "forward";
    default:
      return null;
  }
}

// MouseEvent.buttons bit for each MouseEvent.button index (note 1 and 2 are swapped).
const BUTTON_BITS: ReadonlyArray<readonly [bit: number, index: number]> = [
  [1, 0],
  [4, 1],
  [2, 2],
  [8, 3],
  [16, 4],
];

export const ALL_BUTTONS_MASK = 31;

/**
 * Which buttons changed between two MouseEvent.buttons bitmasks. Using the bitmask rather than
 * pointerdown/pointerup alone also catches a second button pressed while one is already held,
 * which browsers report as a pointermove.
 */
export function changedButtons(prev: number, next: number): Array<{ button: MouseButton; down: boolean }> {
  const out: Array<{ button: MouseButton; down: boolean }> = [];
  const diff = (prev ^ next) & ALL_BUTTONS_MASK;
  if (diff === 0) return out;
  for (const [bit, index] of BUTTON_BITS) {
    if (diff & bit) {
      const button = buttonFromIndex(index);
      if (button) out.push({ button, down: (next & bit) !== 0 });
    }
  }
  return out;
}

/** Decode base64 to bytes. Returns null when the text is not valid base64. */
export function base64ToBytes(base64: string): Uint8ClampedArray<ArrayBuffer> | null {
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    return null;
  }
  const bytes = new Uint8ClampedArray(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
