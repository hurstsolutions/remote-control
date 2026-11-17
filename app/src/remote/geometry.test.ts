import { describe, expect, it } from "vitest";
import { FRAME_HEADER_BYTES } from "../ipc";
import {
  HEADER_BYTES,
  base64ToBytes,
  buttonFromIndex,
  changedButtons,
  clientToRemote,
  cursorCssSize,
  layoutScreen,
  listFrames,
  readFrameHeader,
  rectFits,
  remoteSizeForViewport,
  wheelNotches,
  type FrameRect,
} from "./geometry";

function frame(x: number, y: number, w: number, h: number, fill = 7): Uint8Array {
  const bytes = new Uint8Array(HEADER_BYTES + w * h * 4).fill(fill);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, x, true);
  view.setUint16(2, y, true);
  view.setUint16(4, w, true);
  view.setUint16(6, h, true);
  return bytes;
}

function join(...parts: Uint8Array[]): ArrayBuffer {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out.buffer;
}

describe("frame parsing", () => {
  it("uses the header size from the contract", () => {
    expect(HEADER_BYTES).toBe(FRAME_HEADER_BYTES);
  });

  it("reads a little-endian header and returns the next offset", () => {
    const buffer = join(frame(300, 513, 2, 3));
    const rect: FrameRect = { x: 0, y: 0, w: 0, h: 0 };
    expect(readFrameHeader(new DataView(buffer), 0, rect)).toBe(8 + 2 * 3 * 4);
    expect(rect).toEqual({ x: 300, y: 513, w: 2, h: 3 });
  });

  it("reads coordinates above 32767 as unsigned", () => {
    const rect: FrameRect = { x: 0, y: 0, w: 0, h: 0 };
    readFrameHeader(new DataView(join(frame(40000, 65535, 1, 1))), 0, rect);
    expect(rect.x).toBe(40000);
    expect(rect.y).toBe(65535);
  });

  it("parses several frames in one message", () => {
    const frames = listFrames(join(frame(0, 0, 4, 4), frame(10, 20, 1, 2), frame(5, 6, 3, 1)));
    expect(frames).toEqual([
      { x: 0, y: 0, w: 4, h: 4, pixelOffset: 8 },
      { x: 10, y: 20, w: 1, h: 2, pixelOffset: 8 + 64 + 8 },
      { x: 5, y: 6, w: 3, h: 1, pixelOffset: 8 + 64 + 8 + 8 + 8 },
    ]);
  });

  it("stops at a frame whose header claims more bytes than remain", () => {
    const short = frame(1, 1, 4, 4).slice(0, 8 + 10);
    const frames = listFrames(join(frame(0, 0, 2, 2), short, frame(9, 9, 1, 1)));
    expect(frames).toHaveLength(1);
    expect(frames[0]).toMatchObject({ x: 0, y: 0, w: 2, h: 2 });
  });

  it("stops at a header that is cut short", () => {
    expect(listFrames(join(frame(0, 0, 1, 1), new Uint8Array(5)))).toHaveLength(1);
    expect(listFrames(new ArrayBuffer(7))).toEqual([]);
    expect(listFrames(new ArrayBuffer(0))).toEqual([]);
  });

  it("accepts an empty rectangle and carries on", () => {
    const frames = listFrames(join(frame(3, 3, 0, 5), frame(1, 2, 1, 1)));
    expect(frames).toHaveLength(2);
    expect(frames[1]).toMatchObject({ x: 1, y: 2, pixelOffset: 16 });
  });

  it("rejects a negative or out-of-range offset", () => {
    const rect: FrameRect = { x: 0, y: 0, w: 0, h: 0 };
    const view = new DataView(join(frame(0, 0, 1, 1)));
    expect(readFrameHeader(view, -1, rect)).toBe(-1);
    expect(readFrameHeader(view, 12, rect)).toBe(-1);
    expect(readFrameHeader(view, 5, rect)).toBe(-1);
  });

  it("checks whether a rectangle lies inside the framebuffer", () => {
    expect(rectFits({ x: 0, y: 0, w: 100, h: 50 }, 100, 50)).toBe(true);
    expect(rectFits({ x: 90, y: 0, w: 11, h: 1 }, 100, 50)).toBe(false);
    expect(rectFits({ x: 0, y: 49, w: 1, h: 2 }, 100, 50)).toBe(false);
    expect(rectFits({ x: 0, y: 0, w: 1, h: 1 }, 0, 0)).toBe(false);
  });
});

describe("layoutScreen", () => {
  it("scales down to fit, keeping the aspect ratio, centred", () => {
    const l = layoutScreen("fit", 800, 600, 1600, 900, 1);
    expect(l.scale).toBeCloseTo(0.5);
    expect(l.cssWidth).toBeCloseTo(800);
    expect(l.cssHeight).toBeCloseTo(450);
    expect(l.left).toBe(0);
    expect(l.top).toBe(75);
    expect(l.smooth).toBe(true);
    expect(l.scroll).toBe(false);
  });

  it("letterboxes left and right when the viewport is wider", () => {
    const l = layoutScreen("fit", 1000, 400, 800, 800, 1);
    expect(l.cssWidth).toBeCloseTo(400);
    expect(l.left).toBe(300);
    expect(l.top).toBe(0);
  });

  it("shows a remote sized to the window at exactly one physical pixel each", () => {
    // 1001 x 701 CSS at 2x: the remote was requested as 2002 x 1402.
    const l = layoutScreen("fit", 1001, 701, 2002, 1402, 2);
    expect(l.scale).toBe(0.5);
    expect(l.smooth).toBe(false);
    // An odd viewport leaves the remote a pixel short: still exactly 1:1.
    const odd = layoutScreen("fit", 1001, 701, 1000, 700, 1);
    expect(odd.scale).toBe(1);
    expect(odd.cssWidth).toBe(1000);
    expect(odd.smooth).toBe(false);
  });

  it("scales up when the window is clearly larger than the remote", () => {
    const l = layoutScreen("fit", 2000, 1500, 1000, 500, 1);
    expect(l.scale).toBeCloseTo(2);
    expect(l.smooth).toBe(false); // whole multiple: crisp
    const fractional = layoutScreen("fit", 1500, 1500, 1000, 500, 1);
    expect(fractional.scale).toBeCloseTo(1.5);
    expect(fractional.smooth).toBe(true);
  });

  it("counts physical pixels on a high-density display", () => {
    // 1920x1080 remote in a 1440x900 CSS window at 2x has room for 1:1 and more.
    const l = layoutScreen("fit", 1440, 900, 1920, 1080, 2);
    expect(l.scale).toBeCloseTo(0.75);
    expect(l.cssWidth).toBeCloseTo(1440);
  });

  it("actual size is one physical pixel per remote pixel and scrolls when larger", () => {
    const l = layoutScreen("actual", 800, 600, 1920, 1080, 2);
    expect(l.scale).toBe(0.5);
    expect(l.cssWidth).toBe(960);
    expect(l.cssHeight).toBe(540);
    expect(l.left).toBe(0);
    expect(l.top).toBe(30);
    expect(l.scroll).toBe(true);
    expect(l.smooth).toBe(false);
    const small = layoutScreen("actual", 800, 600, 640, 480, 1);
    expect(small.scroll).toBe(false);
    expect(small.left).toBe(80);
    expect(small.top).toBe(60);
  });

  it("snaps offsets to whole physical pixels", () => {
    const l = layoutScreen("actual", 801, 600, 640, 480, 2);
    expect((l.left * 2) % 1).toBe(0);
  });

  it("survives a zero-sized viewport", () => {
    const l = layoutScreen("fit", 0, 0, 800, 600, 1);
    expect(Number.isFinite(l.scale)).toBe(true);
    expect(l.scale).toBeGreaterThan(0);
  });
});

describe("clientToRemote", () => {
  const box = { left: 100, top: 50, width: 400, height: 300 };

  it("maps through the canvas box", () => {
    expect(clientToRemote(100, 50, box, 800, 600)).toEqual({ x: 0, y: 0 });
    expect(clientToRemote(300, 200, box, 800, 600)).toEqual({ x: 400, y: 300 });
    expect(clientToRemote(499.9, 349.9, box, 800, 600)).toEqual({ x: 799, y: 599 });
  });

  it("clamps positions outside the canvas", () => {
    expect(clientToRemote(0, 0, box, 800, 600)).toEqual({ x: 0, y: 0 });
    expect(clientToRemote(5000, 5000, box, 800, 600)).toEqual({ x: 799, y: 599 });
    expect(clientToRemote(500, 350, box, 800, 600)).toEqual({ x: 799, y: 599 });
  });

  it("returns the origin for an empty box or framebuffer", () => {
    expect(clientToRemote(10, 10, { left: 0, top: 0, width: 0, height: 0 }, 800, 600)).toEqual({ x: 0, y: 0 });
    expect(clientToRemote(10, 10, box, 0, 0)).toEqual({ x: 0, y: 0 });
  });
});

describe("wheelNotches", () => {
  it("pixel mode: 100 pixels is one notch, down is negative", () => {
    expect(wheelNotches(0, 100, 0)).toEqual({ dx: 0, dy: -1 });
    expect(wheelNotches(0, -250, 0)).toEqual({ dx: 0, dy: 2.5 });
    expect(wheelNotches(50, 0, 0)).toEqual({ dx: 0.5, dy: 0 });
  });

  it("line mode: three lines is one notch", () => {
    expect(wheelNotches(0, 3, 1)).toEqual({ dx: 0, dy: -1 });
    expect(wheelNotches(-6, 0, 1)).toEqual({ dx: -2, dy: 0 });
  });

  it("page mode: one page is one notch", () => {
    expect(wheelNotches(0, -1, 2)).toEqual({ dx: 0, dy: 1 });
  });

  it("never produces negative zero", () => {
    const { dx, dy } = wheelNotches(0, 0, 0);
    expect(Object.is(dx, 0)).toBe(true);
    expect(Object.is(dy, 0)).toBe(true);
  });
});

describe("remoteSizeForViewport", () => {
  it("multiplies by the pixel ratio", () => {
    expect(remoteSizeForViewport(1200, 700, 2)).toEqual({ width: 2400, height: 1400 });
  });

  it("rounds down to even numbers", () => {
    expect(remoteSizeForViewport(1001, 701, 1)).toEqual({ width: 1000, height: 700 });
    expect(remoteSizeForViewport(801, 601, 1.5)).toEqual({ width: 1200, height: 900 });
  });

  it("never asks for less than 640 x 480", () => {
    expect(remoteSizeForViewport(200, 100, 1)).toEqual({ width: 640, height: 480 });
    expect(remoteSizeForViewport(0, 0, 2)).toEqual({ width: 640, height: 480 });
  });

  it("never exceeds the viewport, so fit shows it 1:1", () => {
    for (const dpr of [1, 1.25, 1.5, 2, 3]) {
      for (const css of [641, 777, 1023, 1440]) {
        const size = remoteSizeForViewport(css, css, dpr);
        expect(size.width).toBeLessThanOrEqual(css * dpr + 1e-6);
        expect(size.width % 2).toBe(0);
        expect(layoutScreen("fit", css, css, size.width, size.height, dpr).scale).toBeCloseTo(1 / dpr, 10);
      }
    }
  });
});

describe("cursorCssSize", () => {
  it("scales with the display", () => {
    expect(cursorCssSize(64, 64, 0.5)).toEqual({ width: 32, height: 32 });
    expect(cursorCssSize(32, 48, 1)).toEqual({ width: 32, height: 48 });
  });

  it("falls back beyond 128 CSS pixels", () => {
    expect(cursorCssSize(128, 128, 1)).toEqual({ width: 128, height: 128 });
    expect(cursorCssSize(129, 10, 1)).toBeNull();
    expect(cursorCssSize(96, 96, 2)).toBeNull();
  });

  it("rejects empty bitmaps and keeps tiny ones visible", () => {
    expect(cursorCssSize(0, 10, 1)).toBeNull();
    expect(cursorCssSize(2, 2, 0.1)).toEqual({ width: 1, height: 1 });
  });
});

describe("buttons", () => {
  it("maps button indexes", () => {
    expect([0, 1, 2, 3, 4].map(buttonFromIndex)).toEqual(["left", "middle", "right", "back", "forward"]);
    expect(buttonFromIndex(5)).toBeNull();
  });

  it("reports presses and releases from the buttons bitmask", () => {
    expect(changedButtons(0, 1)).toEqual([{ button: "left", down: true }]);
    expect(changedButtons(1, 0)).toEqual([{ button: "left", down: false }]);
    expect(changedButtons(0, 2)).toEqual([{ button: "right", down: true }]);
    expect(changedButtons(0, 4)).toEqual([{ button: "middle", down: true }]);
    expect(changedButtons(8, 16)).toEqual([
      { button: "back", down: false },
      { button: "forward", down: true },
    ]);
  });

  it("catches a second button pressed during a drag", () => {
    expect(changedButtons(1, 3)).toEqual([{ button: "right", down: true }]);
    expect(changedButtons(3, 3)).toEqual([]);
    expect(changedButtons(3, 0)).toHaveLength(2);
  });

  it("ignores bits beyond the five buttons", () => {
    expect(changedButtons(0, 32)).toEqual([]);
  });
});

describe("base64ToBytes", () => {
  it("decodes bytes", () => {
    expect([...(base64ToBytes("AP+AAQ==") ?? [])]).toEqual([0, 255, 128, 1]);
    expect(base64ToBytes("")?.length).toBe(0);
  });

  it("returns null for invalid input", () => {
    expect(base64ToBytes("***")).toBeNull();
  });
});
