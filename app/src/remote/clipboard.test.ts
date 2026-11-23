import { describe, expect, it } from "vitest";
import { ClipboardSync, MAX_CLIPBOARD_CHARS, shouldSendClipboard } from "./clipboard";

describe("shouldSendClipboard", () => {
  it("sends new text only", () => {
    expect(shouldSendClipboard("hello", null)).toBe(true);
    expect(shouldSendClipboard("hello", "hello")).toBe(false);
    expect(shouldSendClipboard("hello", "other")).toBe(true);
  });

  it("never sends nothing, or something huge", () => {
    expect(shouldSendClipboard("", null)).toBe(false);
    expect(shouldSendClipboard(null, null)).toBe(false);
    expect(shouldSendClipboard(undefined, "x")).toBe(false);
    expect(shouldSendClipboard("x".repeat(MAX_CLIPBOARD_CHARS + 1), null)).toBe(false);
  });
});

describe("ClipboardSync", () => {
  function setup(initial: string) {
    const state = { local: initial, sent: [] as string[], open: true, failRead: false, enabled: true };
    const sync = new ClipboardSync(
      {
        readClipboard: () => (state.failRead ? Promise.reject(new Error("no text")) : Promise.resolve(state.local)),
        writeClipboard: (text) => {
          state.local = text;
          return Promise.resolve();
        },
      },
      (text) => state.sent.push(text),
      () => state.open,
      () => state.enabled,
    );
    return { state, sync };
  }

  it("sends the local clipboard once until it changes", async () => {
    const { state, sync } = setup("one");
    await sync.pushLocal();
    await sync.pushLocal();
    expect(state.sent).toEqual(["one"]);
    state.local = "two";
    await sync.pushLocal();
    expect(state.sent).toEqual(["one", "two"]);
  });

  it("does not echo remote text back", async () => {
    const { state, sync } = setup("");
    await sync.receiveRemote("from remote");
    expect(state.local).toBe("from remote");
    await sync.pushLocal();
    expect(state.sent).toEqual([]);
  });

  it("sends nothing when the session is not connected or the read fails", async () => {
    const { state, sync } = setup("text");
    state.open = false;
    await sync.pushLocal();
    state.open = true;
    state.failRead = true;
    await sync.pushLocal();
    expect(state.sent).toEqual([]);
  });

  it("sends again after a reset (a new connection)", async () => {
    const { state, sync } = setup("same");
    await sync.pushLocal();
    sync.reset();
    await sync.pushLocal();
    expect(state.sent).toEqual(["same", "same"]);
  });

  it("ignores remote text over the limit", async () => {
    const { state, sync } = setup("mine");
    await sync.receiveRemote("x".repeat(MAX_CLIPBOARD_CHARS + 1));
    expect(state.local).toBe("mine");
    await sync.receiveRemote("y".repeat(MAX_CLIPBOARD_CHARS));
    expect(state.local.length).toBe(MAX_CLIPBOARD_CHARS);
  });

  it("passes nothing either way when sharing is off", async () => {
    const { state, sync } = setup("local text");
    state.enabled = false;
    await sync.pushLocal();
    await sync.receiveRemote("remote text");
    expect(state.sent).toEqual([]);
    expect(state.local).toBe("local text");
  });
});
