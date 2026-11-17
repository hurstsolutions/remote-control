import { describe, expect, it } from "vitest";
import { HeldKeys, isMetaCode, isModifierCode } from "./keys";

describe("HeldKeys", () => {
  it("forwards downs and ups and tracks what is held", () => {
    const keys = new HeldKeys();
    expect(keys.keyDown("KeyA", "a")).toEqual([{ code: "KeyA", key: "a", down: true }]);
    expect(keys.codes()).toEqual(["KeyA"]);
    expect(keys.keyUp("KeyA", "a")).toEqual([{ code: "KeyA", key: "a", down: false }]);
    expect(keys.size).toBe(0);
  });

  it("forwards auto-repeat as repeated downs", () => {
    const keys = new HeldKeys();
    keys.keyDown("KeyA", "a");
    expect(keys.keyDown("KeyA", "a")).toEqual([{ code: "KeyA", key: "a", down: true }]);
    expect(keys.keyDown("KeyA", "a")).toHaveLength(1);
    expect(keys.size).toBe(1);
  });

  it("ignores a keyup for a key it never saw go down", () => {
    const keys = new HeldKeys();
    expect(keys.keyUp("Enter", "Enter")).toEqual([]);
  });

  it("matches the up by code when the key value changed", () => {
    const keys = new HeldKeys();
    keys.keyDown("ShiftLeft", "Shift");
    keys.keyDown("KeyA", "A");
    keys.keyUp("ShiftLeft", "Shift");
    expect(keys.keyUp("KeyA", "a")).toEqual([{ code: "KeyA", key: "a", down: false }]);
    expect(keys.size).toBe(0);
  });

  it("releases stuck keys when Meta is released (macOS never sends their keyup)", () => {
    const keys = new HeldKeys();
    keys.keyDown("MetaLeft", "Meta");
    keys.keyDown("KeyC", "c");
    keys.keyDown("KeyV", "v");
    // No keyup for C or V arrives while Cmd is held.
    expect(keys.keyUp("MetaLeft", "Meta")).toEqual([
      { code: "KeyC", key: "c", down: false },
      { code: "KeyV", key: "v", down: false },
      { code: "MetaLeft", key: "Meta", down: false },
    ]);
    expect(keys.size).toBe(0);
    // A late real keyup is then ignored rather than sent twice.
    expect(keys.keyUp("KeyC", "c")).toEqual([]);
  });

  it("keeps other modifiers held when Meta is released", () => {
    const keys = new HeldKeys();
    keys.keyDown("ShiftLeft", "Shift");
    keys.keyDown("MetaRight", "Meta");
    keys.keyDown("KeyZ", "Z");
    const out = keys.keyUp("MetaRight", "Meta");
    expect(out.map((m) => m.code)).toEqual(["KeyZ", "MetaRight"]);
    expect(keys.codes()).toEqual(["ShiftLeft"]);
  });

  it("still releases stuck keys when the Meta press itself was not seen", () => {
    const keys = new HeldKeys();
    keys.keyDown("KeyC", "c");
    expect(keys.keyUp("MetaLeft", "Meta")).toEqual([{ code: "KeyC", key: "c", down: false }]);
  });

  it("clear forgets everything", () => {
    const keys = new HeldKeys();
    keys.keyDown("KeyA", "a");
    keys.keyDown("ControlLeft", "Control");
    keys.clear();
    expect(keys.size).toBe(0);
    expect(keys.keyUp("KeyA", "a")).toEqual([]);
  });

  it("tracks keys without a code by their key value", () => {
    const keys = new HeldKeys();
    keys.keyDown("", "AudioVolumeUp");
    expect(keys.codes()).toEqual(["AudioVolumeUp"]);
    expect(keys.keyUp("", "AudioVolumeUp")).toEqual([{ code: "", key: "AudioVolumeUp", down: false }]);
  });

  it("turns each macOS Caps Lock event into a full press", () => {
    const keys = new HeldKeys({ macCapsLock: true });
    const tap = [
      { code: "CapsLock", key: "CapsLock", down: true },
      { code: "CapsLock", key: "CapsLock", down: false },
    ];
    expect(keys.keyDown("CapsLock", "CapsLock")).toEqual(tap); // turned on
    expect(keys.size).toBe(0);
    expect(keys.keyUp("CapsLock", "CapsLock")).toEqual(tap); // turned off
  });

  it("treats Caps Lock normally elsewhere", () => {
    const keys = new HeldKeys();
    expect(keys.keyDown("CapsLock", "CapsLock")).toHaveLength(1);
    expect(keys.keyUp("CapsLock", "CapsLock")).toEqual([{ code: "CapsLock", key: "CapsLock", down: false }]);
  });

  it("classifies modifier codes", () => {
    expect(isModifierCode("AltRight")).toBe(true);
    expect(isModifierCode("KeyA")).toBe(false);
    expect(isMetaCode("MetaLeft")).toBe(true);
    expect(isMetaCode("OSRight")).toBe(true);
    expect(isMetaCode("ControlLeft")).toBe(false);
  });
});
