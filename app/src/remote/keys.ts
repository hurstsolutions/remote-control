// Tracks which keys are held on the remote and turns browser key events into the key messages
// to send. Pure: no DOM.

export interface KeyMessage {
  code: string;
  key: string;
  down: boolean;
}

const MODIFIER_CODES = new Set([
  "ShiftLeft",
  "ShiftRight",
  "ControlLeft",
  "ControlRight",
  "AltLeft",
  "AltRight",
  "MetaLeft",
  "MetaRight",
  "OSLeft",
  "OSRight",
  "CapsLock",
  "Fn",
]);

export function isModifierCode(code: string): boolean {
  return MODIFIER_CODES.has(code);
}

export function isMetaCode(code: string): boolean {
  return code === "MetaLeft" || code === "MetaRight" || code === "OSLeft" || code === "OSRight";
}

export interface HeldKeysOptions {
  /**
   * macOS webviews report Caps Lock as a keydown when it turns on and a keyup when it turns
   * off. With this set, each of those is sent as a full press and release so that the remote
   * toggles once per physical press.
   */
  macCapsLock?: boolean;
}

export class HeldKeys {
  /** id -> the message that pressed it. */
  private readonly held = new Map<string, KeyMessage>();
  private readonly macCapsLock: boolean;

  constructor(options: HeldKeysOptions = {}) {
    this.macCapsLock = options.macCapsLock === true;
  }

  get size(): number {
    return this.held.size;
  }

  /** Codes currently held (the key value for keys that have no code). */
  codes(): string[] {
    return [...this.held.values()].map((m) => m.code || m.key);
  }

  /** A keydown, including auto-repeat: always forwarded as a down. */
  keyDown(code: string, key: string): KeyMessage[] {
    if (this.macCapsLock && code === "CapsLock") return tap(code, key);
    const message: KeyMessage = { code, key, down: true };
    this.held.set(idOf(code, key), message);
    return [message];
  }

  /**
   * A keyup. Keys we never saw go down are ignored. When Meta (Cmd) is released, every
   * non-modifier key still marked down is released first: macOS webviews never deliver keyup
   * for other keys while Cmd is held, so they would otherwise stay stuck on the remote.
   */
  keyUp(code: string, key: string): KeyMessage[] {
    if (this.macCapsLock && code === "CapsLock") return tap(code, key);
    const out: KeyMessage[] = [];
    if (isMetaCode(code)) {
      for (const [id, message] of this.held) {
        if (!isModifierCode(message.code)) {
          this.held.delete(id);
          out.push({ code: message.code, key: message.key, down: false });
        }
      }
    }
    const id = this.find(code, key);
    if (id !== null) {
      this.held.delete(id);
      out.push({ code, key, down: false });
    }
    return out;
  }

  /** Forget everything (the caller sends release_all). */
  clear(): void {
    this.held.clear();
  }

  private find(code: string, key: string): string | null {
    const id = idOf(code, key);
    if (this.held.has(id)) return id;
    return null;
  }
}

function idOf(code: string, key: string): string {
  // The key value can differ between down and up (Shift released first), so prefer the code.
  return code !== "" ? code : `key:${key}`;
}

function tap(code: string, key: string): KeyMessage[] {
  return [
    { code, key, down: true },
    { code, key, down: false },
  ];
}
