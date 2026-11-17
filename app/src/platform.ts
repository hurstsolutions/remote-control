// Everything the UI needs from outside the web page: the IPC api, the clipboard and the window.
// The real implementation talks to Tauri; a mock stands in when running in a plain browser.
import type { api } from "./ipc";

export type Api = typeof api;

export interface Platform {
  readonly api: Api;
  readonly isMock: boolean;
  /** Local clipboard text; rejects or returns "" when the clipboard holds no text. */
  readClipboard(): Promise<string>;
  writeClipboard(text: string): Promise<void>;
  setFullscreen(on: boolean): Promise<void>;
  isFullscreen(): Promise<boolean>;
}

export function hasTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Load the Tauri platform inside the app, the mock in a plain browser (vite dev). */
export async function loadPlatform(): Promise<Platform> {
  if (hasTauri()) {
    const module = await import("./platform-tauri");
    return module.createTauriPlatform();
  }
  const module = await import("./mock/platform");
  return module.createMockPlatform();
}

export function isMac(): boolean {
  return /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
}
