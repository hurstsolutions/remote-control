// The real platform: Tauri IPC, the clipboard plugin and the window API.
import { getCurrentWindow } from "@tauri-apps/api/window";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { api } from "./ipc";
import type { Platform } from "./platform";

export function createTauriPlatform(): Platform {
  return {
    api,
    isMock: false,
    readClipboard: () => readText(),
    writeClipboard: (text) => writeText(text),
    setFullscreen: (on) => getCurrentWindow().setFullscreen(on),
    isFullscreen: () => getCurrentWindow().isFullscreen(),
  };
}
