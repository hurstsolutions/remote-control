// The two log actions offered on the home screen and on every error panel.
import { button, flashLabel } from "./dom";
import type { Platform } from "./platform";

export function copyLogButton(platform: Platform): HTMLButtonElement {
  const element = button("Copy log", () => {
    platform.api
      .logText()
      .then((text) => platform.writeClipboard(text))
      .then(
        () => flashLabel(element, "Copied"),
        (error: unknown) => {
          console.error("copy log failed", error);
          flashLabel(element, "Couldn't copy the log", 2500);
        },
      );
  });
  element.title = "Copy the recent log to the clipboard";
  return element;
}

export function showLogFileButton(platform: Platform): HTMLButtonElement {
  const element = button("Show log file", () => {
    platform.api.revealLog().catch((error: unknown) => {
      console.error("reveal log failed", error);
      flashLabel(element, "Couldn't open the log folder", 2500);
    });
  });
  return element;
}
