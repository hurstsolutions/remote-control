// Run something every few seconds, but only while an element is on screen and the window has focus.

/** On screen: attached and not inside anything hidden. */
export function isShown(element: HTMLElement): boolean {
  return element.isConnected && element.getClientRects().length > 0;
}

/**
 * Call `tick` every `ms` while `element` is shown and the window is focused, and once on coming
 * back to the window when a tick is overdue. Returns a function that stops it.
 */
export function pollWhileVisible(element: HTMLElement, ms: number, tick: () => void): () => void {
  let last = Date.now();
  const run = () => {
    if (!document.hasFocus() || !isShown(element)) return;
    last = Date.now();
    tick();
  };
  const timer = window.setInterval(run, ms);
  const onFocus = () => {
    if (Date.now() - last >= ms) run();
  };
  window.addEventListener("focus", onFocus);
  return () => {
    window.clearInterval(timer);
    window.removeEventListener("focus", onFocus);
  };
}
