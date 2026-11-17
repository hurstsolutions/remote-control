// Modal dialogs: focus trap, Esc to cancel, Enter to submit, focus restored on close.
import { button, h } from "./dom";

export interface DialogOptions<T> {
  title: string;
  /** Form content. */
  body: HTMLElement;
  submitLabel: string;
  cancelLabel?: string;
  danger?: boolean;
  /**
   * Called on submit. Return the result to close the dialog with it, or undefined to keep the
   * dialog open (validation failed). May be async; the buttons are disabled meanwhile.
   */
  onSubmit: () => T | undefined | Promise<T | undefined>;
}

const FOCUSABLE =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

let openCount = 0;

export function isDialogOpen(): boolean {
  return openCount > 0;
}

/** Open a modal dialog. Resolves with the submit result, or null when cancelled. */
export function openDialog<T>(options: DialogOptions<T>): Promise<T | null> {
  return new Promise((resolve) => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const appRoot = document.getElementById("app");
    let busy = false;
    let done = false;

    const titleId = `dialog-title-${Date.now().toString(36)}`;
    const submit = button(options.submitLabel, () => undefined, {
      kind: options.danger ? "danger" : "primary",
      submit: true,
    });
    const cancel = button(options.cancelLabel ?? "Cancel", () => finish(null));
    const form = h(
      "form",
      { class: "dialog", attrs: { role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, novalidate: "" } },
      h("h2", { class: "dialog-title", text: options.title, attrs: { id: titleId } }),
      h("div", { class: "dialog-body" }, options.body),
      h("div", { class: "dialog-footer" }, cancel, submit),
    );
    const overlay = h("div", { class: "dialog-overlay" }, form);

    function finish(result: T | null): void {
      if (done) return;
      done = true;
      openCount--;
      overlay.remove();
      if (openCount === 0) appRoot?.removeAttribute("inert");
      if (previousFocus && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
      resolve(result);
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (busy) return;
      busy = true;
      submit.disabled = true;
      Promise.resolve()
        .then(options.onSubmit)
        .then(
          (result) => {
            if (result !== undefined) finish(result);
          },
          (error: unknown) => console.error("dialog submit failed", error),
        )
        .finally(() => {
          busy = false;
          submit.disabled = false;
        });
    });

    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        finish(null);
        return;
      }
      if (event.key !== "Tab") return;
      const items = [...form.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) {
        event.preventDefault();
        return;
      }
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !form.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !form.contains(active))) {
        event.preventDefault();
        first.focus();
      }
    });

    // A press on the backdrop keeps focus inside the dialog rather than dismissing it, so a
    // stray click never throws away what was typed.
    overlay.addEventListener("mousedown", (event) => {
      if (event.target === overlay) event.preventDefault();
    });

    openCount++;
    appRoot?.setAttribute("inert", "");
    document.body.append(overlay);
    const initial = form.querySelector<HTMLElement>("[data-autofocus]") ?? form.querySelector<HTMLElement>("input, select") ?? submit;
    initial.focus({ preventScroll: true });
    if (initial instanceof HTMLInputElement && initial.type !== "checkbox") initial.select();
  });
}

/** A yes / no question. Resolves true when confirmed. */
export async function confirmDialog(options: {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
}): Promise<boolean> {
  const result = await openDialog<boolean>({
    title: options.title,
    body: h("p", { class: "dialog-text", text: options.message }),
    submitLabel: options.confirmLabel,
    danger: options.danger ?? false,
    onSubmit: () => true,
  });
  return result === true;
}
