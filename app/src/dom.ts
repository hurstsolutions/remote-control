// A tiny element builder so the views stay readable without a framework.

type Child = Node | string | null | undefined | false;

export interface Props {
  class?: string;
  text?: string;
  title?: string;
  attrs?: Record<string, string>;
  on?: { [K in keyof HTMLElementEventMap]?: (event: HTMLElementEventMap[K]) => void };
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (props.class) element.className = props.class;
  if (props.text !== undefined) element.textContent = props.text;
  if (props.title) element.title = props.title;
  if (props.attrs) {
    for (const [name, value] of Object.entries(props.attrs)) element.setAttribute(name, value);
  }
  if (props.on) {
    for (const [name, handler] of Object.entries(props.on)) {
      element.addEventListener(name, handler as EventListener);
    }
  }
  for (const child of children) {
    if (child !== null && child !== undefined && child !== false) element.append(child);
  }
  return element;
}

export interface ButtonOptions {
  kind?: "default" | "primary" | "danger" | "quiet";
  title?: string;
  submit?: boolean;
}

export function button(label: string, onClick: (event: MouseEvent) => void, options: ButtonOptions = {}): HTMLButtonElement {
  const kind = options.kind ?? "default";
  const element = h("button", { class: kind === "default" ? "btn" : `btn btn-${kind}`, text: label });
  element.type = options.submit ? "submit" : "button";
  if (options.title) element.title = options.title;
  element.addEventListener("click", onClick);
  return element;
}

/** Show a different label on a button for a moment (for "Copied"). */
export function flashLabel(target: HTMLButtonElement, text: string, ms = 1500): void {
  const original = target.dataset["label"] ?? target.textContent ?? "";
  target.dataset["label"] = original;
  target.textContent = text;
  window.setTimeout(() => {
    target.textContent = original;
  }, ms);
}
