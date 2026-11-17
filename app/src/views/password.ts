// The password prompt shown when no password is saved or the saved one was refused.
import { openDialog } from "../dialog";
import { h } from "../dom";
import type { Connection } from "../ipc";

export interface PasswordAnswer {
  password: string;
  save: boolean;
}

export function askPassword(connection: Connection, note: string | null): Promise<PasswordAnswer | null> {
  const input = h("input", {
    class: "input",
    attrs: { type: "password", id: "password-input", autocomplete: "off", "data-autofocus": "" },
  });
  const save = h("input", { attrs: { type: "checkbox", id: "password-save" } });
  save.checked = true;
  const error = h("p", { class: "field-error", attrs: { role: "alert" } });
  error.hidden = true;
  const who = connection.username ? `${connection.username} on ${connection.host}` : connection.host;
  const body = h(
    "div",
    { class: "form" },
    note ? h("p", { class: "notice notice-warn", text: note }) : null,
    h("label", { class: "field-label", text: `Password for ${who}`, attrs: { for: "password-input" } }),
    input,
    error,
    h("label", { class: "check" }, save, h("span", { text: "Save in keychain" })),
  );
  return openDialog<PasswordAnswer>({
    title: `Sign in to ${connection.name}`,
    body,
    submitLabel: "Connect",
    onSubmit: () => {
      if (input.value === "") {
        error.textContent = "Enter the password.";
        error.hidden = false;
        input.focus();
        return undefined;
      }
      return { password: input.value, save: save.checked };
    },
  });
}
