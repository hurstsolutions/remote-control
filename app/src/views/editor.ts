// The dialog for adding or editing a saved connection.
import { openDialog } from "../dialog";
import { button, h } from "../dom";
import { DIRECT_MAC_SUMMARY, messageOf } from "../errors";
import type { Connection, Protocol, SavedConnection } from "../ipc";
import type { Platform } from "../platform";
import { DEFAULT_PORT, DEFAULT_SSH_PORT, blankConnection, passwordClearedByEdit, pinnedIdentityAfterEdit } from "../state";
import { parsePort, validateEditor, type EditorField } from "./editor-logic";

let fieldCounter = 0;

interface Field {
  row: HTMLElement;
  input: HTMLInputElement;
  error: HTMLElement;
}

function textField(label: string, value: string, options: { type?: string; hint?: string; narrow?: boolean } = {}): Field {
  const id = `field-${++fieldCounter}`;
  const input = h("input", {
    class: options.narrow ? "input input-narrow" : "input",
    attrs: {
      id,
      type: options.type ?? "text",
      autocomplete: "off",
      autocapitalize: "off",
      autocorrect: "off",
      spellcheck: "false",
    },
  });
  input.value = value;
  if (options.type === "number") input.inputMode = "numeric";
  const error = h("p", { class: "field-error", attrs: { role: "alert" } });
  error.hidden = true;
  const row = h(
    "div",
    { class: "field" },
    h("label", { class: "field-label", text: label, attrs: { for: id } }),
    input,
    options.hint ? h("p", { class: "field-hint", text: options.hint }) : null,
    error,
  );
  return { row, input, error };
}

function checkbox(label: string, checked: boolean): { row: HTMLElement; input: HTMLInputElement } {
  const input = h("input", { attrs: { type: "checkbox" } });
  input.checked = checked;
  return { row: h("label", { class: "check" }, input, h("span", { text: label })), input };
}

/** Shown after saving when the backend removed the saved password. */
export const PASSWORD_CLEARED_NOTE = "Saved password was cleared because the address/user changed.";

/**
 * Open the editor. `existing` is null when adding. Resolves with what save_connection returned
 * (check `password_cleared`), or null when cancelled.
 */
export async function openEditor(platform: Platform, existing: Connection | null): Promise<SavedConnection | null> {
  const api = platform.api;
  const start = existing ?? blankConnection("rdp");
  let hasSavedPassword = false;
  if (existing) {
    try {
      hasSavedPassword = await api.hasSavedPassword(existing.id);
    } catch (error) {
      console.error("has_saved_password failed", error);
    }
  }

  const name = textField("Name", start.name);
  name.input.setAttribute("data-autofocus", "");
  name.input.placeholder = "Office PC";

  const typeId = `field-${++fieldCounter}`;
  const type = h("select", { class: "input", attrs: { id: typeId } });
  type.append(new Option("Windows - Remote Desktop", "rdp"), new Option("Mac - Screen Sharing", "vnc"));
  type.value = start.protocol;
  const typeRow = h("div", { class: "field" }, h("label", { class: "field-label", text: "Type", attrs: { for: typeId } }), type);

  const host = textField("Computer name or IP address", start.host);
  host.input.placeholder = "192.168.1.20";
  const port = textField("Port", String(start.port), { narrow: true });
  const username = textField("Username", start.username);
  const domain = textField("Domain (optional)", start.domain, {
    hint: "Only for work PCs joined to a domain. Leave empty otherwise.",
  });
  const nla = checkbox("Network Level Authentication", start.nla);
  const tunnel = checkbox("Secure with SSH tunnel (recommended)", start.ssh_tunnel);
  const sshPort = textField("SSH port", String(start.ssh_port || DEFAULT_SSH_PORT), { narrow: true });
  const shareClipboard = checkbox("Share clipboard with this computer", start.share_clipboard);
  const clipboardRow = h(
    "div",
    { class: "form-group" },
    shareClipboard.row,
    h("p", {
      class: "field-hint",
      text: "Text you copy here can be pasted there, and the other way round, while connected. Turn off for computers you do not fully trust.",
    }),
  );

  const windowsOnly = h(
    "div",
    { class: "form-group" },
    domain.row,
    h(
      "details",
      { class: "advanced" },
      h("summary", { text: "Advanced" }),
      nla.row,
      h("p", {
        class: "field-hint",
        text: "Signs in before the desktop is shown. Leave on unless the PC is set to allow connections without it.",
      }),
    ),
  );
  const tunnelNote = h("p", { class: "notice" });
  const macOnly = h("div", { class: "form-group" }, tunnel.row, sshPort.row, tunnelNote);

  const saveError = h("p", { class: "notice notice-error", attrs: { role: "alert" } });
  saveError.hidden = true;

  let forgetRow: HTMLElement | null = null;
  // Warns before saving that the saved password will go (the backend removes it).
  const clearWarning = h("p", { class: "notice notice-warn", attrs: { role: "status", id: "password-clear-warning" } });
  clearWarning.hidden = true;
  if (existing && hasSavedPassword) {
    const status = h("span", { class: "muted", text: "A password is saved in the keychain." });
    const forget = button("Forget saved password", () => {
      forget.disabled = true;
      api.forgetPassword(existing.id).then(
        () => {
          hasSavedPassword = false;
          updateClearWarning();
          forget.remove();
          status.textContent = "The saved password was removed. You will be asked for it next time.";
        },
        (error: unknown) => {
          forget.disabled = false;
          status.textContent = `Couldn't remove the saved password: ${messageOf(error)}`;
        },
      );
    });
    forgetRow = h("div", { class: "field field-inline" }, status, forget);
  }

  // The port follows the type until the user types a port of their own.
  let portEdited = start.port !== DEFAULT_PORT[start.protocol];
  port.input.addEventListener("input", () => {
    portEdited = true;
  });

  const protocol = (): Protocol => (type.value === "vnc" ? "vnc" : "rdp");
  const draftOf = (): Connection => {
    const mac = protocol() === "vnc";
    return {
      id: existing?.id ?? "",
      name: name.input.value.trim(),
      protocol: protocol(),
      host: host.input.value.trim(),
      port: parsePort(port.input.value) ?? DEFAULT_PORT[protocol()],
      username: username.input.value.trim(),
      domain: mac ? "" : domain.input.value.trim(),
      nla: mac ? true : nla.input.checked,
      ssh_tunnel: mac ? tunnel.input.checked : true,
      ssh_port: mac && tunnel.input.checked ? (parsePort(sshPort.input.value) ?? DEFAULT_SSH_PORT) : DEFAULT_SSH_PORT,
      pinned_identity: null,
      share_clipboard: shareClipboard.input.checked,
    };
  };
  function updateClearWarning(): void {
    const clears = hasSavedPassword && passwordClearedByEdit(existing, draftOf());
    clearWarning.hidden = !clears;
    clearWarning.textContent = clears
      ? "The address or username changed: saving removes the saved password, and you will be asked for it on the next connect."
      : "";
  }
  const sync = () => {
    const mac = protocol() === "vnc";
    windowsOnly.hidden = mac;
    macOnly.hidden = !mac;
    sshPort.row.hidden = !tunnel.input.checked;
    tunnelNote.classList.toggle("notice-warn", !tunnel.input.checked);
    tunnelNote.textContent = tunnel.input.checked
      ? "On the Mac, turn on both Screen Sharing and Remote Login (System Settings > General > Sharing). The screen and your password travel inside the encrypted SSH connection."
      : `${DIRECT_MAC_SUMMARY} On the Mac, turn on Screen Sharing (System Settings > General > Sharing).`;
  };
  type.addEventListener("change", () => {
    if (!portEdited) port.input.value = String(DEFAULT_PORT[protocol()]);
    sync();
  });
  tunnel.input.addEventListener("change", sync);
  sync();
  for (const element of [type, host.input, port.input, username.input, domain.input, tunnel.input, sshPort.input]) {
    element.addEventListener("input", updateClearWarning);
    element.addEventListener("change", updateClearWarning);
  }

  const fields: Record<EditorField, Field> = { name, host, port, username, sshPort };
  const order: EditorField[] = ["name", "host", "port", "username", "sshPort"];

  const body = h(
    "div",
    { class: "form" },
    name.row,
    typeRow,
    h("div", { class: "field-pair" }, host.row, port.row),
    username.row,
    windowsOnly,
    macOnly,
    clipboardRow,
    forgetRow,
    clearWarning,
    saveError,
  );

  return openDialog<SavedConnection>({
    title: existing ? "Edit connection" : "Add connection",
    body,
    submitLabel: existing ? "Save" : "Add",
    onSubmit: async () => {
      saveError.hidden = true;
      const errors = validateEditor({
        name: name.input.value,
        protocol: protocol(),
        host: host.input.value,
        port: port.input.value,
        username: username.input.value,
        sshTunnel: tunnel.input.checked,
        sshPort: sshPort.input.value,
      });
      let firstInvalid: HTMLInputElement | null = null;
      for (const key of order) {
        const field = fields[key];
        const message = errors[key];
        field.error.textContent = message ?? "";
        field.error.hidden = !message;
        field.input.setAttribute("aria-invalid", message ? "true" : "false");
        if (message && !firstInvalid) firstInvalid = field.input;
      }
      if (firstInvalid) {
        firstInvalid.focus();
        return undefined;
      }
      const draft = draftOf();
      draft.pinned_identity = pinnedIdentityAfterEdit(existing, draft);
      try {
        return await api.saveConnection(draft);
      } catch (error) {
        saveError.textContent = `Couldn't save the connection: ${messageOf(error)}`;
        saveError.hidden = false;
        return undefined;
      }
    },
  });
}
