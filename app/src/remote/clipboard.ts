// Clipboard sync for one session. Clipboard text is never logged.

/** Larger clipboards are not passed either way: they would stall the session for little benefit. */
export const MAX_CLIPBOARD_CHARS = 1_000_000;

/** Whether local clipboard text should be sent, given the last text synced either way. */
export function shouldSendClipboard(text: string | null | undefined, lastSynced: string | null): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  if (text.length > MAX_CLIPBOARD_CHARS) return false;
  return text !== lastSynced;
}

export interface ClipboardPort {
  readClipboard(): Promise<string>;
  writeClipboard(text: string): Promise<void>;
}

export class ClipboardSync {
  /** The last text sent to or received from this session. */
  private lastSynced: string | null = null;
  private reading = false;

  constructor(
    private readonly port: ClipboardPort,
    private readonly send: (text: string) => void,
    /** Checked again after the asynchronous read, so nothing is sent to a closed session. */
    private readonly canSend: () => boolean,
    /** The connection's "share clipboard" setting; when false nothing passes either way. */
    private readonly enabled: () => boolean = () => true,
  ) {}

  /** Read the local clipboard and send it if it changed (window focus, tab activation). */
  async pushLocal(): Promise<void> {
    if (this.reading || !this.enabled() || !this.canSend()) return;
    this.reading = true;
    let text: string | null = null;
    try {
      text = await this.port.readClipboard();
    } catch {
      // No text on the clipboard (an image, a file) or access refused: nothing to send.
    } finally {
      this.reading = false;
    }
    if (!this.enabled() || !this.canSend() || !shouldSendClipboard(text, this.lastSynced)) return;
    this.lastSynced = text;
    this.send(text as string);
  }

  /** The remote copied something: put it on the local clipboard and do not echo it back. */
  async receiveRemote(text: string): Promise<void> {
    if (!this.enabled()) return;
    if (text.length > MAX_CLIPBOARD_CHARS) {
      console.warn(`remote clipboard text ignored: ${text.length} characters is over the ${MAX_CLIPBOARD_CHARS} limit`);
      return;
    }
    this.lastSynced = text;
    try {
      await this.port.writeClipboard(text);
    } catch {
      console.warn("could not write the remote clipboard text to the local clipboard");
    }
  }

  /** A new connection starts with nothing synced. */
  reset(): void {
    this.lastSynced = null;
  }
}
