// Server identity fingerprints, shown the way the remote machine's own tools print them. Pure.
import type { Connection, IdentityKind } from "./ipc";

/** Which identity a connection pins, or null when it has none (VNC without the SSH tunnel). */
export function identityKindOf(connection: Pick<Connection, "protocol" | "ssh_tunnel">): IdentityKind | null {
  if (connection.protocol === "rdp") return "tls_certificate";
  return connection.ssh_tunnel ? "ssh_host_key" : null;
}

function bytesOf(hex: string): number[] | null {
  const clean = hex.trim().toLowerCase();
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) return null;
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  return bytes;
}

/**
 * A lowercase hex SHA-256 as the remote side shows it:
 * - TLS certificate: upper-case byte pairs joined by colons ("3F:A0:..."), what the PowerShell
 *   command in `identityCheckSteps` prints.
 * - SSH host key: "SHA256:" and unpadded base64, exactly what `ssh-keygen -l` prints.
 * Anything that is not hex is returned unchanged.
 */
export function formatFingerprint(kind: IdentityKind, hex: string): string {
  const bytes = bytesOf(hex);
  if (!bytes) return hex;
  if (kind === "ssh_host_key") {
    const base64 = btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
    return `SHA256:${base64}`;
  }
  return bytes.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

export const RDP_CERT_COMMAND =
  "Get-ChildItem 'Cert:\\LocalMachine\\Remote Desktop' | ForEach-Object { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData)).Replace('-', ':') }";
export const MAC_SSH_KEY_COMMAND = "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub";

export interface CheckStep {
  text: string;
  /** A command to type on the remote machine, shown as code. */
  command?: string;
}

/** How to read the real fingerprint on the remote machine itself, to compare. */
export function identityCheckSteps(kind: IdentityKind): CheckStep[] {
  if (kind === "tls_certificate") {
    return [
      {
        text: "On the Windows PC itself (not through this app), open PowerShell and run this. It prints the SHA-256 of the Remote Desktop certificate in the same format as above:",
        command: RDP_CERT_COMMAND,
      },
      {
        text: "The certificate is also listed in certlm.msc > Remote Desktop > Certificates, but the Thumbprint shown there is SHA-1, so it will not match the SHA-256 above.",
      },
    ];
  }
  return [
    {
      text: "On the Mac itself (not through this app), open Terminal and run this. The SHA256:... part should match exactly:",
      command: MAC_SSH_KEY_COMMAND,
    },
    {
      text: "If it differs, also try ssh_host_ecdsa_key.pub and ssh_host_rsa_key.pub in the same folder: the Mac may have offered one of those keys.",
    },
  ];
}
