//! Greetings that servers send first: the RFB version (VNC) and the SSH identification line.
//! We read them and close. Nothing is sent, so there is no sign-in attempt.

use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

/// What a VNC server's greeting says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfbInfo {
    /// E.g. "003.008".
    pub version: String,
    /// "RFB 003.889" is what Apple's Screen Sharing sends.
    pub apple: bool,
}

/// Parse a 12-byte "RFB xxx.yyy\n" greeting.
pub fn parse_rfb(greeting: &[u8]) -> Option<RfbInfo> {
    let text = std::str::from_utf8(greeting.get(..12)?).ok()?;
    let version = text.strip_prefix("RFB ")?.strip_suffix('\n')?;
    let valid = version.len() == 7
        && version.as_bytes()[3] == b'.'
        && version.bytes().enumerate().all(|(i, b)| i == 3 || b.is_ascii_digit());
    valid.then(|| RfbInfo {
        version: version.to_owned(),
        apple: version == "003.889",
    })
}

/// Read the RFB greeting from an open connection to a VNC port.
pub async fn rfb(mut tcp: TcpStream, limit: Duration) -> Option<RfbInfo> {
    let mut greeting = [0u8; 12];
    tokio::time::timeout(limit, tcp.read_exact(&mut greeting)).await.ok()?.ok()?;
    parse_rfb(&greeting)
}

/// Read the SSH identification line ("SSH-2.0-OpenSSH_9.6"), without the line ending.
pub async fn ssh(mut tcp: TcpStream, limit: Duration) -> Option<String> {
    let mut buffer = Vec::with_capacity(256);
    let read = async {
        let mut chunk = [0u8; 256];
        // RFC 4253 allows other lines before the identification; give up after 1 KiB.
        while buffer.len() < 1024 {
            let n = tcp.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(line) = ssh_line(&buffer) {
                return Some(line);
            }
        }
        None
    };
    tokio::time::timeout(limit, read).await.ok().flatten()
}

/// The first complete line starting with "SSH-". Bytes after the last line ending are a line still
/// arriving and are not looked at yet.
fn ssh_line(buffer: &[u8]) -> Option<String> {
    let complete = &buffer[..buffer.iter().rposition(|&b| b == b'\n')?];
    complete
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find(|line| line.starts_with(b"SSH-"))
        .map(|line| String::from_utf8_lossy(&line[..line.len().min(255)]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfb_greetings() {
        assert_eq!(parse_rfb(b"RFB 003.889\n"), Some(RfbInfo { version: "003.889".into(), apple: true }));
        assert_eq!(parse_rfb(b"RFB 003.008\n"), Some(RfbInfo { version: "003.008".into(), apple: false }));
        assert_eq!(parse_rfb(b"RFB 003.008"), None);
        assert_eq!(parse_rfb(b"SSH-2.0-xx\r\n"), None);
        assert_eq!(parse_rfb(b"RFB 0a3.008\n"), None);
    }

    #[test]
    fn ssh_lines() {
        assert_eq!(ssh_line(b"SSH-2.0-OpenSSH_9.6\r\n").as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        assert_eq!(ssh_line(b"hello\r\nSSH-2.0-x\n").as_deref(), Some("SSH-2.0-x"));
        assert_eq!(ssh_line(b"SSH-2.0-incomplete"), None);
        // A complete line before it does not make the partial one count.
        assert_eq!(ssh_line(b"hello\r\nSSH-2.0-partial"), None);
        assert_eq!(ssh_line(b"hello\r\nSSH-2.0-partial\r\n").as_deref(), Some("SSH-2.0-partial"));
        assert_eq!(ssh_line(b"SSH-2.0-a\nSSH-2.0-b").as_deref(), Some("SSH-2.0-a"));
    }
}
