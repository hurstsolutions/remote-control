//! Text-only clipboard bridge between the RDP CLIPRDR channel and the front end.
//!
//! The backend never touches the OS clipboard itself: the front end owns that. Local text arrives
//! as `SessionInput::Clipboard`, remote text leaves as `SessionEvent::Clipboard`.

use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::IntoOwned as _;
use rc_types::MAX_CLIPBOARD_BYTES;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// What the channel backend asks the session loop to do.
#[derive(Debug)]
pub(crate) enum ClipEvent {
    /// Forward to the CLIPRDR channel.
    Message(ClipboardMessage),
    /// The remote clipboard text was fetched.
    RemoteText(String),
}

#[derive(Debug)]
pub(crate) struct TextClipboard {
    pub local_text: Arc<Mutex<String>>,
    pub tx: mpsc::UnboundedSender<ClipEvent>,
}

impl TextClipboard {
    fn send(&self, message: ClipboardMessage) {
        let _ = self.tx.send(ClipEvent::Message(message));
    }

    fn local_formats(&self) -> Vec<ClipboardFormat> {
        let has_text = !self.local_text.lock().map(|t| t.is_empty()).unwrap_or(true);
        if has_text {
            vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
        } else {
            Vec::new()
        }
    }
}

ironrdp_core::impl_as_any!(TextClipboard);

impl CliprdrBackend for TextClipboard {
    fn temporary_directory(&self) -> &str {
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {
        debug!("clipboard channel ready");
    }

    fn on_request_format_list(&mut self) {
        self.send(ClipboardMessage::SendInitiateCopy(self.local_formats()));
    }

    fn on_process_negotiated_capabilities(&mut self, capabilities: ClipboardGeneralCapabilityFlags) {
        debug!(?capabilities, "clipboard capabilities negotiated");
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // Fetch text right away so the local clipboard is ready before the user pastes.
        if available_formats
            .iter()
            .any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT)
        {
            self.send(ClipboardMessage::SendInitiatePaste(ClipboardFormatId::CF_UNICODETEXT));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = if request.format == ClipboardFormatId::CF_UNICODETEXT {
            let text = self.local_text.lock().map(|t| t.clone()).unwrap_or_default();
            // Windows expects CRLF line endings in CF_UNICODETEXT.
            let text = text.replace("\r\n", "\n").replace('\n', "\r\n");
            FormatDataResponse::new_unicode_string(&text)
        } else {
            FormatDataResponse::new_error()
        };
        self.send(ClipboardMessage::SendFormatData(response.into_owned()));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            debug!("remote clipboard data request was refused");
            return;
        }
        // UTF-16 with a terminating NUL on the wire, and every UTF-16 unit decodes to at least one
        // UTF-8 byte: drop what is certainly too large before decoding it. Sizes only: clipboard
        // text is never logged.
        let wire_bytes = response.data().len();
        if (wire_bytes / 2).saturating_sub(1) > MAX_CLIPBOARD_BYTES {
            warn!(wire_bytes, limit = MAX_CLIPBOARD_BYTES, "remote clipboard text too large; ignored");
            return;
        }
        match response.to_unicode_string() {
            Ok(text) if text.len() > MAX_CLIPBOARD_BYTES => {
                warn!(bytes = text.len(), limit = MAX_CLIPBOARD_BYTES, "remote clipboard text too large; ignored");
            }
            Ok(text) => {
                let text = text.replace("\r\n", "\n");
                let _ = self.tx.send(ClipEvent::RemoteText(text));
            }
            Err(error) => warn!(%error, "could not decode remote clipboard text"),
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> (TextClipboard, mpsc::UnboundedReceiver<ClipEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (TextClipboard { local_text: Arc::new(Mutex::new(String::new())), tx }, rx)
    }

    fn remote_text(rx: &mut mpsc::UnboundedReceiver<ClipEvent>) -> Option<String> {
        match rx.try_recv() {
            Ok(ClipEvent::RemoteText(text)) => Some(text),
            _ => None,
        }
    }

    #[test]
    fn remote_text_is_passed_on_with_unix_line_endings() {
        let (mut clip, mut rx) = backend();
        clip.on_format_data_response(FormatDataResponse::new_unicode_string("a\r\nb"));
        assert_eq!(remote_text(&mut rx).as_deref(), Some("a\nb"));
    }

    #[test]
    fn oversized_remote_text_is_dropped() {
        let (mut clip, mut rx) = backend();
        let huge = "x".repeat(MAX_CLIPBOARD_BYTES + 1);
        clip.on_format_data_response(FormatDataResponse::new_unicode_string(&huge));
        assert_eq!(remote_text(&mut rx), None);
        // Exactly at the limit still gets through.
        let edge = "y".repeat(MAX_CLIPBOARD_BYTES);
        clip.on_format_data_response(FormatDataResponse::new_unicode_string(&edge));
        assert_eq!(remote_text(&mut rx).map(|t| t.len()), Some(MAX_CLIPBOARD_BYTES));
    }
}
