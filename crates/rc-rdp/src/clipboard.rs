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
        match response.to_unicode_string() {
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
