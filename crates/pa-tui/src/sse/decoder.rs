//! Bounded SSE framing only; AG-UI remains the application event contract.
//!
//! Limits apply before buffering a complete line or JSON value. UTF-8 is decoded only
//! after a line boundary, never lossily at a network chunk boundary. An incomplete
//! final line/frame is deliberately not dispatched: EOF is not an event boundary.

/// Local client ceiling, not a server-negotiated permission to send larger frames.
pub(super) const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecodeError {
    TooLarge,
    InvalidUtf8,
}

#[derive(Default)]
pub(super) struct Decoder {
    line: Vec<u8>,
    data: Option<String>,
    frame_bytes: usize,
    after_cr: bool,
    first_line_read: bool,
}

impl Decoder {
    pub(super) fn push(&mut self, byte: u8) -> Result<Option<String>, DecodeError> {
        // CR, LF and CRLF are each one line ending, even across network chunks.
        if std::mem::replace(&mut self.after_cr, false) && byte == b'\n' {
            return Ok(None);
        }
        if self.frame_bytes == MAX_FRAME_BYTES {
            return Err(DecodeError::TooLarge);
        }
        self.frame_bytes += 1;
        match byte {
            b'\r' | b'\n' => {
                self.after_cr = byte == b'\r';
                self.end_line()
            }
            _ => {
                self.line.push(byte);
                Ok(None)
            }
        }
    }

    fn end_line(&mut self) -> Result<Option<String>, DecodeError> {
        let line = std::str::from_utf8(&self.line).map_err(|_| DecodeError::InvalidUtf8)?;
        let first = !std::mem::replace(&mut self.first_line_read, true);
        let line = if first {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        let event = if line.is_empty() {
            self.frame_bytes = 0;
            self.data.take()
        } else {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            if field == "data" {
                let value = value.strip_prefix(' ').unwrap_or(value);
                match &mut self.data {
                    Some(data) => {
                        data.push('\n');
                        data.push_str(value);
                    }
                    None => self.data = Some(value.to_owned()),
                }
            }
            // id/event/retry and comments are framing metadata. This existing client
            // still replays from zero; it must not pretend a wire id is an applied cursor.
            None
        };
        self.line.clear();
        Ok(event)
    }
}
