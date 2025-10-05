use std::fmt;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, ReadHalf, WriteHalf},
    time::timeout,
};

use crate::core::{ConnectionStream, error::Error};

/// Handles read/write operations on a `ConnectionStream`.
///
/// This struct wraps the split halves of a connection (reader and writer),
/// provides timeout support, and ensures proper line handling per SMTP protocol.
///
/// Constructed internally per accepted connection. Most read/write operations
/// are asynchronous and time-limited using the provided `timeout`.
pub(crate) struct StreamController {
    /// Buffered reader half of the connection.
    pub reader: BufReader<ReadHalf<ConnectionStream>>,

    /// Buffered writer half of the connection.
    pub writer: BufWriter<WriteHalf<ConnectionStream>>,

    /// Whether the connection is currently encrypted via TLS.
    pub is_tls: bool,

    /// Timeout duration applied to each read/write operation.
    timeout: core::time::Duration,
}

impl Into<ConnectionStream> for StreamController {
    fn into(self) -> ConnectionStream {
        self.reader.into_inner().unsplit(self.writer.into_inner())
    }
}

impl StreamController {
    /// Creates a new `StreamController` from a `ConnectionStream`.
    ///
    /// Splits the stream into read and write halves, wraps them in buffered readers/writers,
    /// and stores the timeout for all I/O operations.
    pub fn new(stream: ConnectionStream, timeout: core::time::Duration) -> Self {
        let is_tls = stream.is_tls();
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            is_tls,
            timeout,
        }
    }

    /// Writes a single line to the connection, automatically appending `\r\n`.
    ///
    /// The operation is bounded by the session timeout.
    pub async fn write_line(&mut self, line: impl AsRef<str>) -> Result<(), Error> {
        timeout(
            self.timeout,
            self.writer.write_all(line.as_ref().as_bytes()),
        )
        .await??;
        timeout(self.timeout, self.writer.write_all(b"\r\n")).await??;
        timeout(self.timeout, self.writer.flush()).await??;
        Ok(())
    }

    /// Writes a displayable response to the connection.
    ///
    /// Converts the response to a string and delegates to `write_line`.
    pub async fn write_response(&mut self, res: &impl fmt::Display) -> Result<(), Error> {
        self.write_line(&res.to_string()).await
    }

    /// Reads a line from the connection and trims leading and trailing whitespace.
    ///
    /// Timeout applies to the read operation.
    pub async fn read_line_trimmed(&mut self, dist: &mut String) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_line(dist)).await??;

        // Trim leading whitespace
        let start_len_diff = dist.len() - dist.trim_start().len();
        if start_len_diff > 0 {
            dist.drain(0..start_len_diff);
        }

        // Trim trailing whitespace
        let end_trimmed = dist.trim_end().len();
        if end_trimmed < dist.len() {
            dist.truncate(end_trimmed);
        }

        Ok(())
    }

    /// Reads a line from the connection, ensuring proper CRLF line ending.
    ///
    /// If the line ends with LF only, it converts it to CRLF.
    /// Returns `Error::InvalidLineEnding` for malformed lines.
    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_until(b'\n', buffer)).await??;

        if buffer.ends_with(b"\r\n") {
            Ok(())
        } else if buffer.ends_with(b"\n") {
            // Convert LF to CRLF if needed
            buffer.pop(); // remove LF
            if buffer.ends_with(b"\r") {
                buffer.push(b'\n'); // already CR present, just append LF
                Ok(())
            } else {
                buffer.push(b'\r');
                buffer.push(b'\n');
                Ok(())
            }
        } else {
            Err(Error::InvalidLineEnding)
        }
    }

    /// Reads the data of an SMTP `DATA` command until a line containing only `.`.
    ///
    /// Handles dot-stuffing (lines starting with `.`) and enforces an optional maximum size.
    pub async fn read_mail_data(&mut self, max_size: Option<usize>) -> Result<Vec<u8>, Error> {
        let mut data = vec![];
        let mut line = vec![];
        let mut total_size = 0;

        loop {
            line.clear();
            self.read_line_crlf(&mut line).await?;

            // End of data marker
            if line == b".\r\n" {
                break;
            }

            // Handle dot-stuffing
            let processed_line = if line.starts_with(b".") {
                &line[1..]
            } else {
                &line
            };

            // Check max size
            if let Some(max) = max_size {
                if total_size + processed_line.len() > max {
                    return Err(Error::MaxSizeExceeded { limit: max });
                }
            }

            data.extend_from_slice(processed_line);
            total_size += processed_line.len();
        }

        Ok(data)
    }
}
