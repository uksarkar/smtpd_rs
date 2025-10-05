use std::fmt;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, ReadHalf, WriteHalf},
    time::timeout,
};

use crate::core::{ConnectionStream, error::Error};

// StreamController with proper generics
pub struct StreamController {
    pub reader: BufReader<ReadHalf<ConnectionStream>>,
    pub writer: BufWriter<WriteHalf<ConnectionStream>>,
    pub is_tls: bool,
    timeout: core::time::Duration,
}

impl Into<ConnectionStream> for StreamController {
    fn into(self) -> ConnectionStream {
        self.reader.into_inner().unsplit(self.writer.into_inner())
    }
}

impl StreamController {
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

    pub async fn write_response(&mut self, res: &impl fmt::Display) -> Result<(), Error> {
        self.write_line(&res.to_string()).await
    }

    pub async fn read_line_trimmed(&mut self, dist: &mut String) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_line(dist)).await??;

        let start_len_diff = dist.len() - dist.trim_start().len();
        if start_len_diff > 0 {
            dist.drain(0..start_len_diff);
        }

        let end_trimmed = dist.trim_end().len();
        if end_trimmed < dist.len() {
            dist.truncate(end_trimmed);
        }

        Ok(())
    }

    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_until(b'\n', buffer)).await??;

        if buffer.ends_with(b"\r\n") {
            Ok(())
        } else if buffer.ends_with(b"\n") {
            // Convert LF to CRLF if needed
            buffer.pop(); // remove LF
            if buffer.ends_with(b"\r") {
                buffer.push(b'\n'); // add LF back
                Ok(())
            } else {
                // Insert CR before LF
                buffer.push(b'\r');
                buffer.push(b'\n');
                Ok(())
            }
        } else {
            Err(Error::InvalidLineEnding)
        }
    }

    pub async fn read_mail_data(&mut self, max_size: Option<usize>) -> Result<Vec<u8>, Error> {
        let mut data = vec![];
        let mut line = vec![];
        let mut total_size = 0;

        loop {
            line.clear();
            self.read_line_crlf(&mut line).await?;

            if line == b".\r\n" {
                break;
            }

            let processed_line = if line.starts_with(b".") {
                &line[1..]
            } else {
                &line
            };

            if let Some(max) = max_size {
                if total_size + processed_line.len() > max {
                    return Err(Error::MaxSizeExceeded {
                        limit: max,
                        got: total_size + processed_line.len(),
                    });
                }
            }

            data.extend_from_slice(processed_line);
            total_size += processed_line.len();
        }

        Ok(data)
    }
}
