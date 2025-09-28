use std::fmt;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{core::error::Error};

// StreamController with proper generics
pub struct StreamController<S> {
    pub(crate) stream: S,
}

impl<S> StreamController<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> StreamController<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn write_line(&mut self, line: impl AsRef<str>) -> Result<(), Error> {
        self.stream.write_all(line.as_ref().as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn write_response(&mut self, res: &impl fmt::Display) -> Result<(), Error> {
        self.write_line(&res.to_string()).await
    }

    pub async fn read_line_trimmed(&mut self, dist: &mut String) -> Result<(), Error> {
        let mut reader = BufReader::new(&mut self.stream);
        dist.clear();
        reader.read_line(dist).await?;

        let start_trimmed = dist.trim_start();
        let start_len_diff = dist.len() - start_trimmed.len();
        if start_len_diff > 0 {
            dist.drain(0..start_len_diff);
        }

        let end_trimmed = dist.trim_end();
        let end_len_diff = dist.len() - end_trimmed.len();
        if end_len_diff > 0 {
            dist.truncate(end_trimmed.len());
        }

        Ok(())
    }

    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        let mut reader = BufReader::new(&mut self.stream);
        buffer.clear();
        reader.read_until(b'\n', buffer).await?;

        if buffer.ends_with(b"\r\n") {
            Ok(())
        } else if buffer.ends_with(b"\n") {
            buffer.pop();
            if buffer.ends_with(b"\r") {
                buffer.push(b'\n');
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
