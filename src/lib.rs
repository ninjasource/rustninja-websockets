#![deny(warnings)]
#![feature(extern_prelude)]

pub mod websocket;

// WORK IN PROGRESS
// TODO: figure out how to debug these in VS Code
#[cfg(test)]
mod tests {

    use websocket;
    use websocket::WebSocket;

    use std::cmp::min;
    use std::io::{Read, Result, Write};

    /// `MemStream` is a reader + writer stream backed by an in-memory buffer
    #[derive(PartialEq, PartialOrd)]
    pub struct MemStream {
        buf: Vec<u8>,
        pos: usize,
    }

    // TODO: find a better implementation of this without unsafe rust perhaps
    impl MemStream {
        /// Creates a new `MemStream` which can be read and written to
        pub fn new() -> MemStream {
            MemStream {
                buf: vec![],
                pos: 0,
            }
        }
        /// Tests whether this stream has read all bytes in its ring buffer
        /// If `true`, then this will no longer return bytes from `read`
        pub fn eof(&self) -> bool {
            self.pos >= self.buf.len()
        }
    }

    impl Read for MemStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.eof() {
                return Ok(0);
            }
            let write_len = min(buf.len(), self.buf.len() - self.pos);
            {
                let input = &self.buf[self.pos..self.pos + write_len];
                let output = &mut buf[0..write_len];
                assert_eq!(input.len(), output.len());

                unsafe {
                    std::ptr::copy_nonoverlapping(input.as_ptr(), output.as_mut_ptr(), input.len());
                }
            }
            self.pos += write_len;
            assert!(self.pos <= self.buf.len());

            return Ok(write_len);
        }
    }

    impl Write for MemStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            for byte in buf {
                self.buf.push(*byte);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn server_handshake() {
        let client_request = "Host: localhost:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Sec-WebSocket-Version: 13
Origin: http://localhost:5000
Sec-WebSocket-Extensions: permessage-deflate
Sec-WebSocket-Key: Z7OY1UwHOx/nkSz38kfPwg==
DNT: 1
Connection: keep-alive, Upgrade
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket

";

        let client_request = String::from(client_request);
        println!("Request: '{}'", client_request);

        let header =
            websocket::read_http_header(&client_request).expect("Failed to read http header");
        println!("Read http header");
        let websocket_context = websocket::get_websocket_context(&header)
            .expect("Http header is not a websocket request");
        println!("Completed decoding header");

        let mut stream = MemStream::new();
        {
            let mut _ws =
                WebSocket::new_server(&websocket_context.sec_websocket_key, None, &mut stream);
        }

        let mut buffer: [u8; 1024] = [0; 1024];
        stream.read(&mut buffer).unwrap();
        let s: String = String::from_utf8_lossy(&buffer[..]).to_string();

        println!("Response: {}", s);
        assert_eq!(2 + 2, 4);
    }
}
