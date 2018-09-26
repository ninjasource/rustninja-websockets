//#![deny(warnings)]
#![feature(extern_prelude)]

extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate rand;

use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;

use std::collections::HashMap;
use std::io::prelude::*;

use self::byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::BufWriter;

use self::rand::thread_rng;
use self::rand::RngCore;

pub struct HttpHeader {
    pub path: String,
    pub headers: HashMap<String, String>,
}

pub struct WebSocketContext<'a> {
    pub sec_websocket_protocol_list: Vec<&'a str>,
    pub sec_websocket_key: String,
}

pub enum WebSocketMessageType {
    Text = 0,
    Binary = 1,
    Close = 2,
}

pub enum WebSocketCloseStatus {
    NormalClosure = 1000,
    EndpointUnavailable = 1001,
    ProtocolError = 1002,
    InvalidMessageType = 1003,
    Empty = 1005,
    InvalidPayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalServerError = 1011,
}

pub struct WebSocketReadResult {
    pub count: usize,
    pub end_of_message: bool,
    pub close_status: Option<WebSocketCloseStatus>,
    pub close_status_description: Option<String>,
    pub message_type: WebSocketMessageType,
}

#[derive(Copy, Clone)]
enum WebSocketOpCode {
    ContinuationFrame = 0,
    TextFrame = 1,
    BinaryFrame = 2,
    ConnectionClose = 8,
    Ping = 9,
    Pong = 10,
}

impl WebSocketOpCode {
    fn to_message_type(&self) -> WebSocketMessageType {
        match self {
            WebSocketOpCode::TextFrame => WebSocketMessageType::Text,
            WebSocketOpCode::BinaryFrame => WebSocketMessageType::Binary,
            WebSocketOpCode::ConnectionClose => WebSocketMessageType::Close,
            _ => panic!("Cannot convert op code to message type"),
        }
    }
}

struct WebSocketFrame {
    is_fin_bit_set: bool,
    op_code: WebSocketOpCode,
    count: usize,
    close_status: Option<WebSocketCloseStatus>,
    close_status_description: Option<String>,
}

pub fn get_websocket_context(http_header: &HttpHeader) -> Option<WebSocketContext> {
    let sec_websocket_protocol_list = match http_header.headers.get("Sec-WebSocket-Protocol") {
        Some(sub_protocol_csv) => sub_protocol_csv.split(',').collect(),
        None => Vec::new(),
    };

    let is_websocket_request: bool = match http_header.headers.get("Upgrade") {
        Some(value) => value == "websocket",
        None => false,
    };

    let sec_websocket_key = match http_header.headers.get("Sec-WebSocket-Key") {
        Some(value) => value.to_string(),
        None => String::new(),
    };

    if is_websocket_request {
        // TODO: check version
        Some(WebSocketContext {
            sec_websocket_protocol_list: sec_websocket_protocol_list,
            sec_websocket_key: sec_websocket_key,
        })
    } else {
        None
    }
}

pub fn read_http_header(http_header: &String) -> Option<HttpHeader> {
    let mut lines = http_header.lines();
    let first_line = lines.next();

    match first_line {
        None => None,
        Some(line) => {
            let cells: Vec<_> = line.split(' ').collect();
            if cells[0] == "GET" {
                let path = cells[1].to_string();
                let mut headers = HashMap::new();
                for line in lines {
                    if let Some(index) = line.find(':') {
                        let key: String = line[..index].to_string();
                        let value: String = line[index + 2..].to_string(); // TODO: possible error here if there is no header value
                        headers.insert(key, value);
                    } else {
                        break;
                    }
                }

                let header = HttpHeader {
                    path: path,
                    headers: headers,
                };

                Some(header)
            } else {
                None
            }
        }
    }
}

fn read_frame<T: Read>(stream: &mut T, buffer: &mut [u8]) -> WebSocketFrame {
    let mut small_buff: [u8; 2] = [0; 2];
    read_into_buffer(stream, &mut small_buff, 2);
    let byte1 = small_buff[0];
    let byte2 = small_buff[1];

    // process first byte
    const FIN_BIT_FLAG: u8 = 0x80;
    const OP_CODE_FLAG: u8 = 0x0F;
    let is_fin_bit_set = (byte1 & FIN_BIT_FLAG) == FIN_BIT_FLAG;
    let op_code = get_op_code(byte1 & OP_CODE_FLAG);

    // process second byte
    const MASK_FLAG: u8 = 0x80;
    let is_mask_bit_set = (byte2 & MASK_FLAG) == MASK_FLAG;
    let len = read_length(byte2, stream);

    if buffer.len() < len {
        panic!(
            "Websocket buffer ({} bytes) too small to fit websocket frame ({} bytes)",
            buffer.len(),
            len
        );
    }

    if is_mask_bit_set {
        let mut mask_key_buffer: [u8; 4] = [0; 4];
        read_into_buffer(stream, &mut mask_key_buffer, 4);
        read_into_buffer(stream, buffer, len as u64);
        toggle_mask(&mask_key_buffer, buffer);
    } else {
        read_into_buffer(stream, buffer, len as u64);
    }

    let frame = match op_code {
        WebSocketOpCode::ConnectionClose => {
            decode_close_frame(is_fin_bit_set, op_code, buffer, len)
        }
        _ => WebSocketFrame {
            count: len,
            op_code: op_code,
            close_status: None,
            close_status_description: None,
            is_fin_bit_set: is_fin_bit_set,
        },
    };

    frame
}

fn respond_to_close_frame(frame: WebSocketFrame) -> WebSocketReadResult {
    // TODO - do this properly - we may need to respond as part of the close handshake
    WebSocketReadResult {
        count: frame.count,
        close_status: frame.close_status,
        close_status_description: frame.close_status_description,
        end_of_message: true,
        message_type: WebSocketMessageType::Close,
    }
}

fn build_client_disconnected_frame() -> WebSocketFrame {
    WebSocketFrame {
        count: 0,
        op_code: WebSocketOpCode::ConnectionClose,
        close_status: Some(WebSocketCloseStatus::EndpointUnavailable),
        close_status_description: Some("Client disconnected".to_string()),
        is_fin_bit_set: false,
    }
}

fn get_op_code(val: u8) -> WebSocketOpCode {
    match val {
        0 => WebSocketOpCode::ContinuationFrame,
        1 => WebSocketOpCode::TextFrame,
        2 => WebSocketOpCode::BinaryFrame,
        8 => WebSocketOpCode::ConnectionClose,
        9 => WebSocketOpCode::Ping,
        10 => WebSocketOpCode::Pong,
        _ => panic!("Websocket opcode {} not valid"),
    }
}

fn toggle_mask(mask_key: &[u8], buffer: &mut [u8]) {
    let mask_key_len = mask_key.len();
    for i in 0..buffer.len() {
        buffer[i] = buffer[i] ^ mask_key[i % mask_key_len];
    }
}

fn decode_close_frame(
    _is_fin_bit_set: bool,
    _op_code: WebSocketOpCode,
    _buffer: &mut [u8],
    _len: usize,
) -> WebSocketFrame {
    build_client_disconnected_frame()
}

fn read_length<T: Read>(byte2: u8, stream: &mut T) -> usize {
    let len = byte2 & 0x7F;

    match len {
        126 => stream.read_u16::<BigEndian>().unwrap() as usize,
        127 => stream.read_u64::<BigEndian>().unwrap() as usize,
        _ => len as usize,
    }
}

// TODO Return a Result
fn read_into_buffer<T: Read>(stream: &mut T, buffer: &mut [u8], count: u64) -> bool {
    let mut handle = stream.take(count);
    let success = match handle.read(buffer) {
        Ok(num_bytes_read) => {
            let num_bytes_read = num_bytes_read as u64;
            num_bytes_read == count
        }
        _ => false,
    };

    success
}

fn write_frame<T: Read + Write>(
    stream: &mut T,
    is_client: bool,
    buffer: &[u8],
    count: usize,
    op_code: WebSocketOpCode,
    end_of_message: bool,
    rng: &mut rand::ThreadRng,
) {
    // more capacity if the length is large
    let mut capacity = if count < 126 {
        count + 2
    } else if count < 65535 {
        count + 4
    } else {
        count + 10
    };

    // if client then more capacity for the mask key
    if is_client {
        capacity += 4;
    }

    // this will buffer then write to the tcp stream once it goes out of scope
    let mut buffered_stream = BufWriter::with_capacity(capacity, stream);

    // write byte1
    let fin_bit_set_as_byte: u8 = if end_of_message { 0x80 } else { 0x00 };
    let byte1: u8 = fin_bit_set_as_byte | op_code as u8;
    buffered_stream.write(&[byte1]).unwrap();

    // write byte2 (and extra length bits if required)
    let mask_bit_set_as_byte = if is_client { 0x80 } else { 0x00 };
    if count < 126 {
        let byte2 = mask_bit_set_as_byte | count as u8;
        buffered_stream.write(&[byte2]).unwrap();
    } else if count < 65535 {
        let byte2 = mask_bit_set_as_byte | 126;
        buffered_stream.write(&[byte2]).unwrap();
        buffered_stream
            .write_u16::<LittleEndian>(count as u16)
            .unwrap();
    } else {
        let byte2 = mask_bit_set_as_byte | 127;
        buffered_stream.write(&[byte2]).unwrap();
        buffered_stream
            .write_u64::<LittleEndian>(count as u64)
            .unwrap();
    }

    if is_client {
        // if this is a client then we need to mask the bytes to prevent web server caching
        let mut mask_key: [u8; 4] = [0; 4];
        rng.fill_bytes(&mut mask_key);
        buffered_stream.write(&mask_key).unwrap();
        let slice = &buffer[..count];
        for i in 0..slice.len() {
            let masked_byte: u8 = slice[i] ^ mask_key[i % 4];

            // TODO: check if there is a faster way to do this
            buffered_stream.write(&[masked_byte]).unwrap();
        }
    } else {
        buffered_stream.write(&buffer[..count]).unwrap();
    }

    buffered_stream.flush().expect("Websocket write failed");
}

pub struct WebSocket<T: Read + Write> {
    is_client: bool,
    rng: rand::ThreadRng,
    stream: T,
    continuation_frame_op_code: Option<WebSocketOpCode>,
}

impl<T: Read + Write> WebSocket<T> {
    pub fn new_server(
        sec_websocket_key: &String,
        sec_websocket_protocol: Option<&String>,
        mut stream: T,
    ) -> WebSocket<T> {
        let mut http_response = String::from(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        );

        if let Some(sec_websocket_protocol) = sec_websocket_protocol {
            http_response.push_str("Sec-WebSocket-Protocol: ");
            http_response.push_str(sec_websocket_protocol);
            http_response.push_str("\r\n");
        }

        // concatenate the key with a known websocket guid (as per the spec)
        let mut accept_string = String::new();
        accept_string.push_str(sec_websocket_key);
        accept_string.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

        // hash the accept_string
        let mut hasher = Sha1::new();
        hasher.input_str(&accept_string);
        let mut hashed: [u8; 20] = [0; 20];
        hasher.result(&mut hashed);
        let base64_encoded = base64::encode(hashed.as_ref());
        //let base64_encoded = hasher.result_str();

        http_response.push_str("Sec-WebSocket-Accept: ");
        http_response.push_str(&base64_encoded);
        http_response.push_str("\r\n\r\n");

        // put the response on the wire
        &mut stream
            .write(http_response.as_bytes())
            .expect("Http handshake response write failed");

        WebSocket {
            is_client: false,
            rng: thread_rng(),
            stream: stream,
            continuation_frame_op_code: None,
        }
    }

    pub fn write(
        &mut self,
        buffer: &[u8],
        count: usize,
        message_type: WebSocketMessageType,
        end_of_message: bool,
    ) {
        let op_code = match message_type {
            WebSocketMessageType::Text => WebSocketOpCode::TextFrame,
            WebSocketMessageType::Binary => WebSocketOpCode::BinaryFrame,
            WebSocketMessageType::Close => WebSocketOpCode::ConnectionClose,
        };

        write_frame(
            &mut self.stream,
            self.is_client,
            buffer,
            count,
            op_code,
            end_of_message,
            &mut self.rng,
        )
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> WebSocketReadResult {
        let stream = &mut self.stream;

        loop {
            let frame = read_frame(stream, buffer);

            let result = match frame.op_code {
                WebSocketOpCode::Ping => {
                    write_frame(
                        stream,
                        self.is_client,
                        buffer,
                        frame.count,
                        WebSocketOpCode::Pong,
                        true,
                        &mut self.rng,
                    );
                    None
                }
                WebSocketOpCode::Pong => {
                    // ignore pong messages for now
                    None
                }
                WebSocketOpCode::ConnectionClose => Some(respond_to_close_frame(frame)),
                WebSocketOpCode::TextFrame => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    close_status_description: None,
                    message_type: WebSocketMessageType::Text,
                }),
                WebSocketOpCode::BinaryFrame => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    close_status_description: None,
                    message_type: WebSocketMessageType::Binary,
                }),
                WebSocketOpCode::ContinuationFrame => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    close_status_description: None,
                    message_type: self
                        .continuation_frame_op_code
                        .expect("Continuation frame received before a text or binary frame")
                        .to_message_type(),
                }),
            };

            if let Some(x) = result {
                return x;
            }
        }
    }
}

// ************************************************************ TESTS *****************************************************************************

// WORK IN PROGRESS
// TODO: figure out how to debug these in VS Code
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Result, Write};

    pub struct FullDuplexMemoryStream {
        read_stream: MemoryStream,
        write_stream: MemoryStream,
    }

    impl FullDuplexMemoryStream {
        pub fn new() -> FullDuplexMemoryStream {
            FullDuplexMemoryStream {
                read_stream: MemoryStream::new(),
                write_stream: MemoryStream::new(),
            }
        }
    }

    // Helper class to be used as an in memory reader and writer stream
    pub struct MemoryStream {
        buf: Vec<u8>,
        pos: usize,
    }

    impl MemoryStream {
        pub fn new() -> MemoryStream {
            MemoryStream {
                buf: vec![],
                pos: 0,
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let bytes_left = self.buf.len() - self.pos;

            if bytes_left <= 0 {
                return Ok(0);
            }

            let num_bytes_to_copy = if buf.len() > bytes_left {
                bytes_left
            } else {
                buf.len()
            };

            let destination = &mut buf[0..num_bytes_to_copy];
            destination.copy_from_slice(&self.buf[self.pos..self.pos + num_bytes_to_copy]);
            self.pos += num_bytes_to_copy;
            return Ok(0);
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.buf.extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cha() {
        let mut m = MemoryStream::new();

        let buf: [u8; 10] = [0; 10];
        m.write(&buf).unwrap();
        m.write(&buf).unwrap();

        let mut buf_out: [u8; 10] = [0; 10];
        m.read(&mut buf_out).unwrap();
    }

    //  #[test]
    fn _server_handshake() {
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

        let header = read_http_header(&client_request).expect("Failed to read http header");
        println!("Read http header");
        let websocket_context =
            get_websocket_context(&header).expect("Http header is not a websocket request");
        println!("Completed decoding header");

        let mut stream = MemoryStream::new();
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
