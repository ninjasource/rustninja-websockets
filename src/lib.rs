// ---------------------------------------------------------------------
// Copyright 2018 David Haig
// MIT Licence
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
// ---------------------------------------------------------------------

// The library below implements version 13 of the WebSocket protocol
// see http://tools.ietf.org/html/rfc6455 for specification

extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate httparse;
extern crate rand;
use self::byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use self::rand::thread_rng;
use self::rand::RngCore;
use std::io::BufWriter;
use std::io::Cursor;
use std::io::{Error, ErrorKind, Read, Result, Write};

pub struct HttpHeader {
    pub path: String,
    pub websocket_context: Option<WebSocketContext>,
}

pub struct WebSocketContext {
    pub sec_websocket_protocol_list: Vec<String>,
    pub sec_websocket_key: String,
}

#[derive(PartialEq, Debug)]
pub enum WebSocketSendMessageType {
    Text = 1,
    Binary = 2,
    Ping = 9,
}

#[derive(PartialEq, Debug)]
pub enum WebSocketReceiveMessageType {
    Text = 1,
    Binary = 2,
    Close = 8,
    Pong = 10,
}

pub struct WebSocketCloseStatus {
    pub code: WebSocketCloseStatusCode,
    pub description: String,
}

#[derive(PartialEq, Debug)]
pub enum WebSocketCloseStatusCode {
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
    pub message_type: WebSocketReceiveMessageType,
}

#[derive(Copy, Clone, Debug)]
enum WebSocketOpCode {
    ContinuationFrame = 0,
    TextFrame = 1,
    BinaryFrame = 2,
    ConnectionClose = 8,
    Ping = 9,
    Pong = 10,
}

#[derive(PartialEq)]
enum WebSocketState {
    _None = 0,
    _Connecting = 1,
    Open = 2,
    CloseSent = 3,
    CloseReceived = 4,
    Closed = 5,
    _Aborted = 6,
}

impl WebSocketOpCode {
    fn to_message_type(&self) -> Result<WebSocketReceiveMessageType> {
        match self {
            WebSocketOpCode::TextFrame => Ok(WebSocketReceiveMessageType::Text),
            WebSocketOpCode::BinaryFrame => Ok(WebSocketReceiveMessageType::Binary),
            WebSocketOpCode::ConnectionClose => Ok(WebSocketReceiveMessageType::Close),
            _ => Err(std::io::Error::new(
                ErrorKind::Other,
                "Cannot convert op code to message type",
            )),
        }
    }
}

struct WebSocketFrame {
    is_fin_bit_set: bool,
    op_code: WebSocketOpCode,
    count: usize,
    close_status: Option<WebSocketCloseStatus>,
}

pub struct WebSocket<'a, T: Read + Write> {
    is_client: bool,
    rng: rand::ThreadRng,
    stream: &'a mut T,
    continuation_frame_op_code: Option<WebSocketOpCode>,
    state: WebSocketState,
}

impl<'a, T: Read + Write> WebSocket<'a, T> {
    pub fn new_server(
        sec_websocket_key: &String,
        sec_websocket_protocol: Option<&String>,
        stream: &'a mut T,
    ) -> Result<WebSocket<'a, T>> {
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

        http_response.push_str("Sec-WebSocket-Accept: ");
        http_response.push_str(&base64_encoded);
        http_response.push_str("\r\n\r\n");

        // put the response on the wire
        stream.write(http_response.as_bytes())?;

        Ok(WebSocket {
            is_client: false,
            rng: thread_rng(),
            stream,
            continuation_frame_op_code: None,
            state: WebSocketState::Open,
        })
    }

    pub fn close(
        &mut self,
        close_status: WebSocketCloseStatusCode,
        status_description: &str,
    ) -> Result<()> {
        if self.state == WebSocketState::Open {
            self.state = WebSocketState::CloseSent;

            let mut vec: Vec<u8> = vec![];
            vec.write_u16::<BigEndian>(close_status as u16).unwrap();
            vec.extend(status_description.as_bytes());

            write_frame(
                &mut self.stream,
                self.is_client,
                &vec[..],
                vec.len(),
                WebSocketOpCode::ConnectionClose,
                true,
                &mut self.rng,
            )?
        }

        Ok(())
    }

    pub fn write(
        &mut self,
        buffer: &[u8],
        count: usize,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
    ) -> Result<()> {
        let op_code = match message_type {
            WebSocketSendMessageType::Text => WebSocketOpCode::TextFrame,
            WebSocketSendMessageType::Binary => WebSocketOpCode::BinaryFrame,
            WebSocketSendMessageType::Ping => WebSocketOpCode::Ping,
        };

        write_frame(
            &mut self.stream,
            self.is_client,
            buffer,
            count,
            op_code,
            end_of_message,
            &mut self.rng,
        )?;

        Ok(())
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Result<WebSocketReadResult> {
        let stream = &mut self.stream;

        loop {
            let frame = read_frame(stream, buffer)?;

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
                    )?;
                    None
                }
                WebSocketOpCode::Pong => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    message_type: WebSocketReceiveMessageType::Pong,
                }),
                WebSocketOpCode::ConnectionClose => Some(respond_to_close_frame(
                    &mut self.state,
                    stream,
                    buffer,
                    frame,
                    self.is_client,
                    &mut self.rng,
                )?),
                WebSocketOpCode::TextFrame => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    message_type: WebSocketReceiveMessageType::Text,
                }),
                WebSocketOpCode::BinaryFrame => Some(WebSocketReadResult {
                    count: frame.count,
                    end_of_message: frame.is_fin_bit_set,
                    close_status: None,
                    message_type: WebSocketReceiveMessageType::Binary,
                }),
                WebSocketOpCode::ContinuationFrame => match self.continuation_frame_op_code {
                    Some(cf_op_code) => Some(WebSocketReadResult {
                        count: frame.count,
                        end_of_message: frame.is_fin_bit_set,
                        close_status: None,
                        message_type: cf_op_code.to_message_type()?,
                    }),
                    None => {
                        return Err(std::io::Error::new(
                            ErrorKind::Other,
                            "Continuation frame received before a text or binary frame",
                        ))
                    }
                },
            };

            if let Some(x) = result {
                return Ok(x);
            }
        }
    }
}

pub fn read_http_header<T: Read>(stream: &mut T, buffer: &mut [u8]) -> Result<HttpHeader> {
    let mut num_bytes_read = 0;

    loop {
        // read bytes into buffer
        num_bytes_read += stream.read(&mut buffer[num_bytes_read..])?;
        if num_bytes_read == 0 {
            return Err(Error::new(ErrorKind::Other, "Read zero bytes from stream"));
        }

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        if req
            .parse(&mut buffer[..num_bytes_read])
            .unwrap()
            .is_complete()
        {
            let path = String::from(req.path.expect("no path specified in http header"));
            let mut sec_websocket_protocol_list: Vec<String> = Vec::new();
            let mut is_websocket_request = false;
            let mut sec_websocket_key = String::new();

            for item in req.headers.iter() {
                match item.name {
                    "Upgrade" => {
                        is_websocket_request =
                            String::from_utf8_lossy(item.value).to_string() == "websocket"
                    }
                    "Sec-WebSocket-Protocol" => {
                        // extract a csv list of supported sub protocols
                        for item in String::from_utf8_lossy(item.value).to_string().split(',') {
                            sec_websocket_protocol_list.push(String::from(item));
                        }
                    }
                    "Sec-WebSocket-Key" => {
                        sec_websocket_key = String::from_utf8_lossy(item.value).to_string();
                    }
                    &_ => {
                        // ignore all other headers
                    }
                }
            }

            let websocket_context = {
                if is_websocket_request {
                    // TODO: check version
                    Some(WebSocketContext {
                        sec_websocket_protocol_list,
                        sec_websocket_key,
                    })
                } else {
                    None
                }
            };

            let header = HttpHeader {
                path,
                websocket_context,
            };

            return Ok(header);
        }
    }
}

fn read_frame<T: Read>(stream: &mut T, buffer: &mut [u8]) -> Result<WebSocketFrame> {
    let mut small_buff: [u8; 2] = [0; 2];
    read_into_buffer(stream, &mut small_buff, 2)?;
    let byte1 = small_buff[0];
    let byte2 = small_buff[1];

    // process first byte
    const FIN_BIT_FLAG: u8 = 0x80;
    const OP_CODE_FLAG: u8 = 0x0F;
    let is_fin_bit_set = (byte1 & FIN_BIT_FLAG) == FIN_BIT_FLAG;
    let op_code = get_op_code(byte1 & OP_CODE_FLAG)?;

    // process second byte
    const MASK_FLAG: u8 = 0x80;
    let is_mask_bit_set = (byte2 & MASK_FLAG) == MASK_FLAG;
    let len = read_length(byte2, stream)?;

    if buffer.len() < len {
        panic!(
            "Websocket buffer ({} bytes) too small to fit websocket frame ({} bytes)",
            buffer.len(),
            len
        );
    }

    if is_mask_bit_set {
        let mut mask_key_buffer: [u8; 4] = [0; 4];
        read_into_buffer(stream, &mut mask_key_buffer, 4)?;
        read_into_buffer(stream, buffer, len as usize)?;
        toggle_mask(&mask_key_buffer, buffer);
    } else {
        read_into_buffer(stream, buffer, len as usize)?;
    }

    let frame = match op_code {
        WebSocketOpCode::ConnectionClose => decode_close_frame(buffer, len)?,
        _ => WebSocketFrame {
            count: len,
            op_code,
            close_status: None,
            is_fin_bit_set,
        },
    };

    Ok(frame)
}

fn build_client_disconnected_frame() -> WebSocketFrame {
    let close_status = WebSocketCloseStatus {
        code: WebSocketCloseStatusCode::EndpointUnavailable,
        description: "Client disconnected".to_string(),
    };
    WebSocketFrame {
        count: 0,
        op_code: WebSocketOpCode::ConnectionClose,
        close_status: Some(close_status),
        is_fin_bit_set: false,
    }
}

fn get_op_code(val: u8) -> Result<WebSocketOpCode> {
    match val {
        0 => Ok(WebSocketOpCode::ContinuationFrame),
        1 => Ok(WebSocketOpCode::TextFrame),
        2 => Ok(WebSocketOpCode::BinaryFrame),
        8 => Ok(WebSocketOpCode::ConnectionClose),
        9 => Ok(WebSocketOpCode::Ping),
        10 => Ok(WebSocketOpCode::Pong),
        _ => Err(std::io::Error::new(
            ErrorKind::Other,
            format!("Websocket opcode {} not valid", val),
        )),
    }
}

fn toggle_mask(mask_key: &[u8], buffer: &mut [u8]) {
    let mask_key_len = mask_key.len();
    for i in 0..buffer.len() {
        buffer[i] = buffer[i] ^ mask_key[i % mask_key_len];
    }
}

fn u16_to_close_status(code: u16) -> WebSocketCloseStatusCode {
    match code {
        1000 => WebSocketCloseStatusCode::NormalClosure,
        1001 => WebSocketCloseStatusCode::EndpointUnavailable,
        1002 => WebSocketCloseStatusCode::ProtocolError,
        1003 => WebSocketCloseStatusCode::InvalidMessageType,
        1005 => WebSocketCloseStatusCode::Empty,
        1007 => WebSocketCloseStatusCode::InvalidPayloadData,
        1008 => WebSocketCloseStatusCode::PolicyViolation,
        1009 => WebSocketCloseStatusCode::MessageTooBig,
        1010 => WebSocketCloseStatusCode::MandatoryExtension,
        1011 => WebSocketCloseStatusCode::InternalServerError,
        _ => panic!("Unknown close status: {}", code),
    }
}

fn decode_close_frame(buffer: &mut [u8], len: usize) -> Result<WebSocketFrame> {
    if len >= 2 {
        let mut stream = Cursor::new(&buffer[..2]);
        let code = stream.read_u16::<BigEndian>()?;
        let close_status_code = u16_to_close_status(code);
        let close_status_description = String::from_utf8_lossy(&buffer[2..len]).to_string();

        let close_status = WebSocketCloseStatus {
            code: close_status_code,
            description: close_status_description,
        };
        return Ok(WebSocketFrame {
            count: 0,
            op_code: WebSocketOpCode::ConnectionClose,
            close_status: Some(close_status),
            is_fin_bit_set: false,
        });
    }

    Ok(build_client_disconnected_frame())
}

fn read_length<T: Read>(byte2: u8, stream: &mut T) -> Result<usize> {
    let len = byte2 & 0x7F;

    if len < 126 {
        return Ok(len as usize);
    } else if len == 126 {
        return Ok(stream.read_u16::<BigEndian>()? as usize);
    } else if len == 127 {
        return Ok(stream.read_u64::<BigEndian>()? as usize);
    }

    Err(Error::new(
        ErrorKind::Other,
        format!("Invalid length (must be between 0 and 127): {}", len),
    ))
}

fn read_into_buffer<T: Read>(stream: &mut T, buffer: &mut [u8], count: usize) -> Result<()> {
    let mut num_bytes: usize = 0;
    while num_bytes < count {
        num_bytes += stream.read(&mut buffer[num_bytes..count])?
    }

    Ok(())
}

fn respond_to_close_frame<T: Write>(
    state: &mut WebSocketState,
    stream: &mut T,
    buffer: &[u8],
    frame: WebSocketFrame,
    is_client: bool,
    rng: &mut rand::ThreadRng,
) -> Result<WebSocketReadResult> {
    if *state == WebSocketState::CloseSent {
        // we initiated the close, this is the other party's response
        *state = WebSocketState::Closed;
    } else if *state == WebSocketState::Open {
        // respond to close handshake (other party initiated close)
        *state = WebSocketState::CloseReceived;
        write_frame(
            stream,
            is_client,
            buffer,
            frame.count,
            WebSocketOpCode::ConnectionClose,
            true,
            rng,
        )?;
    }

    Ok(WebSocketReadResult {
        count: frame.count,
        close_status: frame.close_status,
        end_of_message: true,
        message_type: WebSocketReceiveMessageType::Close,
    })
}

fn write_frame<T: Write>(
    stream: &mut T,
    is_client: bool,
    buffer: &[u8],
    count: usize,
    op_code: WebSocketOpCode,
    end_of_message: bool,
    rng: &mut rand::ThreadRng,
) -> Result<()> {
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
    buffered_stream.write(&[byte1])?;

    // write byte2 (and extra length bits if required)
    let mask_bit_set_as_byte = if is_client { 0x80 } else { 0x00 };
    if count < 126 {
        let byte2 = mask_bit_set_as_byte | count as u8;
        buffered_stream.write(&[byte2])?;
    } else if count < 65535 {
        let byte2 = mask_bit_set_as_byte | 126;
        buffered_stream.write(&[byte2])?;
        buffered_stream.write_u16::<LittleEndian>(count as u16)?;
    } else {
        let byte2 = mask_bit_set_as_byte | 127;
        buffered_stream.write(&[byte2])?;
        buffered_stream.write_u64::<LittleEndian>(count as u64)?
    }

    if is_client {
        // if this is a client then we need to mask the bytes to prevent web server caching
        let mut mask_key: [u8; 4] = [0; 4];
        rng.fill_bytes(&mut mask_key);
        buffered_stream.write(&mask_key)?;
        let slice = &buffer[..count];
        for i in 0..slice.len() {
            let masked_byte: u8 = slice[i] ^ mask_key[i % 4];

            // TODO: check if there is a faster way to do this
            buffered_stream.write(&[masked_byte])?;
        }
    } else {
        buffered_stream.write(&buffer[..count])?;
    }

    buffered_stream.flush()?;
    Ok(())
}

// ************************************************************************************************************************************************
// ************************************************************ TESTS *****************************************************************************
// ************************************************************************************************************************************************

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::{Read, Write};

    #[test]
    fn opening_handshake() {
        let client_request = "GET /chat HTTP/1.1
Host: localhost:5000
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

        let network_buffer: Vec<u8> = Vec::new();
        let mut stream = Cursor::new(network_buffer);
        stream.write(client_request.as_bytes()).unwrap(); // write the header to the network stream
        stream.set_position(0);
        let mut receive_buffer: [u8; 2048] = [0; 2048];
        let header =
            read_http_header(&mut stream, &mut receive_buffer).expect("Failed to read http header");
        let websocket_context = header
            .websocket_context
            .expect("Http header is not a websocket request");

        // initiate the server handshake an immediately give back ownership of the steam
        // discard the websocket, we only want to test the handshake
        let position = stream.position();
        {
            WebSocket::new_server(&websocket_context.sec_websocket_key, None, &mut stream)
                .expect("Failed to create new websocket server");
        }
        stream.set_position(position);

        //let mut receive_buffer: [u8; 512] = [0; 512];
        match stream.read(&mut receive_buffer) {
            Ok(size) => {
                println!("Size: {}", size);
                let s = std::str::from_utf8(&receive_buffer[..size]).unwrap();
                let client_response_expected = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n";
                println!("Response: '{}'", s);
                assert_eq!(client_response_expected, s);
            }
            Err(..) => assert!(false, "Failed to read stream"),
        }
    }

    #[test]
    fn client_to_server_message() {
        send_test_message(true);
    }

    #[test]
    fn server_to_client_message() {
        send_test_message(false);
    }

    #[test]
    fn closing_handshake() {
        let b: Vec<u8> = vec![];
        let mut stream = Cursor::new(b);
        let mut buf_out: [u8; 255] = [0; 255];
        let goodbye_message = "so long and thanks for all the fish";

        {
            let mut ws = WebSocket {
                is_client: true,
                rng: thread_rng(),
                stream: &mut stream,
                continuation_frame_op_code: None,
                state: WebSocketState::Open,
            };

            ws.close(WebSocketCloseStatusCode::NormalClosure, goodbye_message)
                .expect("Failed to close");
        }

        stream.set_position(0);

        {
            let mut ws = WebSocket {
                is_client: !false,
                rng: thread_rng(),
                stream: &mut stream,
                continuation_frame_op_code: None,
                state: WebSocketState::Open,
            };

            let result = ws.read(&mut buf_out).expect("Failed to read");
            println!("Received {} bytes", result.count);

            assert_eq!(WebSocketReceiveMessageType::Close, result.message_type);
            let close_status = result.close_status.unwrap();
            assert_eq!(WebSocketCloseStatusCode::NormalClosure, close_status.code);
            assert_eq!(goodbye_message, close_status.description);
        }
    }

    fn send_test_message(from_client_to_server: bool) {
        let b: Vec<u8> = vec![];
        let mut stream = Cursor::new(b);
        let mut buf_out: [u8; 255] = [0; 255];
        let buf_in = "hello, world".as_bytes();

        {
            let mut ws = WebSocket {
                is_client: from_client_to_server,
                rng: thread_rng(),
                stream: &mut stream,
                continuation_frame_op_code: None,
                state: WebSocketState::Open,
            };

            ws.write(buf_in, buf_in.len(), WebSocketSendMessageType::Text, true)
                .expect("Failed to write");
        }

        stream.set_position(0);

        {
            let mut ws = WebSocket {
                is_client: !from_client_to_server,
                rng: thread_rng(),
                stream: &mut stream,
                continuation_frame_op_code: None,
                state: WebSocketState::Open,
            };

            let result = ws.read(&mut buf_out).expect("Failed to read");
            println!("Received {} bytes", result.count);
            let s = std::str::from_utf8(&buf_out[..result.count]).unwrap();
            assert_eq!("hello, world", s);
        }
    }
}
