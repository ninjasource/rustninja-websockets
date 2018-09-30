extern crate httparse;
extern crate websockets;

use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use websockets::*;

fn main() {
    // TODO: this is a horrible way to get the www root path. Make it nicer
    let args: Vec<_> = env::args().collect();
    let mut www_root_path = Path::new(&args[0])
        .parent()
        .expect("Invalid path")
        .to_str()
        .unwrap()
        .to_owned();
    if Path::new(&www_root_path).exists() {
        www_root_path += "\\";
    }
    www_root_path += "..\\..\\wwwroot";

    if Path::new(&www_root_path).exists() {
        println!("www root path: {}", www_root_path);
        println!("localhost listening on port 5000");
        let listner = TcpListener::bind("127.0.0.1:5000").unwrap();
        for stream in listner.incoming() {
            let stream = stream.unwrap();
            handle_connection(stream, &www_root_path);
        }
    } else {
        println!("www root path not found: {}", www_root_path);
    }
}

fn send_404(mut stream: &TcpStream) {
    let response = "HTTP/1.1 404 Not Found".as_bytes();
    stream.write(&response).expect("Write failed");
}

fn handle_connection(mut stream: TcpStream, www_root_path: &str) {
    let mut buffer: [u8; 1024] = [0; 1024];
    stream.read(&mut buffer).unwrap();
    let s: String = String::from_utf8_lossy(&buffer[..]).to_string();
    let http_header = read_http_header(&s);

    println!("Request: '{}'", s);

    if let Some(header) = http_header {
        println!("Completed reading http header");
        if let Some(websocket_context) = get_websocket_context(&header) {
            handle_websocket_request(websocket_context, stream, buffer);
        } else {
            handle_file_request(&header, www_root_path, stream);
        }
    } else {
        println!("FAILED");
    }
}

fn handle_websocket_request(
    websocket_context: WebSocketContext,
    stream: TcpStream,
    mut buffer: [u8; 1024],
) {
    println!("This is a websocket request. Responding to handshake");
    let mut ws = WebSocket::new_server(&websocket_context.sec_websocket_key, None, stream);
    println!("Handshake complete");
    loop {
        let result = ws.read(&mut buffer);
        match result.message_type {
            WebSocketReceiveMessageType::Close => {
                println!("Connection closed");
                break;
            }
            WebSocketReceiveMessageType::Text => {
                println!("Received {} Text bytes", result.count);
                let s = match std::str::from_utf8(&buffer[..result.count]) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                println!("Received: {}", s);
                let to_send = s.as_bytes();
                ws.write(to_send, to_send.len(), WebSocketSendMessageType::Text, true);
                println!("Sent: {}", s);
            }
            WebSocketReceiveMessageType::Binary => {
                println!("Received {} Binary bytes", result.count);
            }
            WebSocketReceiveMessageType::Pong => {
                println!("Received {} Pong bytes", result.count);
            }
        }
    }
}

fn handle_file_request(header: &HttpHeader, www_root_path: &str, mut stream: TcpStream) {
    if header.path == "/" {
        let index_file = www_root_path.to_owned() + "\\index.html";
        let index_file = index_file.as_str();
        if let Ok(mut file) = File::open(index_file) {
            if let Ok(metadata) = fs::metadata(index_file) {
                let len = metadata.len();
                let mut response = String::from(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=UTF-8\r\nContent-Length: ",
                );
                response.push_str(&len.to_string());
                response.push_str("\r\n\r\n");

                let mut buf = response.into_bytes();

                file.read_to_end(&mut buf).expect("Read failed");
                stream.write(&buf).expect("Write failed");
                println!("Sent file: {}", index_file);
            }
        } else {
            println!("File not found: {}", index_file);
            send_404(&stream);
        }
    } else {
        println!("Unknown header path {}", header.path);
        send_404(&stream);
    }
}
