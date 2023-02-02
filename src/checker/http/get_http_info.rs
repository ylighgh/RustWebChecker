use std::io::{Read, Write};
use std::net::TcpStream;
use openssl::ssl::SslStream;
use httparse;

pub struct HTTP {
    pub version: String,
    pub response_code: isize,
    pub response_time: String,
    pub server_type: String,
    pub content_encoding: String,
    pub server_ip: String,
    pub server_port: isize,
}

impl HTTP {
    pub fn new(mut stream: Option<T>, host: String, port: isize, path: String) {
        let request_data = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: gzip,deflate\r\n\r\n", path, host);

        stream.write_all(request_data.as_bytes()).expect("send http request error");

        let mut buf = String::new();
        stream.read_to_string(&mut buf).expect("accept http response error");

        response_parser(buf, host, port);
    }
}


pub fn response_parser(response: String, _host: String, _port: isize) {
    let buf = response.as_bytes();
    
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Response::new(&mut headers);
    let res = req.parse(buf).unwrap();

    if res.is_complete() {
        for i in 0..req.headers.len() {
            let key = req.headers[i].name;
            let value = String::from_utf8_lossy(req.headers[i].value).to_string();
            println!("{}:{}", key, value);
        }
    }
}
