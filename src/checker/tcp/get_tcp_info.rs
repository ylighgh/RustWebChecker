use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

static TIMEOUT: u64 = 3;

pub struct TCP {
    pub stream: Option<TcpStream>,
    pub alert_info: String,
}

impl TCP {
    pub fn new(host: String, port: isize) -> TCP {
        let remote = format!("{}:{}", host, port);
        let socket_addr = remote.to_socket_addrs().unwrap().next().unwrap();
        let tcp_stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(TIMEOUT));
        match tcp_stream {
            Ok(tcp_stream) => TCP {
                stream: Option::from(tcp_stream),
                alert_info: "".to_string(),
            },
            Err(e) => TCP {
                stream: None,
                alert_info: e.to_string(),
            }
        }
    }
}