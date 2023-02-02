use std::collections::HashMap;

pub struct URL {
    pub protocol: String,
    pub host: String,
    pub port: isize,
    pub path: String,
}


impl URL {
    pub fn parser(url: &str) -> URL {
        let mut protocol: &str = "http";
        let uri: &str;
        let mut host: &str;
        let path: &str;
        let mut port: isize;


        // 检查协议
        if &url[0..7] == "http://" {
            let v: Vec<&str> = url.split("://").collect();
            uri = v[1]
        } else if &url[0..8] == "https://" {
            protocol = "https";
            let v: Vec<&str> = url.split("://").collect();
            uri = v[1]
        } else {
            uri = url
        }

        // 检查path
        let i = uri.find("/");
        match i {
            Some(index) => {
                host = &uri[0..index];
                path = &uri[index..uri.len()]
            }
            None => {
                host = uri;
                path = "/";
            }
        }

        // 检查端口
        let mut port_map: HashMap<&str, isize> = HashMap::new();
        port_map.insert("http", 80);
        port_map.insert("https", 443);
        port = port_map[protocol];
        if host.contains(":") {
            let v: Vec<&str> = host.split(":").collect();
            host = v[0];
            port = v[1].parse().unwrap();
        }

        URL {
            protocol: protocol.to_string(),
            host: host.to_string(),
            port,
            path: path.to_string(),
        }
    }
}
