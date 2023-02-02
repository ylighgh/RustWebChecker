use checker::utils::parser_url::URL;
use checker::tcp::get_tcp_info::TCP;
use checker::tls::get_tls_info::TLS;
use checker::http::get_http_info::HTTP;


fn main() {
    let host = "https://www.baidu.com/";

    let url = URL::parser(host);
    let tcp = TCP::new(url.host.clone(), url.port.clone());
    match tcp.stream {
        Some(tcp_stream) => {
            let tls = TLS::new(tcp_stream, url.host.clone());
            match tls.stream {
                Some(tls_stream) => {
                    println!("alpn: {}", tls.alpn);
                    println!("hostname: {}", tls.certificate.hostname);
                    println!("subject_common_name: {}", tls.certificate.subject.common_name);
                    println!("sans: {:?}", tls.certificate.sans);
                    HTTP::new(tls_stream, url.host.clone(), url.port.clone(), url.path.clone());
                }
                None => {}
            }
        }
        None => { println!("{}", tcp.alert_info) }
    }
}