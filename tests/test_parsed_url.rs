use checker::utils::parser_url::URL;

#[test]
fn test_parsed_url() {
    let url_info = URL::parser("https://www.baidu.com:12345/123.txt");
    assert_eq!(url_info.protocol, "https");
    assert_eq!(url_info.host, "www.baidu.com");
    assert_eq!(url_info.port, 12345);
    assert_eq!(url_info.path, "/123.txt");
}