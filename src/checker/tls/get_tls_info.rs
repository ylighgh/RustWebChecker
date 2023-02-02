use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::{X509NameEntries, X509};
use serde::{Deserialize, Serialize};
use std::net::{TcpStream};
use std::ops::Deref;

pub struct TLS {
    pub stream: Option<SslStream<TcpStream>>,
    pub alpn: String,
    pub certificate: Certificate,
    pub warning_info: Vec<String>,
    pub alert_info: Vec<String>,
}


#[derive(Serialize, Deserialize)]
pub struct Certificate {
    pub hostname: String,
    pub subject: Subject,
    pub issued: Issuer,
    pub valid_from: String,
    pub valid_to: String,
    pub valid_day_to_expire: i32,
    pub is_expired: bool,
    pub cert_sn: String,
    pub cert_ver: String,
    pub cert_alg: String,
    pub sans: Vec<String>,
}


#[derive(Serialize, Deserialize)]
pub struct Issuer {
    pub country_or_region: String,
    pub organization: String,
    pub common_name: String,
    pub organization_unit: String,
}

#[derive(Serialize, Deserialize)]
pub struct Subject {
    pub country_or_region: String,
    pub state_or_province: String,
    pub locality: String,
    pub organization_unit: String,
    pub organization: String,
    pub common_name: String,
}


impl TLS {
    pub fn new(stream: TcpStream, host: String) -> TLS {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        context.set_verify(SslVerifyMode::empty());

        let protos: &[&[u8]] = &[b"h2", b"http/1.1"];
        let wire = protos.into_iter().flat_map(|proto| {
            let mut proto = proto.to_vec();
            let len: u8 = proto.len().try_into().expect("proto is too long");
            proto.insert(0, len);
            proto
        }).collect::<Vec<_>>();

        context.set_alpn_protos(&*wire).expect("set ALPN error");

        let context_builder = context.build();

        let mut connector = Ssl::new(&context_builder).unwrap();
        connector.set_hostname(&*host).unwrap();

        let tls_stream = connector
            .connect(stream)
            .expect("tls handshake failed.");

        let buf = tls_stream.ssl().selected_alpn_protocol().unwrap();
        let alpn = String::from_utf8_lossy(buf).to_string();

        let x509_ref = tls_stream
            .ssl()
            .peer_certificate()
            .ok_or("Certificate not found")
            .unwrap();

        let data = get_certificate_info(&x509_ref);
        let certificate = Certificate {
            hostname: host.to_string(),
            subject: data.subject,
            issued: data.issued,
            valid_from: data.valid_from,
            valid_to: data.valid_to,
            valid_day_to_expire: data.valid_day_to_expire,
            is_expired: data.is_expired,
            cert_sn: data.cert_sn,
            cert_ver: data.cert_ver,
            cert_alg: data.cert_alg,
            sans: data.sans,
        };

        // check_hostname(&certificate.hostname, &certificate.sans);

        TLS {
            stream: Option::from(tls_stream),
            alpn,
            certificate,
            warning_info: vec![],
            alert_info: vec![],
        }
    }
}


fn from_entries(mut entries: X509NameEntries) -> String {
    match entries.next() {
        None => "None".to_string(),
        Some(x509_name_ref) => x509_name_ref.data().as_utf8().unwrap().to_string(),
    }
}

fn get_subject(cert_ref: &X509) -> Subject {
    let subject_country_region =
        from_entries(cert_ref.subject_name().entries_by_nid(Nid::COUNTRYNAME));
    let subject_state_province = from_entries(
        cert_ref
            .subject_name()
            .entries_by_nid(Nid::STATEORPROVINCENAME),
    );
    let subject_locality = from_entries(cert_ref.subject_name().entries_by_nid(Nid::LOCALITYNAME));
    let subject_organization_unit = from_entries(
        cert_ref
            .subject_name()
            .entries_by_nid(Nid::ORGANIZATIONALUNITNAME),
    );
    let subject_common_name = from_entries(cert_ref.subject_name().entries_by_nid(Nid::COMMONNAME));
    let organization_name = from_entries(
        cert_ref
            .subject_name()
            .entries_by_nid(Nid::ORGANIZATIONNAME),
    );

    Subject {
        country_or_region: subject_country_region,
        state_or_province: subject_state_province,
        locality: subject_locality,
        organization_unit: subject_organization_unit,
        organization: organization_name,
        common_name: subject_common_name,
    }
}

fn get_issuer(cert_ref: &X509) -> Issuer {
    let issuer_common_name = from_entries(cert_ref.issuer_name().entries_by_nid(Nid::COMMONNAME));
    let issuer_organization_name =
        from_entries(cert_ref.issuer_name().entries_by_nid(Nid::ORGANIZATIONNAME));
    let issuer_country_region =
        from_entries(cert_ref.issuer_name().entries_by_nid(Nid::COUNTRYNAME));
    let issuer_organization_unit = from_entries(cert_ref.issuer_name().entries_by_nid(Nid::ORGANIZATIONALUNITNAME));
    Issuer {
        country_or_region: issuer_country_region,
        organization_unit: issuer_organization_unit,
        organization: issuer_organization_name,
        common_name: issuer_common_name,
    }
}

fn get_certificate_info(cert_ref: &X509) -> Certificate {
    let mut sans = Vec::new();
    match cert_ref.subject_alt_names() {
        None => {}
        Some(general_names) => {
            for general_name in general_names {
                sans.push(general_name.dnsname().unwrap().to_string());
            }
        }
    }

    return Certificate {
        hostname: "None".to_string(),
        subject: get_subject(cert_ref),
        issued: get_issuer(cert_ref),
        valid_from: cert_ref.not_before().to_string(),
        valid_to: cert_ref.not_after().to_string(),
        valid_day_to_expire: get_validity_days(cert_ref.not_after()),
        is_expired: has_expired(cert_ref.not_after()),
        cert_sn: cert_ref.serial_number().to_bn().unwrap().to_string(),
        cert_ver: cert_ref.version().to_string(),
        cert_alg: cert_ref.signature_algorithm().object().to_string(),
        sans,
    };
}

fn get_validity_days(not_after: &Asn1TimeRef) -> i32 {
    return Asn1Time::days_from_now(0)
        .unwrap()
        .deref()
        .diff(not_after)
        .unwrap()
        .days;
}

fn has_expired(not_after: &Asn1TimeRef) -> bool {
    !(not_after > Asn1Time::days_from_now(0).unwrap())
}

// fn tls_checker(cert: Certificate) {}
//
// fn check_hostname(host: &String, san: &Vec<String>) {
//     println!("{}", host);
//     println!("{:?}", san);
// }