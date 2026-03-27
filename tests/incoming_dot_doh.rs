use std::{sync::Arc, time::Duration};

use balnceDNS::{
    config::{BalancingAlgorithm, SecurityConfig, TlsConfig, UpstreamConfig, UpstreamProto},
    incoming::{DohServer, DotServer},
    upstream::{Balancer, UpstreamSet},
};
use rand::Rng as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};

#[tokio::test(flavor = "multi_thread")]
async fn incoming_dot_roundtrip() {
    let (cert_path, key_path, cert_der) = make_self_signed_cert();

    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = match upstream_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut resp = buf[..n].to_vec();
            if resp.len() >= 4 {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                let b = (flags | 0x8000).to_be_bytes();
                resp[2] = b[0];
                resp[3] = b[1];
            }
            let _ = upstream_sock.send_to(&resp, peer).await;
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "up".to_string(),
            proto: UpstreamProto::Udp,
            addr: Some(upstream_addr),
            url: None,
            server_name: None,
            tls_insecure: false,
            pool: "default".to_string(),
            weight: 1,
        }])
        .unwrap(),
    );
    let balancer = Arc::new(Balancer::new(BalancingAlgorithm::RoundRobin));
    let security = SecurityConfig {
        deny_any: false,
        deny_dnskey: false,
        request_timeout_ms: 1500,
    };

    let dot = DotServer::new(
        "127.0.0.1:0".parse().unwrap(),
        TlsConfig {
            cert_pem: cert_path.to_string_lossy().to_string(),
            key_pem: key_path.to_string_lossy().to_string(),
        },
        upstreams,
        balancer,
        security,
        None,
        None,
        None,
        None,
        Arc::new(balnceDNS::hooks::Hooks::new::<String>(None)),
    )
    .await
    .unwrap();
    let dot_addr = dot.local_addr();
    let task = tokio::spawn(async move { dot.run().await });

    let client_cfg = rustls_client_with_root(cert_der);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(dot_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("dot.test").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let query = build_query(0x1111, RecordType::A);
    tls.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
    tls.write_all(&query).await.unwrap();

    let mut len_buf = [0u8; 2];
    time::timeout(Duration::from_secs(3), tls.read_exact(&mut len_buf))
        .await
        .unwrap()
        .unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    tls.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp.get(0..2).map(|b| u16::from_be_bytes([b[0], b[1]])), Some(0x1111));

    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn incoming_doh_roundtrip() {
    let (cert_path, key_path, _cert_der) = make_self_signed_cert();

    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = match upstream_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut resp = buf[..n].to_vec();
            if resp.len() >= 4 {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                let b = (flags | 0x8000).to_be_bytes();
                resp[2] = b[0];
                resp[3] = b[1];
            }
            let _ = upstream_sock.send_to(&resp, peer).await;
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "up".to_string(),
            proto: UpstreamProto::Udp,
            addr: Some(upstream_addr),
            url: None,
            server_name: None,
            tls_insecure: false,
            pool: "default".to_string(),
            weight: 1,
        }])
        .unwrap(),
    );
    let balancer = Arc::new(Balancer::new(BalancingAlgorithm::RoundRobin));
    let security = SecurityConfig {
        deny_any: false,
        deny_dnskey: false,
        request_timeout_ms: 1500,
    };

    let doh = DohServer::new(
        "127.0.0.1:0".parse().unwrap(),
        TlsConfig {
            cert_pem: cert_path.to_string_lossy().to_string(),
            key_pem: key_path.to_string_lossy().to_string(),
        },
        upstreams,
        balancer,
        security,
        None,
        None,
        None,
        None,
        Arc::new(balnceDNS::hooks::Hooks::new::<String>(None)),
    )
    .await
    .unwrap();
    let doh_addr = doh.local_addr();
    let task = tokio::spawn(async move { doh.run().await });

    let url = format!("https://127.0.0.1:{}/dns-query", doh_addr.port());
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let query = build_query(0x2222, RecordType::A);
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .body(query)
        .send()
        .await
        .unwrap();

    let bytes = resp.bytes().await.unwrap();
    assert!(bytes.len() >= 2);
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    assert_eq!(id, 0x2222);

    task.abort();
}

fn build_query(id: u16, record_type: RecordType) -> Vec<u8> {
    let name = Name::from_ascii("example.com.").unwrap();
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, record_type));
    msg.to_vec().unwrap()
}

fn make_self_signed_cert() -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certified = rcgen::generate_simple_self_signed(["dot.test".to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let cert_der = certified.cert.der().to_vec();

    let mut rng = rand::thread_rng();
    let dir = std::env::temp_dir().join(format!("astracat-dns-{}", rng.r#gen::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (cert_path, key_path, cert_der)
}

fn rustls_client_with_root(cert_der: Vec<u8>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let _ = roots.add(rustls::pki_types::CertificateDer::from(cert_der));
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg
}
