use std::{sync::Arc, time::Duration};

use std::sync::Once;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time,
};
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};

use balnceDNS::{
    config::{BalancingAlgorithm, SecurityConfig, UpstreamConfig, UpstreamProto},
    dns,
    proxy::{TcpProxy, UdpProxy},
    upstream::{Balancer, UpstreamSet},
};

use rcgen::generate_simple_self_signed;
use tokio_rustls::TlsAcceptor;

fn init_tracing() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_test_writer()
            .try_init();
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_proxy_roundtrip_preserves_id() {
    init_tracing();
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut seen = false;
        loop {
            let (n, peer) = match upstream_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            if !seen {
                let _ = peer;
                seen = true;
            }
            let mut resp = buf[..n].to_vec();
            if resp.len() >= 4 {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                let new_flags = flags | 0x8000;
                let b = new_flags.to_be_bytes();
                resp[2] = b[0];
                resp[3] = b[1];
            }
            let _ = upstream_sock.send_to(&resp, peer).await;
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "mock".to_string(),
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

    let proxy = UdpProxy::new(
        "127.0.0.1:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x1234, RecordType::A);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, _) = time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(dns::read_id(resp), Some(0x1234));

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_proxy_denies_any_with_refused() {
    init_tracing();
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = match upstream_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let _ = upstream_sock.send_to(&buf[..n], peer).await;
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "mock".to_string(),
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
        deny_any: true,
        deny_dnskey: false,
        request_timeout_ms: 1500,
    };

    let proxy = UdpProxy::new(
        "127.0.0.1:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x2222, RecordType::ANY);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, _) = time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = &buf[..n];
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rcode = flags & 0x000f;
    assert_eq!(dns::read_id(resp), Some(0x2222));
    assert_eq!(rcode, 5);

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_proxy_roundtrip_preserves_id() {
    init_tracing();
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match upstream_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg = vec![0u8; len];
                    if stream.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    if msg.len() >= 4 {
                        let flags = u16::from_be_bytes([msg[2], msg[3]]);
                        let new_flags = flags | 0x8000;
                        let b = new_flags.to_be_bytes();
                        msg[2] = b[0];
                        msg[3] = b[1];
                    }
                    let resp_len = (msg.len() as u16).to_be_bytes();
                    if stream.write_all(&resp_len).await.is_err() {
                        return;
                    }
                    if stream.write_all(&msg).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "mock".to_string(),
            proto: UpstreamProto::Tcp,
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

    let proxy = TcpProxy::new(
        "127.0.0.1:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let query = build_query(0x7777, RecordType::A);
    let len = (query.len() as u16).to_be_bytes();
    client.write_all(&len).await.unwrap();
    client.write_all(&query).await.unwrap();

    let mut resp_len_buf = [0u8; 2];
    time::timeout(Duration::from_secs(3), client.read_exact(&mut resp_len_buf))
        .await
        .unwrap()
        .unwrap();
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    client.read_exact(&mut resp).await.unwrap();

    assert_eq!(dns::read_id(&resp), Some(0x7777));

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_proxy_roundtrip_ipv6_if_available() {
    init_tracing();
    let upstream_sock = match UdpSocket::bind("[::1]:0").await {
        Ok(s) => s,
        Err(_) => return,
    };
    let upstream_addr = upstream_sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = match upstream_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let _ = upstream_sock.send_to(&buf[..n], peer).await;
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "mock-v6".to_string(),
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

    let proxy = UdpProxy::new(
        "[::1]:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    let query = build_query(0xaaaa, RecordType::A);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, _) = time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(dns::read_id(resp), Some(0xaaaa));

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_proxy_roundtrip_via_doh_upstream() {
    init_tracing();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let doh_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };

            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                let mut read = 0usize;
                loop {
                    let n = match stream.read(&mut buf[read..]).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    read += n;
                    if read >= 4 && buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if read >= buf.len() {
                        return;
                    }
                }

                let req = String::from_utf8_lossy(&buf[..read]);
                let mut content_length = 0usize;
                for line in req.lines() {
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if line.is_empty() {
                        break;
                    }
                }

                let header_end = buf[..read]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap();

                let mut body = Vec::new();
                body.extend_from_slice(&buf[header_end..read]);
                while body.len() < content_length {
                    let mut tmp = vec![0u8; content_length - body.len()];
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    body.extend_from_slice(&tmp[..n]);
                }

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });

    let url = format!("http://127.0.0.1:{}/dns-query", doh_addr.port());
    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "doh".to_string(),
            proto: UpstreamProto::Doh,
            addr: None,
            url: Some(url),
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

    let proxy = UdpProxy::new(
        "127.0.0.1:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x3333, RecordType::A);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, _) = time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(dns::read_id(resp), Some(0x3333));

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_proxy_roundtrip_via_dot_upstream_insecure() {
    init_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = generate_simple_self_signed(["dot.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                loop {
                    let mut len_buf = [0u8; 2];
                    if tls.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg = vec![0u8; len];
                    if tls.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    let resp_len = (msg.len() as u16).to_be_bytes();
                    if tls.write_all(&resp_len).await.is_err() {
                        return;
                    }
                    if tls.write_all(&msg).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let upstreams = Arc::new(
        UpstreamSet::new(vec![UpstreamConfig {
            name: "dot".to_string(),
            proto: UpstreamProto::Dot,
            addr: Some(dot_addr),
            url: None,
            server_name: Some("dot.test".to_string()),
            tls_insecure: true,
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

    let proxy = UdpProxy::new(
        "127.0.0.1:0".parse().unwrap(),
        upstreams,
        balancer,
        security,
        None,
    )
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x4444, RecordType::A);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, _) = time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(dns::read_id(resp), Some(0x4444));

    proxy_task.abort();
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
