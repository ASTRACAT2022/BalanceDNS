use std::sync::Arc;

use balnceDNS::{
    blocklist_remote::BlocklistRemote,
    config::BlocklistRemoteConfig,
    dns,
};
use hyper::{service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, task};
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};

#[tokio::test(flavor = "multi_thread")]
async fn blocklist_blocks_domain_and_returns_nxdomain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let body = "! comment\n||ads.example.com^\n0.0.0.0 tracker.example.net\nmail.yandex.ru##.promo\n".to_string();
    let body_arc = Arc::new(body);

    task::spawn({
        let body_arc = body_arc.clone();
        async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let body_arc = body_arc.clone();
                task::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
                        let body_arc = body_arc.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from(body_arc.as_bytes().to_vec()),
                            )))
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    });

    let url = format!("http://127.0.0.1:{}/list", addr.port());
    let bl = BlocklistRemote::new(BlocklistRemoteConfig {
        url,
        refresh_seconds: 300,
    })
    .unwrap();
    bl.refresh_once().await.unwrap();

    let query = build_query(0x1a2b, "ads.example.com.", RecordType::A);
    assert!(bl.is_blocked(&query));

    let resp = dns::build_nxdomain_response(&query).unwrap();
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rcode = flags & 0x000f;
    assert_eq!(rcode, 3);
}

fn build_query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
    let name = Name::from_ascii(name).unwrap();
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, record_type));
    msg.to_vec().unwrap()
}

