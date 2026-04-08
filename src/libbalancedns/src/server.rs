use crate::balancedns_runtime::BalanceDnsRuntime;
use crossbeam_channel::bounded;
use log::{info, error};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

pub enum Frame {
    Udp {
        packet: Vec<u8>,
        addr: SocketAddr,
    },
    Tcp {
        packet: Vec<u8>,
        addr: SocketAddr,
    },
}

pub struct Server {
    runtime: Arc<BalanceDnsRuntime>,
}

impl Server {
    pub fn new(runtime: Arc<BalanceDnsRuntime>) -> Self {
        Self { runtime }
    }

    pub fn spawn_udp_listener(
        &self,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let socket = UdpSocket::bind(&listen_addr)?;
        let sender_socket = socket.try_clone()?;
        let runtime = self.runtime.clone();

        let worker_count = (thread::available_parallelism().map(|p| p.get()).unwrap_or(4)).max(2);
        let (tx, rx) = bounded::<(SocketAddr, Vec<u8>)>(worker_count * 1024);

        for worker_id in 0..worker_count {
            let socket = sender_socket.try_clone()?;
            let rx = rx.clone();
            let runtime = runtime.clone();
            thread::Builder::new()
                .name(format!("balancedns_udp_worker_{}", worker_id))
                .spawn(move || loop {
                    let (addr, packet) = match rx.recv() {
                        Ok(job) => job,
                        Err(_) => break,
                    };
                    runtime.varz.client_queries.inc();
                    runtime.varz.client_queries_udp.inc();
                    match runtime.process_query(&packet) {
                        Ok(response) => {
                            if let Err(e) = socket.send_to(&response, addr) {
                                error!("UDP send error to {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            runtime.varz.client_queries_errors.inc();
                            error!("Query processing error for {}: {}", addr, e);
                        }
                    }
                })?;
        }

        info!("UDP listener is ready on {}", listen_addr);
        thread::Builder::new()
            .name("balancedns_udp".to_string())
            .spawn(move || {
                let mut buf = [0u8; 65535];
                loop {
                    match socket.recv_from(&mut buf) {
                        Ok((len, addr)) => {
                            if let Err(e) = tx.try_send((addr, buf[..len].to_vec())) {
                                error!("UDP listener queue error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("UDP accept error: {}", e);
                        }
                    }
                }
            })
    }
}
