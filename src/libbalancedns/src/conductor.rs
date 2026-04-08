use crate::config::{Config, UpstreamConfig, UpstreamProtocol};
use crate::dns;
use crate::varz::Varz;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub struct Conductor {
    config: Config,
    varz: Arc<Varz>,
    inflight: Mutex<HashMap<dns::NormalizedQuestionKey, watch::Receiver<Option<Vec<u8>>>>>,
}

impl Conductor {
    pub fn new(config: Config, varz: Arc<Varz>) -> Self {
        Self {
            config,
            varz,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub async fn resolve(
        &self,
        normalized_question: &dns::NormalizedQuestion,
        fqdn: &str,
        upstream_indices: Vec<usize>,
        runtime: Arc<crate::balancedns_runtime::BalanceDnsRuntime>,
    ) -> io::Result<Vec<u8>> {
        let key = normalized_question.key();

        // 1. Query Coalescing (Deduplication)
        let rx = {
            let mut inflight = self.inflight.lock();
            if let Some(rx) = inflight.get(&key) {
                rx.clone()
            } else {
                let (tx, rx) = watch::channel(None);
                inflight.insert(key.clone(), rx.clone());
                drop(inflight);

                // This task is the "leader" for this query
                let response = self.resolve_inner(normalized_question, fqdn, upstream_indices, runtime.clone()).await;

                let mut inflight = self.inflight.lock();
                inflight.remove(&key);

                let result = match response {
                    Ok(ref pkt) => Some(pkt.clone()),
                    Err(_) => None,
                };
                let _ = tx.send(result);
                return response;
            }
        };

        // 2. Wait for the leader
        let mut rx = rx;
        loop {
            if let Some(ref response) = *rx.borrow() {
                let mut response = response.clone();
                dns::set_tid(&mut response, normalized_question.tid);
                return Ok(response);
            }
            if rx.changed().await.is_err() {
                // Leader failed or disappeared
                return Err(io::Error::new(io::ErrorKind::Other, "Coalesced query failed"));
            }
        }
    }

    async fn resolve_inner(
        &self,
        normalized_question: &dns::NormalizedQuestion,
        _fqdn: &str,
        upstream_indices: Vec<usize>,
        runtime: Arc<crate::balancedns_runtime::BalanceDnsRuntime>,
    ) -> io::Result<Vec<u8>> {
        let (query_packet, upstream_question) = dns::build_query_packet(normalized_question, false)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let upstream_question_fqdn = dns::qname_to_fqdn(&upstream_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let total_timeout = Duration::from_millis(self.config.request_timeout_ms);
        let started_at = Instant::now();
        let mut _last_err = None;

        for upstream_idx in upstream_indices {
            let upstream = &self.config.upstreams[upstream_idx];
            let elapsed = started_at.elapsed();
            if elapsed >= total_timeout {
                _last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "Overall upstream resolution timed out"));
                break;
            }
            let remaining_timeout = total_timeout.saturating_sub(elapsed);

            self.varz.upstream_sent.inc();
            match self.query_upstream(
                upstream,
                &query_packet,
                &upstream_question,
                &upstream_question_fqdn,
                normalized_question.tid,
                remaining_timeout,
                runtime.clone(),
            ).await {
                Ok(response) => {
                    self.varz.upstream_received.inc();
                    return Ok(response);
                }
                Err(err) => {
                    self.varz.upstream_errors.inc();
                    _last_err = Some(err);
                }
            }
        }

        let fallback = dns::build_servfail_packet(normalized_question)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(fallback)
    }

    async fn query_upstream(
        &self,
        upstream: &UpstreamConfig,
        query_packet: &[u8],
        upstream_question: &dns::NormalizedQuestionMinimal,
        upstream_question_fqdn: &str,
        client_tid: u16,
        timeout: Duration,
        runtime: Arc<crate::balancedns_runtime::BalanceDnsRuntime>,
    ) -> io::Result<Vec<u8>> {
        let started_at = Instant::now();

        let mut response = match upstream.proto {
            UpstreamProtocol::Udp => {
                let upstream = upstream.clone();
                let query_packet = query_packet.to_vec();
                tokio::task::spawn_blocking(move || {
                    runtime.query_udp_upstream(&upstream, &query_packet, timeout)
                }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))??
            }
            UpstreamProtocol::Doh => {
                let upstream = upstream.clone();
                let query_packet = query_packet.to_vec();
                tokio::task::spawn_blocking(move || {
                    runtime.query_doh_upstream(&upstream, &query_packet, timeout)
                }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))??
            }
        };

        let normalized_response = dns::normalize(&response, false)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let normalized_response_fqdn = dns::qname_to_fqdn(&normalized_response.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        if normalized_response.tid != upstream_question.tid
            || normalized_response.qtype != upstream_question.qtype
            || normalized_response.qclass != upstream_question.qclass
            || normalized_response_fqdn != upstream_question_fqdn
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Upstream [{}] returned a mismatched response", upstream.name),
            ));
        }

        let sample_rtt = started_at.elapsed().as_secs_f64();
        let current_rtt = self.varz.upstream_avg_rtt.get();
        let updated_rtt = if current_rtt == 0.0 {
            sample_rtt
        } else {
            (current_rtt * 0.8) + (sample_rtt * 0.2)
        };
        self.varz.upstream_avg_rtt.set(updated_rtt);

        dns::set_tid(&mut response, client_tid);
        Ok(response)
    }
}
