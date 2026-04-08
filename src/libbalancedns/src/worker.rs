use crate::balancedns_runtime::BalanceDnsRuntime;
use crate::config::ResolverMode;
use crate::dns;
use crate::plugins::PacketAction;
use crate::server::{Frame, Transport};
use std::borrow::Cow;
use std::io;
use std::sync::Arc;

pub struct Worker;

impl Worker {
    pub fn new() -> Self {
        Self
    }

    pub fn process_frame(
        &self,
        runtime: &Arc<BalanceDnsRuntime>,
        frame: Frame,
    ) -> io::Result<Vec<u8>> {
        match frame.transport() {
            Transport::Udp | Transport::Tcp | Transport::Dot | Transport::Doh => {}
        }
        let _client_addr = frame.client_addr();
        self.process_packet(runtime, frame.packet())
    }

    pub fn process_packet(
        &self,
        runtime: &Arc<BalanceDnsRuntime>,
        packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        let _inflight_query = BalanceDnsRuntime::inflight_query_guard(&runtime.varz);
        let packet = if runtime.plugins.is_empty() {
            Cow::Borrowed(packet)
        } else {
            match runtime.plugins.apply_pre_query(packet) {
                None => Cow::Borrowed(packet),
                Some(PacketAction::Continue(updated)) => Cow::Owned(updated),
                Some(PacketAction::Respond(response)) => {
                    return Ok(runtime.apply_post_response_plugins(response));
                }
            }
        };
        let normalized_question = dns::normalize(packet.as_ref(), true)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = dns::qname_to_fqdn(&normalized_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = fqdn.to_ascii_lowercase();

        if runtime.config.deny_any && normalized_question.qtype == dns::DNS_TYPE_ANY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if runtime.config.deny_dnskey && normalized_question.qtype == dns::DNS_TYPE_DNSKEY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if let Some((ip_addr, ttl)) = runtime.lookup_host(&fqdn) {
            let response = dns::build_address_packet(&normalized_question, ip_addr, ttl)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            return Ok(runtime.apply_post_response_plugins(response));
        }
        if runtime.is_blocked(&fqdn) {
            return Ok(dns::build_nxdomain_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }

        if runtime.config.cache_enabled {
            let cache_entry = runtime.cache.get2(&normalized_question);
            if let Some(cache_entry) = cache_entry {
                if cache_entry.is_expired() {
                    runtime.varz.client_queries_expired.inc();
                    if runtime.config.stale_refresh_enabled
                        && cache_entry.is_servable_stale(runtime.config.stale_ttl_seconds)
                    {
                        runtime.schedule_stale_refresh(
                            normalized_question.clone(),
                            normalized_question.key(),
                            fqdn.clone(),
                        );
                        runtime.varz.client_queries_cached.inc();
                        let mut cached_packet = cache_entry.packet.clone();
                        let _ = dns::set_ttl(&mut cached_packet, 1);
                        dns::set_tid(&mut cached_packet, normalized_question.tid);
                        return Ok(runtime.apply_post_response_plugins(cached_packet));
                    }
                } else {
                    runtime.varz.client_queries_cached.inc();
                    let mut cached_packet = cache_entry.packet.clone();
                    dns::set_tid(&mut cached_packet, normalized_question.tid);
                    return Ok(runtime.apply_post_response_plugins(cached_packet));
                }
            }
        }

        let response = match runtime.resolver_mode() {
            ResolverMode::Forward => runtime.resolve_via_upstreams(&normalized_question, &fqdn),
            ResolverMode::Recursive => runtime.resolve_via_recursor(&normalized_question),
        }?;
        let response = runtime.apply_post_response_plugins(response);
        if runtime.config.cache_enabled {
            let ttl = dns::min_ttl(
                &response,
                runtime.config.min_ttl,
                runtime.config.max_ttl,
                runtime.config.cache_ttl_seconds,
            )
            .unwrap_or(runtime.config.cache_ttl_seconds);
            let _ = runtime
                .cache
                .insert(normalized_question.key(), response.clone(), ttl);
        }
        Ok(response)
    }
}
