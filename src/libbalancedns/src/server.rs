use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Clone, Debug)]
pub struct Frame {
    transport: Transport,
    packet: Vec<u8>,
    client_addr: Option<SocketAddr>,
}

impl Frame {
    pub fn udp(packet: Vec<u8>, client_addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Udp,
            packet,
            client_addr: Some(client_addr),
        }
    }

    pub fn tcp(packet: Vec<u8>, client_addr: Option<SocketAddr>) -> Self {
        Self {
            transport: Transport::Tcp,
            packet,
            client_addr,
        }
    }

    pub fn dot(packet: Vec<u8>, client_addr: Option<SocketAddr>) -> Self {
        Self {
            transport: Transport::Dot,
            packet,
            client_addr,
        }
    }

    pub fn doh(packet: Vec<u8>, client_addr: Option<SocketAddr>) -> Self {
        Self {
            transport: Transport::Doh,
            packet,
            client_addr,
        }
    }

    #[inline]
    pub fn transport(&self) -> Transport {
        self.transport
    }

    #[inline]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    #[inline]
    pub fn client_addr(&self) -> Option<SocketAddr> {
        self.client_addr
    }
}
