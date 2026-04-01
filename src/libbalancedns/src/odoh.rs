//! ODoH (Oblivious DNS over HTTPS) server implementation
//! Simple stub implementation

pub struct OdohServer {
    config_bytes: Vec<u8>,
}

impl OdohServer {
    pub fn new() -> Self {
        // Empty config for now - oDoH is not fully implemented
        OdohServer {
            config_bytes: vec![],
        }
    }

    pub fn get_config_bytes(&self) -> Vec<u8> {
        self.config_bytes.clone()
    }

    pub fn decrypt_query(&self, _encrypted_query: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        Err("oDoH not implemented".to_string())
    }

    pub fn encrypt_response(
        &self,
        _query_bytes: &[u8],
        _response_bytes: &[u8],
        _srv_secret: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("oDoH not implemented".to_string())
    }
}
