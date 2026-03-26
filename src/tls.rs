use std::{fs::File, io::BufReader, path::Path, sync::Arc};

pub fn ensure_rustls_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn load_server_config(cert_pem: &Path, key_pem: &Path) -> anyhow::Result<rustls::ServerConfig> {
    ensure_rustls_crypto_provider();

    let certs = load_certs(cert_pem)
        .map_err(|e| anyhow::anyhow!("failed to read cert {}: {}", cert_pem.display(), e))?;
    let key = load_private_key(key_pem)
        .map_err(|e| anyhow::anyhow!("failed to read key {}: {}", key_pem.display(), e))?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c))
        .collect();
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut pkcs8 = Vec::new();
    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        pkcs8.push(key?);
    }

    if let Some(key) = pkcs8.into_iter().next() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key),
        ));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut rsa = Vec::new();
    for key in rustls_pemfile::rsa_private_keys(&mut reader) {
        rsa.push(key?);
    }

    if let Some(key) = rsa.into_iter().next() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(key),
        ));
    }

    Err(anyhow::anyhow!("no supported private keys found"))
}

pub fn server_tls_acceptor(cert_pem: &Path, key_pem: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cfg = load_server_config(cert_pem, key_pem)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}
