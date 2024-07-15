
//use std::fs::File;
use std::io;
//use std::io::BufReader;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use tokio_rustls::client::TlsStream;
use crate::ssl::rustls::pki_types::ServerName;

use crate::config::Config;

pub async fn wrap(stream: TcpStream, cfg: &Config) -> Result<TlsStream<TcpStream>,String> {
	let /*mut*/ root_cert_store = rustls::RootCertStore::empty();
/*	if let Some(ca) = cfg.get_ca_file() {
		let mut pem = BufReader::new(File::open(ca).unwrap());
		for cert in rustls_pemfile::certs(&mut pem) {
			root_cert_store.add(cert.unwrap()).unwrap();
		}
	} else {
		root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	} */

	let config = rustls::ClientConfig::builder()
		.with_root_certificates(root_cert_store)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));

	let domain = ServerName::try_from(cfg.get_domain().as_str())
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname")).unwrap()
		.to_owned();

	Ok(connector.connect(domain, stream).await.unwrap())
}

