
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use tokio_rustls::client::TlsStream;
use rustls::pki_types::ServerName;
use log::warn;

use rustls::{Error,SignatureScheme,DigitallySignedStruct};
use rustls::client::danger::{ServerCertVerifier,ServerCertVerified,HandshakeSignatureValid};
use rustls::pki_types::{UnixTime,CertificateDer};

use crate::config::{Config,SslMode};

#[derive(Debug)]
struct SslCertValidationDisabler { }
impl ServerCertVerifier for SslCertValidationDisabler {
	fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
		Ok( ServerCertVerified::assertion() )
	}

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
		Ok( HandshakeSignatureValid::assertion() )
	}

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
		Ok( HandshakeSignatureValid::assertion() )
	}
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		let mut rv = Vec::new();

		rv.push(SignatureScheme::RSA_PKCS1_SHA1);
		rv.push(SignatureScheme::ECDSA_SHA1_Legacy);
		rv.push(SignatureScheme::RSA_PKCS1_SHA256);
		rv.push(SignatureScheme::ECDSA_NISTP256_SHA256);
		rv.push(SignatureScheme::RSA_PKCS1_SHA384);
		rv.push(SignatureScheme::ECDSA_NISTP384_SHA384);
		rv.push(SignatureScheme::RSA_PKCS1_SHA512);
		rv.push(SignatureScheme::ECDSA_NISTP521_SHA512);
		rv.push(SignatureScheme::RSA_PSS_SHA256);
		rv.push(SignatureScheme::RSA_PSS_SHA384);
		rv.push(SignatureScheme::RSA_PSS_SHA512);
		rv.push(SignatureScheme::ED25519);
		rv.push(SignatureScheme::ED448);

		rv
	}
}


fn build_ssl_config(cfg: &Config) -> rustls::ClientConfig {
	let config = rustls::ClientConfig::builder();

	match cfg.get_ssl_mode() {
		SslMode::BUILTIN => {
			let mut root_cert_store = rustls::RootCertStore::empty();
			root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
			config
				.with_root_certificates(root_cert_store)
				.with_no_client_auth()
		},
		SslMode::FILE => {
			let mut root_cert_store = rustls::RootCertStore::empty();
			if let Some(ca) = cfg.get_ca_file() {
				let mut pem = BufReader::new(File::open(ca).unwrap());
				for cert in rustls_pemfile::certs(&mut pem) {
					root_cert_store.add(cert.unwrap()).unwrap();
				}
			} else {
				warn!("Wrong configuration: file ssl_mode set but no cafile defined, falling back to builtin mode");
				root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
			}
			config
				.with_root_certificates(root_cert_store)
				.with_no_client_auth()
		},
		SslMode::OS => {
#[cfg(target_os = "android")]
			panic!("\"os\" ssl mode not availble on android");
#[cfg(not(target_os = "android"))]
			config
				.dangerous() // The `Verifier` we're using is actually safe
				.with_custom_certificate_verifier(Arc::new(rustls_platform_verifier::Verifier::new()))
				.with_no_client_auth()
		},
		SslMode::DANGEROUS => {
			config
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(SslCertValidationDisabler { }))
				.with_no_client_auth()
		},
	}
}

pub async fn wrap(stream: TcpStream, cfg: Config) -> Result<TlsStream<TcpStream>,String> {
	let config = build_ssl_config(&cfg);
	let connector = TlsConnector::from(Arc::new(config));

	// let domain = ServerName::try_from(cfg.get_domain().as_str())
	let domain = ServerName::try_from(cfg.get_domain())
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname")).unwrap()
		.to_owned();

	Ok(connector.connect(domain, stream).await.unwrap())
}

