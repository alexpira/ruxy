
use std::fs::File;
use std::path::PathBuf;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector, TlsAcceptor};
use rustls::pki_types::{ServerName,UnixTime,CertificateDer,PrivateKeyDer};
use log::{warn,error};

use rustls::{Error,SignatureScheme,DigitallySignedStruct};
use rustls::client::danger::{ServerCertVerifier,ServerCertVerified,HandshakeSignatureValid};

use crate::config::{Config,RemoteConfig,SslMode,HttpVersionMode,SslData};
use crate::net::Stream;

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

fn load_certs(filename: PathBuf) -> Result<Vec<CertificateDer<'static>>, String> {
	let certfile = match File::open(filename.clone()) {
		Ok(v) => v,
		Err(e) => return Err(format!("failed to open {:?}: {}", filename, e)),
	};

	let mut cert_store = Vec::new();
	let mut reader = BufReader::new(certfile);
	for cert in rustls_pemfile::certs(&mut reader) {
		match cert {
			Ok(c) => cert_store.push(c.into_owned()),
			Err(e) => warn!("Invalid certificate in {:?}: {:?}", filename, e),
		}
	}

	Ok(cert_store)
}

fn load_private_key(filename: PathBuf) -> Result<PrivateKeyDer<'static>, String> {
	let keyfile = match File::open(filename.clone()) {
		Ok(v) => v,
		Err(e) => return Err(format!("failed to open {:?}: {:?}", filename, e)),
	};
	let mut reader = BufReader::new(keyfile);

	match rustls_pemfile::private_key(&mut reader) {
		Ok(k) => match k {
			Some(v) => Ok(v),
			None => Err(format!("No key found inside {:?}", filename)),
		},
		Err(e) => Err(format!("Invalid key in {:?}: {:?}", filename, e)),
	}
}

fn build_client_ssl_config(cfg: SslData) -> rustls::ClientConfig {
	let config = rustls::ClientConfig::builder();

	let mut config = match cfg.0 {
		SslMode::Builtin => {
			let mut root_cert_store = rustls::RootCertStore::empty();
			root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
			config
				.with_root_certificates(root_cert_store)
				.with_no_client_auth()
		},
		SslMode::File => {
			let mut root_cert_store = rustls::RootCertStore::empty();
			if let Some(ca) = cfg.2 {
				match load_certs(ca.clone()) {
					Err(e) => error!("{}:{} {}", file!(), line!(), e),
					Ok(certs) => {
						for cert in certs.into_iter() {
							if let Err(e) = root_cert_store.add(cert) {
								warn!("Failed to add certificate from {:?}: {:?}", ca, e);
							}
						}
					},
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
		SslMode::Dangerous => {
			config
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(SslCertValidationDisabler { }))
				.with_no_client_auth()
		},
	};

	config.alpn_protocols = match cfg.1 {
		HttpVersionMode::V1 => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
		HttpVersionMode::V2Direct => vec![b"h2".to_vec()],
		HttpVersionMode::V2Handshake => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
	};
	config
}

pub async fn wrap_client<T>(stream: T, cfg: SslData, remote: &RemoteConfig) -> Result<tokio_rustls::client::TlsStream<T>,String> where T: Stream {
	let config = build_client_ssl_config(cfg);
	let connector = TlsConnector::from(Arc::new(config));

	let domain_name = remote.domain();
	let domain = match ServerName::try_from(domain_name.clone())
		.map_err(|_| format!("{}:{} invalid dnsname: {}", file!(), line!(), domain_name)) {
		Ok(v) => v.to_owned(),
		Err(e) => return Err(e)
	};

	match connector.connect(domain, stream).await {
		Ok(v) => Ok(v),
		Err(e) => Err(format!("{}:{} Connection failed: {:?}", file!(), line!(), e))
	}
}

pub fn get_ssl_acceptor(cfg: Config) -> Result<TlsAcceptor,String> {
	let certs = match cfg.get_server_ssl_cafile() {
		Some(path) => load_certs(path)?,
		None => return Err(format!("{}:{} Invalid server SSL configuration", file!(), line!())),
	};
	let key = match cfg.get_server_ssl_keyfile() {
		Some(path) => load_private_key(path)?,
		None => return Err(format!("{}:{} Invalid server SSL configuration", file!(), line!())),
	};

	let mut config = match rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key) {
		Ok(v) => v,
		Err(e) => return Err(format!("{}:{} Invalid configuration: {:?}", file!(), line!(), e))
	};

	config.alpn_protocols = match cfg.server_version() {
		HttpVersionMode::V1 => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
		HttpVersionMode::V2Direct => vec![b"h2".to_vec()],
		HttpVersionMode::V2Handshake => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
	};

	Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn wrap_server(stream: TcpStream, acceptor: TlsAcceptor) -> Result<tokio_rustls::server::TlsStream<TcpStream>,String> {
	match acceptor.accept(stream).await {
		Ok(v) => Ok(v),
		Err(e) => Err(format!("{}:{} Accept failed: {:?}", file!(), line!(), e))
	}
}


